// What any visitor can reach without signing in, plus the server's outer shell (headers, CORS,
// unknown routes). Run from this folder: npm test

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startBackend, FRONTEND_ORIGIN } from './harness.js';

let api;
before(async () => { api = await startBackend(); });
after(async () => { await api.stop(); });

describe('public reads', () => {
    it('/status answers with the shop settings', async () => {
        const r = await api.get('/status');
        assert.equal(r.status, 200);
        assert.equal(r.body.maintenance, false);
        assert.equal(typeof r.body.proConfigPrice, 'number');
        assert.equal(typeof r.body.voteInfoText, 'string');
        assert.equal(typeof r.body.voteInfoTextEl, 'string');
    });

    it('/drops is an empty list on a fresh database', async () => {
        const r = await api.get('/drops');
        assert.equal(r.status, 200);
        assert.deepEqual(r.body, []);
    });

    it('/vote-event is an empty object when no vote is running', async () => {
        const r = await api.get('/vote-event');
        assert.equal(r.status, 200);
        assert.deepEqual(r.body, {});
    });
});

describe('the outer shell', () => {
    it('an unknown /api route is a JSON 404, not a stack trace', async () => {
        const r = await api.get('/definitely-not-a-route');
        assert.equal(r.status, 404);
        assert.deepEqual(r.body, { error: 'Not Found' });
    });

    it('API answers are never cached', async () => {
        const r = await api.get('/status');
        assert.match(r.headers.get('cache-control'), /no-store/);
    });

    it('security headers are set', async () => {
        const r = await api.get('/status');
        assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
        assert.equal(r.headers.get('cross-origin-resource-policy'), 'cross-origin');
    });

    it('CORS lets the site in and nobody else', async () => {
        const allowed = await api.get('/status', { headers: { Origin: FRONTEND_ORIGIN } });
        assert.equal(allowed.headers.get('access-control-allow-origin'), FRONTEND_ORIGIN);
        const stranger = await api.get('/status', { headers: { Origin: 'https://evil.example' } });
        assert.equal(stranger.headers.get('access-control-allow-origin'), null);
    });

    // KNOWN QUIRK, pinned as it is today so a refactor can't change it by accident: a body that is not
    // valid JSON is answered with the generic 500 (it reaches the global error handler), where a 400
    // would be the right answer. Never a stack trace either way. To fix separately, then update this.
    it('a body that is not JSON gets the generic error, never a stack trace', async () => {
        const r = await fetch(`${api.url}/newsletter`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{not json' });
        assert.equal(r.status, 500);
        assert.deepEqual(await r.json(), { error: 'Server Error' });
    });

    it('admin-only routes refuse a request with no token', async () => {
        for (const [method, route] of [['GET', '/users'], ['POST', '/drops'], ['GET', '/tickets'], ['GET', '/newsletter'], ['POST', '/generate-code'], ['GET', '/site-config']]) {
            const r = await api.call(method, route, { body: method === 'POST' ? {} : undefined });
            assert.equal(r.status, 401, `${method} ${route} should need a token`);
        }
    });
});

describe('CORS for Vercel previews', () => {
    // A pattern listed first on purpose: the email links must still use the real address
    let preview;
    before(async () => { preview = await startBackend({ env: { FRONTEND_URL: 'https://codex-*-phoenix-codex.vercel.app,https://codex-iota-nine.vercel.app' } }); });
    after(async () => { await preview.stop(); });
    const allows = async (origin) => (await preview.get('/status', { headers: { Origin: origin } })).headers.get('access-control-allow-origin') === origin;

    it('lets in every preview deployment of the account, and the production site', async () => {
        assert.equal(await allows('https://codex-lx35hnix4-phoenix-codex.vercel.app'), true);
        assert.equal(await allows('https://codex-git-main-test-phoenix-codex.vercel.app'), true);
        assert.equal(await allows('https://codex-iota-nine.vercel.app'), true);
    });

    it('does not let in look-alikes', async () => {
        for (const origin of [
            'https://codex-x.evil.com-phoenix-codex.vercel.app',  // a dot inside the wildcard
            'https://codex-abc-phoenix-codex.vercel.app.evil.com', // the real suffix, then more
            'https://evilcodex-abc-phoenix-codex.vercel.app',      // something before the prefix
            'http://codex-abc-phoenix-codex.vercel.app',           // not https
            'https://codex--phoenix-codex.vercel.app',             // the wildcard empty
            'https://codex-abc-phoenix-codex.vercel.app:8443'      // another port
        ]) {
            assert.equal(await allows(origin), false, origin);
        }
    });

    it('email links use the real site address, never the pattern', async () => {
        const u = await preview.signUp('Previewer', { verify: false });
        for (let i = 0; i < 40 && !preview.lastMailTo(u.email); i++) await new Promise(r => setTimeout(r, 50));
        assert.match(preview.lastMailTo(u.email).text, /https:\/\/codex-iota-nine\.vercel\.app\/\?verify=/);
    });
});

describe('CORS patterns that are refused', () => {
    it('a wildcard anywhere but the first part of an https host is ignored', async () => {
        const api2 = await startBackend({ env: { FRONTEND_URL: 'https://codex.*.app,https://*,http://codex-*-x.vercel.app' } });
        try {
            for (const origin of ['https://codex.evil.app', 'https://anything', 'http://codex-a-x.vercel.app']) {
                const r = await api2.get('/status', { headers: { Origin: origin } });
                assert.equal(r.headers.get('access-control-allow-origin'), null, origin);
            }
        } finally { await api2.stop(); }
    });
});
