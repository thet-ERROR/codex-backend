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
