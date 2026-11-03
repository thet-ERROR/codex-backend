// Customer reviews through a mission code (the code that comes in the box), and the newsletter.
// Run: npm test

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startBackend } from './harness.js';

let api, admin, pc;
before(async () => {
    api = await startBackend();
    admin = await api.adminToken();
    pc = (await api.post('/drops', { name: 'REVIEWED RIG', priceCents: 150000 }, { token: admin })).body;
});
after(async () => { await api.stop(); });

const newCode = async (pcId = pc._id, pcName = pc.name) => (await api.post('/generate-code', { pcId, pcName }, { token: admin })).body;
const review = (code, over = {}, opts) => api.post('/submit-review', { code, user: 'Giorgos', text: 'Runs cold and quiet.', rating: 5, ...over }, opts);
const reviewsOnPc = async () => (await api.get('/drops')).body.find(p => p._id === pc._id).reviews;

describe('mission codes', () => {
    let code;
    it('the admin generates a code for a PC', async () => {
        const t = await newCode();
        assert.match(t.code, /^CDX-[0-9A-F]{10}$/);
        assert.equal(t.pcName, 'REVIEWED RIG');
        code = t.code;
        assert.equal((await api.post('/generate-code', {})).status, 401);
    });

    it('checking a code is read-only: it does not start the 48-hour clock', async () => {
        const r = await api.get(`/check-code/${code}`);
        assert.deepEqual(r.body, { valid: true, activated: false, pcName: 'REVIEWED RIG' });
        assert.equal((await api.get(`/check-code/${code}`)).body.activated, false);
    });

    it('an unknown code is reported as invalid', async () => {
        assert.deepEqual((await api.get('/check-code/CDX-NOSUCHCODE')).body, { valid: false, msg: '❌ INVALID CODE' });
        assert.equal((await api.post('/check-code/CDX-NOSUCHCODE/activate')).status, 404);
    });

    it('activating starts the 48-hour window, and repeating it does not restart it', async () => {
        const first = await api.post(`/check-code/${code}/activate`);
        assert.equal(first.body.valid, true);
        assert.equal(first.body.expired, false);
        assert.ok(first.body.timeLeft > 47.9 * 3600e3 && first.body.timeLeft <= 48 * 3600e3);
        await new Promise(r => setTimeout(r, 30));
        const second = await api.post(`/check-code/${code}/activate`);
        assert.ok(second.body.timeLeft <= first.body.timeLeft, 'a second activation must not extend the window');
        const check = await api.get(`/check-code/${code}`);
        assert.equal(check.body.activated, true);
        assert.equal(check.body.expired, false);
    });

    it('the admin sees the codes', async () => {
        const list = await api.get('/tickets', { token: admin });
        assert.ok(list.body.some(t => t.code === code));
    });
});

describe('submitting a review', () => {
    it('refuses what is missing or malformed', async () => {
        const code = (await newCode()).code;
        assert.equal((await review(code, { user: '' })).status, 400);
        assert.equal((await review(code, { text: '' })).status, 400);
        assert.equal((await review('', {})).status, 400);
        for (const rating of [0, 6, 2.5, 'abc']) assert.equal((await review(code, { rating })).status, 400, `rating ${rating}`);
        assert.equal((await review(code, { user: 'Evil <b>' })).status, 400);
        assert.equal((await review('CDX-NOSUCHCODE')).status, 400);
    });

    it('a guest posts a review with a code; it lands on the PC; the code works once', async () => {
        const code = (await newCode()).code;
        const r = await review(code, { text: 'Great <70°C temps' });
        assert.equal(r.status, 200);
        const posted = (await reviewsOnPc()).find(x => x.user === 'Giorgos');
        assert.equal(posted.text, 'Great <70°C temps', 'angle brackets are fine in the text');
        assert.equal(posted.rating, 5);
        assert.equal(posted.rank, undefined, 'a guest review carries no rank badge');

        const again = await review(code);
        assert.equal(again.status, 409);
        assert.equal((await api.get(`/check-code/${code}`)).body.msg, '⚠️ ALREADY REDEEMED');
    });

    it('the same code used twice at once posts one review', async () => {
        const code = (await newCode()).code;
        const before = (await reviewsOnPc()).length;
        const [a, b] = await Promise.all([review(code, { user: 'Racer' }), review(code, { user: 'Racer' })]);
        assert.deepEqual([a.status, b.status].sort(), [200, 409]);
        assert.equal((await reviewsOnPc()).length, before + 1);
    });

    it('text and name are trimmed to their limits', async () => {
        const code = (await newCode()).code;
        await review(code, { user: 'N'.repeat(80), text: 'T'.repeat(1500) });
        const posted = (await reviewsOnPc()).find(x => x.user.startsWith('NNN'));
        assert.equal(posted.user.length, 40);
        assert.equal(posted.text.length, 1000);
    });

    it('a signed-in reviewer gets their rank beside the name and credit for a field report', async () => {
        const member = await api.signUp('Reviewer');
        // The rank on a review is the one stored on the account when it is written. Ranks are worked
        // out when the profile is loaded, so an account that has never loaded it is still a recruit.
        const first = await review((await newCode()).code, { user: 'Reviewer', text: 'First' }, { token: member.token });
        assert.equal(first.status, 200);
        assert.equal((await reviewsOnPc()).find(x => x.text === 'First').rank, 'recruit');

        const me = await api.get('/me', { token: member.token });
        assert.ok(me.body.achievements.includes('field_report'), 'the review is credited to the account');
        assert.equal(me.body.rank, 'fieldAgent');

        await review((await newCode()).code, { user: 'Reviewer', text: 'Second' }, { token: member.token });
        assert.equal((await reviewsOnPc()).find(x => x.text === 'Second').rank, 'fieldAgent');
    });

    it('a code past its 48 hours cannot be used', async () => {
        const code = (await newCode()).code;
        await api.post(`/check-code/${code}/activate`);
        await api.col('reviewtickets').updateOne({ code }, { $set: { firstScan: new Date(Date.now() - 49 * 3600e3) } });
        const check = await api.get(`/check-code/${code}`);
        assert.equal(check.body.expired, true);
        const r = await review(code);
        assert.equal(r.status, 403);
        assert.match(r.body.error, /expired/);
    });

    it('a code for a PC that no longer exists is refused, and stays usable', async () => {
        const gone = (await api.post('/drops', { name: 'SHORT LIVED', priceCents: 1000 }, { token: admin })).body;
        const code = (await newCode(gone._id, gone.name)).code;
        await api.del(`/drops/${gone._id}`, { token: admin });
        assert.equal((await review(code)).status, 404);
        assert.equal((await api.get(`/check-code/${code}`)).body.valid, true);
    });
});

describe('newsletter', () => {
    it('anyone can subscribe; a repeat does not create a second entry', async () => {
        assert.deepEqual((await api.post('/newsletter', { email: 'Fan@Gmail.com' })).body, { success: true });
        assert.deepEqual((await api.post('/newsletter', { email: 'fan@gmail.com' })).body, { success: true });
        assert.equal(await api.col('newsletters').countDocuments({ email: 'fan@gmail.com' }), 1);
    });

    it('refuses anything that is not a plain address, including HTML', async () => {
        for (const email of ['nope', '', '<img src=x onerror=alert(1)>@gmail.com', 'a b@gmail.com', { $ne: null }]) {
            assert.equal((await api.post('/newsletter', { email })).status, 400, JSON.stringify(email));
        }
    });

    it('only the admin can read the list', async () => {
        assert.equal((await api.get('/newsletter')).status, 401);
        const list = await api.get('/newsletter', { token: admin });
        assert.equal(list.status, 200);
        assert.ok(list.body.some(n => n.email === 'fan@gmail.com'));
    });
});
