// Accounts: sign-up checks, email verification, sign-in, sessions, password reset, wishlist,
// achievements and ranks, the daily wheel and coupons. Run from this folder: npm test
//
// The server limits sign-in attempts per address (10 per 15 minutes) and sign-up related calls
// (50 per hour), so the few tests that burn through those use a server of their own.

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startBackend } from './harness.js';

let api, admin, pcId;
before(async () => {
    api = await startBackend();
    admin = await api.adminToken();
    pcId = (await api.post('/drops', { name: 'WISH TARGET', priceCents: 99900 }, { token: admin })).body._id;
});
after(async () => { await api.stop(); });

const register = (over = {}) => api.post('/register', { username: 'Someone', email: 'someone@gmail.com', password: 'long-enough-1', subscribed: false, ...over });

describe('sign-up checks', () => {
    const refused = [
        ['a username that is too short', { username: 'ab' }, /3-24 characters/],
        ['a username with a space', { username: 'two words' }, /3-24 characters/],
        ['an email that is not an address', { email: 'nope' }, /valid email/],
        ['an email carrying HTML', { email: '<svg/onload=alert(1)>@gmail.com' }, /valid email/],
        ['a throw-away email domain', { email: 'x@mailinator.com' }, /disposable/],
        ['a password under 8 characters', { password: 'short' }, /at least 8/],
    ];
    for (const [name, over, message] of refused) {
        it(`refuses ${name}`, async () => {
            const r = await register(over);
            assert.equal(r.status, 400);
            assert.match(r.body.error, message);
        });
    }

    it('a query object in place of a string is treated as empty, not as a query', async () => {
        const r = await register({ username: { $ne: null } });
        assert.equal(r.status, 400);
    });
});

describe('sign-up and email verification', () => {
    let alice, verifyMail;

    it('creates the account, returns a session and says it is not verified yet', async () => {
        const r = await register({ username: 'Alice', email: 'alice@gmail.com', subscribed: true });
        assert.equal(r.status, 200);
        assert.equal(r.body.success, true);
        assert.equal(r.body.emailVerified, false);
        assert.ok(r.body.token);
        alice = { token: r.body.token };
        // The newsletter box that was ticked
        assert.ok(await api.col('newsletters').findOne({ email: 'alice@gmail.com' }));
    });

    it('stores a hashed password and a hashed verification token — never the raw ones', async () => {
        const doc = await api.col('users').findOne({ username: 'Alice' });
        assert.notEqual(doc.password, 'long-enough-1');
        assert.match(doc.password, /^\$2[aby]\$/);
        assert.match(doc.emailVerifyTokenHash, /^[a-f0-9]{64}$/);
    });

    it('emails a confirm link and a "wasn\'t you" link', async () => {
        for (let i = 0; i < 40 && !api.lastMailTo('alice@gmail.com'); i++) await new Promise(r => setTimeout(r, 50));
        verifyMail = api.lastMailTo('alice@gmail.com');
        assert.ok(verifyMail, 'no verification email was sent');
        assert.match(verifyMail.subject, /CONFIRM YOUR AGENT IDENTITY/);
        assert.match(verifyMail.text, /http:\/\/localhost:3000\/\?verify=[a-f0-9]{64}/);
        assert.match(verifyMail.text, /\?report=[a-f0-9]{64}/);
    });

    it('refuses a duplicate email and a duplicate username', async () => {
        assert.equal((await register({ username: 'Other', email: 'alice@gmail.com' })).body.error, 'Email exists');
        assert.equal((await register({ username: 'Alice', email: 'other@gmail.com' })).body.error, 'Username already taken');
    });

    it('an unverified account is kept out of the member routes', async () => {
        for (const [method, route] of [['GET', '/me'], ['GET', '/wheel'], ['POST', '/wishlist/' + pcId], ['POST', '/cast-vote']]) {
            const r = await api.call(method, route, { token: alice.token });
            assert.equal(r.status, 403, `${method} ${route}`);
            assert.equal(r.body.code, 'EMAIL_NOT_VERIFIED');
        }
    });

    it('resending is allowed once, then held back by a cooldown', async () => {
        // Registering just sent one, so a second request inside the minute is refused
        const r = await api.post('/resend-verification', undefined, { token: alice.token });
        assert.equal(r.status, 429);
        assert.ok(r.body.retryAfterMs > 0);
    });

    it('a wrong token does not verify; the right one does, once', async () => {
        assert.equal((await api.post('/verify-email', { token: 'f'.repeat(64) })).status, 400);
        assert.equal((await api.post('/verify-email', {})).status, 400);
        const token = api.tokenFromMail(verifyMail, /\?verify=([a-f0-9]+)/);
        assert.equal((await api.post('/verify-email', { token })).status, 200);
        assert.equal((await api.post('/verify-email', { token })).status, 400, 'a verification link must work only once');
    });

    it('once verified, the same session reaches the member routes', async () => {
        assert.equal((await api.get('/me', { token: alice.token })).status, 200);
    });
});

describe('sessions and sign-in', () => {
    it('signs in with the right password and refuses the wrong one, with the same message for an unknown name', async () => {
        const bob = await api.signUp('Bobby');
        const ok = await api.post('/user-login', { username: 'Bobby', password: bob.password });
        assert.equal(ok.status, 200);
        assert.equal(ok.body.emailVerified, true);
        assert.ok(ok.body.token);
        const wrong = await api.post('/user-login', { username: 'Bobby', password: 'not-the-password' });
        const unknown = await api.post('/user-login', { username: 'Nobody', password: 'whatever-1' });
        assert.equal(wrong.status, 400);
        assert.equal(unknown.status, 400);
        assert.equal(wrong.body.error, unknown.body.error, 'the two failures must look the same');
    });

    it('a query object as the username does not match anyone', async () => {
        const r = await api.post('/user-login', { username: { $ne: null }, password: { $ne: null } });
        assert.equal(r.status, 400);
    });

    it('a reported account is locked even for the right password', async () => {
        const eve = await api.signUp('Evelyn');
        await api.col('users').updateOne({ username: 'Evelyn' }, { $set: { securityLockedUntil: new Date(Date.now() + 3600e3) } });
        const r = await api.post('/user-login', { username: 'Evelyn', password: eve.password });
        assert.equal(r.status, 403);
        assert.equal(r.body.code, 'ACCOUNT_LOCKED');
    });

    it('a session without a token, or with a forged one, is refused', async () => {
        assert.equal((await api.get('/me')).status, 401);
        assert.equal((await api.get('/me', { token: 'forged' })).status, 401);
    });
});

describe('password reset', () => {
    it('emails a reset token, swaps the password, and kills sessions issued before', async () => {
        const dan = await api.signUp('Daniel');
        // The answer is the same whether or not the address has an account
        assert.deepEqual((await api.post('/forgot-password', { email: 'ghost@gmail.com' })).body, { success: true });
        assert.deepEqual((await api.post('/forgot-password', { email: dan.email })).body, { success: true });
        const mail = api.lastMailTo(dan.email);
        assert.match(mail.subject, /PASSWORD RECOVERY/);
        const resetToken = api.tokenFromMail(mail, /RESET TOKEN:\n([a-f0-9]+)/);
        assert.ok(resetToken);

        assert.equal((await api.post('/reset-password', { token: 'wrong', newPass: 'brand-new-pass-2' })).status, 400);
        assert.equal((await api.post('/reset-password', { token: resetToken, newPass: 'short' })).status, 400);
        assert.equal((await api.post('/reset-password', { token: resetToken, newPass: 'brand-new-pass-2' })).status, 200);
        assert.equal((await api.post('/reset-password', { token: resetToken, newPass: 'another-pass-3' })).status, 400, 'a reset token must work only once');

        assert.equal((await api.get('/me', { token: dan.token })).status, 401, 'the old session survived the reset');
        const fresh = await api.post('/user-login', { username: 'Daniel', password: 'brand-new-pass-2' });
        assert.equal(fresh.status, 200);
        assert.equal((await api.post('/user-login', { username: 'Daniel', password: dan.password })).status, 400);
    });
});

describe('profile, ranks and achievements', () => {
    let me;
    before(async () => { me = await api.signUp('Profiler'); });

    it('a newly verified account starts on the first rank rewards', async () => {
        const r = await api.get('/me', { token: me.token });
        assert.equal(r.body.username, 'Profiler');
        assert.deepEqual(r.body.achievements, ['recruited', 'identity_confirmed', 'founder']);
        assert.equal(r.body.xp, 200);
        assert.equal(r.body.rank, 'operative');
        assert.equal(r.body.bonusSpins, 1);
        assert.equal(r.body.ranks.length, 6);
    });

    it('wishlist: add is idempotent, earns a badge, and remove works', async () => {
        const add = await api.post(`/wishlist/${pcId}`, undefined, { token: me.token });
        assert.equal(add.status, 200);
        assert.equal(add.body.wishlist.length, 1);
        assert.equal(add.body.wishlist[0].name, 'WISH TARGET');
        assert.ok(add.body.achievements.includes('first_target'));
        assert.equal(add.body.xp, 225);
        const again = await api.post(`/wishlist/${pcId}`, undefined, { token: me.token });
        assert.equal(again.body.wishlist.length, 1);
        const del = await api.del(`/wishlist/${pcId}`, { token: me.token });
        assert.equal(del.body.wishlist.length, 0);
        // KNOWN QUIRK, pinned as it is today: server.js says a badge the account no longer qualifies
        // for is dropped, but syncAchievements starts from the badges already stored, so a badge is
        // kept for good once earned. To fix separately (and then flip this assertion).
        assert.ok(del.body.achievements.includes('first_target'));
    });

    it('achievements: only badges the server cannot see itself may be reported', async () => {
        const server = await api.post('/achievements', { id: 'recruited' }, { token: me.token });
        assert.equal(server.status, 400);
        assert.ok(Array.isArray(server.body.achievements), 'a refused report still answers with the real profile');
        assert.equal((await api.post('/achievements', { id: 'made-up' }, { token: me.token })).status, 400);
        const ok = await api.post('/achievements', { id: 'first_loot' }, { token: me.token });
        assert.equal(ok.status, 200);
        assert.ok(ok.body.achievements.includes('first_loot'));
        assert.equal(ok.body.xp, 250);
    });

    it('the terminal secrets can be reported, pay 10 XP each, and nothing else gets in', async () => {
        const before = (await api.get('/me', { token: me.token })).body.xp;
        for (const id of ['nice_try', 'scorched_earth', 'curious_agent']) {
            const r = await api.post('/achievements', { id }, { token: me.token });
            assert.equal(r.status, 200, id);
            assert.ok(r.body.achievements.includes(id));
        }
        const after = (await api.get('/me', { token: me.token })).body;
        assert.equal(after.xp - before, 30);
        // Reporting the same one twice pays nothing more
        const again = await api.post('/achievements', { id: 'nice_try' }, { token: me.token });
        assert.equal(again.body.xp, after.xp);
    });

    it('reaching a rank pays its colour once, and /me shows it', async () => {
        const r = await api.get('/me', { token: me.token });
        assert.equal(r.body.rank, 'fieldAgent');
        assert.ok(r.body.unlockedColors.includes('ultraviolet'));
        const again = await api.get('/me', { token: me.token });
        assert.equal(again.body.unlockedColors.filter(c => c === 'ultraviolet').length, 1);
    });
});

describe('daily wheel and coupons', () => {
    let spinner;
    before(async () => { spinner = await api.signUp('Spinner'); });

    it('status: three attempts a day, no cooldown yet', async () => {
        const r = await api.get('/wheel', { token: spinner.token });
        assert.equal(r.body.attemptsLeft, 3);
        assert.equal(r.body.maxAttempts, 3);
        assert.equal(r.body.nextAvailableAt, null);
    });

    it('a spin is decided by the server and uses up an attempt; spins run out, then wait a day', async () => {
        // The rank's bonus spin is paid the first time the profile is loaded, not at sign-up
        assert.equal((await api.get('/wheel', { token: spinner.token })).body.bonusSpins, 0);
        assert.equal((await api.get('/me', { token: spinner.token })).body.bonusSpins, 1);
        // The result is random; what is fixed is the bookkeeping
        let last;
        for (let i = 0; i < 3; i++) {
            const r = await api.post('/wheel/spin', undefined, { token: spinner.token });
            assert.equal(r.status, 200);
            assert.ok(r.body.index >= 0 && r.body.index < 8);
            assert.ok(['blank', 'color', 'coupon'].includes(r.body.reward.type));
            last = r.body;
            if (last.attemptsLeft === 0) break;      // a win ends the day's cycle at once
        }
        assert.equal(last.attemptsLeft, 0);
        assert.ok(new Date(last.nextAvailableAt) > new Date());
        // The rank's banked bonus spin can still be used; after that, nothing
        const bonus = await api.post('/wheel/spin', undefined, { token: spinner.token });
        assert.equal(bonus.status, 200);
        assert.equal(bonus.body.bonusSpins, 0);
        const none = await api.post('/wheel/spin', undefined, { token: spinner.token });
        assert.equal(none.status, 429);
        assert.equal(none.body.code, 'NO_SPINS');
    });

    it('coupons: the admin can look one up and redeem it exactly once; expired ones cannot be redeemed', async () => {
        const holder = await api.signUp('Couponer');
        const now = Date.now();
        await api.col('users').updateOne({ username: 'Couponer' }, { $push: { coupons: { $each: [
            { code: 'CDX-GOOD22', percent: 5, issuedAt: new Date(now), expiresAt: new Date(now + 86400e3) },
            { code: 'CDX-OLD222', percent: 5, issuedAt: new Date(now - 40 * 86400e3), expiresAt: new Date(now - 86400e3) }
        ] } } });

        const mine = await api.get('/me', { token: holder.token });
        assert.deepEqual(mine.body.coupons.map(c => c.code), ['CDX-GOOD22'], 'an expired coupon must not be listed');

        assert.equal((await api.get('/admin/coupons/CDX-GOOD22')).status, 401, 'coupon lookup is admin-only');
        const look = await api.get('/admin/coupons/cdx-good22', { token: admin });   // case-insensitive
        assert.equal(look.status, 200);
        assert.equal(look.body.username, 'Couponer');
        assert.equal(look.body.usedAt, null);
        assert.equal((await api.get('/admin/coupons/CDX-NOPE22', { token: admin })).status, 404);

        const redeem = await api.post('/admin/coupons/CDX-GOOD22/redeem', undefined, { token: admin });
        assert.equal(redeem.status, 200);
        assert.equal((await api.post('/admin/coupons/CDX-GOOD22/redeem', undefined, { token: admin })).status, 409, 'redeemed twice');
        assert.equal((await api.post('/admin/coupons/CDX-OLD222/redeem', undefined, { token: admin })).status, 409, 'redeemed after expiry');
        assert.ok((await api.get('/admin/coupons/CDX-GOOD22', { token: admin })).body.usedAt);
    });
});

describe('repeated wrong passwords', () => {
    // A server of its own: these use up the per-address sign-in allowance
    it('lock one account after five failures, even for the right password', async () => {
        const fresh = await startBackend();
        try {
            const frank = await fresh.signUp('Franklin');
            for (let i = 0; i < 5; i++) {
                assert.equal((await fresh.post('/user-login', { username: 'Franklin', password: 'wrong-guess-1' })).status, 400, `attempt ${i + 1}`);
            }
            const locked = await fresh.post('/user-login', { username: 'Franklin', password: frank.password });
            assert.equal(locked.status, 429);
            assert.match(locked.body.error, /Too many failed attempts/);
        } finally { await fresh.stop(); }
    });

    it('the per-address limit stops a run of guesses across many names', async () => {
        const fresh = await startBackend();
        try {
            let blocked = 0;
            for (let i = 0; i < 14; i++) {
                const r = await fresh.post('/user-login', { username: `ghost${i}`, password: 'whatever-1' });
                if (r.status === 429) blocked++;
            }
            assert.ok(blocked >= 3, `expected the address to be limited after 10 attempts, ${blocked} were blocked`);
        } finally { await fresh.stop(); }
    });
});
