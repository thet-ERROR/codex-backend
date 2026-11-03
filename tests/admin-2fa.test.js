// The admin's two-factor sign-in: turning it on with an authenticator app, signing in with a code or a
// recovery code, replays, guessing, sessions ended by the change, turning it off. Run: npm test

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { startBackend, ADMIN_PASSWORD } from './harness.js';
const require = createRequire(import.meta.url);
const totp = require('../src/lib/totp.js');

// What the phone's app would show, a given number of 30-second steps from now
const codeFor = (secretB32, offset = 0) => totp.hotp(totp.base32Decode(secretB32), totp.stepAt() + offset);

describe('turning two-factor sign-in on, and signing in with it', () => {
    let api, token, secret, recovery;
    before(async () => { api = await startBackend(); token = await api.adminToken(); });
    after(async () => { await api.stop(); });

    it('starts off, with the server key in place', async () => {
        const r = await api.get('/admin/2fa', { token });
        assert.deepEqual(r.body, { enabled: false, keyConfigured: true, recoveryCodesLeft: 0, enabledAt: null });
        assert.equal((await api.get('/admin/2fa')).status, 401);
    });

    it('setup gives the QR link and the key to type in by hand', async () => {
        const r = await api.post('/admin/2fa/setup', undefined, { token });
        assert.equal(r.status, 200);
        assert.match(r.body.secret, /^[A-Z2-7]{32}$/);
        assert.equal(r.body.otpauthUrl, `otpauth://totp/PHOENIX%20CODEX%3Aadmin?secret=${r.body.secret}&issuer=PHOENIX%20CODEX&algorithm=SHA1&digits=6&period=30`);
        secret = r.body.secret;
        // Not on yet: the password alone still signs in
        assert.ok((await api.post('/login', { password: ADMIN_PASSWORD })).body.token);
    });

    it('a wrong code does not turn it on; the right one does, with ten recovery codes', async () => {
        assert.equal((await api.post('/admin/2fa/enable', { code: '000000' }, { token })).status, 400);
        const r = await api.post('/admin/2fa/enable', { code: codeFor(secret) }, { token });
        assert.equal(r.status, 200);
        assert.equal(r.body.recoveryCodes.length, 10);
        assert.equal(new Set(r.body.recoveryCodes).size, 10);
        r.body.recoveryCodes.forEach(c => assert.match(c, /^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/));
        recovery = r.body.recoveryCodes;

        assert.equal((await api.get('/admin/orders', { token })).status, 401, 'sessions from before must end');
        token = r.body.token;
        assert.equal((await api.get('/admin/orders', { token })).status, 200, 'this session goes on with the new token');
        assert.equal((await api.get('/admin/2fa', { token })).body.enabled, true);
    });

    it('nothing secret is stored readable: the key is sealed, the recovery codes hashed', async () => {
        const doc = await api.col('adminsecurities').findOne({ _id: 'admin' });
        assert.notEqual(doc.totpSecret, secret);
        assert.equal(doc.totpSecret.split('.').length, 3);
        assert.equal(doc.recoveryHashes.length, 10);
        assert.ok(doc.recoveryHashes.every(h => /^[a-f0-9]{64}$/.test(h)));
        assert.ok(!JSON.stringify(doc).includes(recovery[0].replace('-', '')));
    });

    it('the password alone now only earns a challenge', async () => {
        const r = await api.post('/login', { password: ADMIN_PASSWORD });
        assert.equal(r.body.twoFactorRequired, true);
        assert.equal(r.body.token, undefined);
        assert.ok(r.body.challenge);
        assert.equal((await api.post('/login', { password: 'wrong' })).status, 403);
    });

    it('challenge + code signs in; a wrong code does not; the same code never works twice', async () => {
        const { challenge } = (await api.post('/login', { password: ADMIN_PASSWORD })).body;
        assert.equal((await api.post('/login/2fa', { challenge, code: '123456' })).status, 401);
        const code = codeFor(secret, 1);
        const ok = await api.post('/login/2fa', { challenge, code });
        assert.equal(ok.status, 200);
        assert.equal((await api.get('/admin/orders', { token: ok.body.token })).status, 200);
        const replay = await api.post('/login/2fa', { challenge, code });
        assert.equal(replay.status, 401);
        assert.match(replay.body.error, /already used/);
        // An older code still inside the time window, after a newer one was used: only the "never go
        // back" rule refuses it (a captured code from a moment ago must not open the panel)
        const older = await api.post('/login/2fa', { challenge, code: codeFor(secret, 0) });
        assert.equal(older.status, 401);
    });

});

// A server of its own: signing in is limited to 10 tries per 15 minutes per address, password and
// code steps together, and the group above uses most of that
describe('signing in with a recovery code, and turning two-factor sign-in off', () => {
    let api, token, secret, recovery;
    before(async () => {
        api = await startBackend();
        const token0 = await api.adminToken();
        secret = (await api.post('/admin/2fa/setup', undefined, { token: token0 })).body.secret;
        const on = (await api.post('/admin/2fa/enable', { code: codeFor(secret) }, { token: token0 })).body;
        token = on.token;
        recovery = on.recoveryCodes;
    });
    after(async () => { await api.stop(); });

    it('a made-up or user challenge is refused', async () => {
        assert.equal((await api.post('/login/2fa', { challenge: 'nonsense', code: codeFor(secret) })).body.code, 'CHALLENGE_EXPIRED');
        const member = await api.signUp('Sneaky');
        assert.equal((await api.post('/login/2fa', { challenge: member.token, code: codeFor(secret) })).body.code, 'CHALLENGE_EXPIRED');
    });

    it('a recovery code signs in once, without the phone', async () => {
        const { challenge } = (await api.post('/login', { password: ADMIN_PASSWORD })).body;
        const r = await api.post('/login/2fa', { challenge, recoveryCode: recovery[0].toLowerCase().replace('-', ' ') });
        assert.equal(r.status, 200);
        assert.equal(r.body.usedRecovery, true);
        assert.equal(r.body.recoveryCodesLeft, 9);
        assert.equal((await api.post('/login/2fa', { challenge, recoveryCode: recovery[0] })).status, 401, 'a recovery code works once');
        token = r.body.token;
    });

    it('turning it off needs the password and a second factor, and ends the other sessions', async () => {
        const other = token;
        assert.equal((await api.post('/admin/2fa/disable', { password: 'wrong', recoveryCode: recovery[1] }, { token })).status, 403);
        const r = await api.post('/admin/2fa/disable', { password: ADMIN_PASSWORD, recoveryCode: recovery[1] }, { token });
        assert.equal(r.status, 200);
        assert.equal((await api.get('/admin/orders', { token: other })).status, 401);
        assert.equal((await api.get('/admin/orders', { token: r.body.token })).status, 200);
        assert.ok((await api.post('/login', { password: ADMIN_PASSWORD })).body.token, 'the password alone signs in again');
        const doc = await api.col('adminsecurities').findOne({ _id: 'admin' });
        assert.equal(doc.totpSecret, undefined);
        assert.deepEqual(doc.recoveryHashes, []);
    });
});

describe('two-factor: new recovery codes, guessing, a missing server key', () => {
    it('new recovery codes need a current code, and replace the old ones', async () => {
        const api = await startBackend();
        try {
            const token0 = await api.adminToken();
            const { secret } = (await api.post('/admin/2fa/setup', undefined, { token: token0 })).body;
            const on = (await api.post('/admin/2fa/enable', { code: codeFor(secret, -1) }, { token: token0 })).body;
            const old = on.recoveryCodes;
            assert.equal((await api.post('/admin/2fa/recovery-codes', { code: '000000' }, { token: on.token })).status, 401);
            const fresh = await api.post('/admin/2fa/recovery-codes', { code: codeFor(secret, 0) }, { token: on.token });
            assert.equal(fresh.status, 200);
            const { challenge } = (await api.post('/login', { password: ADMIN_PASSWORD })).body;
            assert.equal((await api.post('/login/2fa', { challenge, recoveryCode: old[0] })).status, 401, 'old codes stop working');
            assert.equal((await api.post('/login/2fa', { challenge, recoveryCode: fresh.body.recoveryCodes[0] })).status, 200);
        } finally { await api.stop(); }
    });

    it('five wrong codes lock the admin out, even with the right code after', async () => {
        const api = await startBackend();
        try {
            const token0 = await api.adminToken();
            const { secret } = (await api.post('/admin/2fa/setup', undefined, { token: token0 })).body;
            await api.post('/admin/2fa/enable', { code: codeFor(secret) }, { token: token0 });
            const { challenge } = (await api.post('/login', { password: ADMIN_PASSWORD })).body;
            for (let i = 0; i < 5; i++) assert.equal((await api.post('/login/2fa', { challenge, code: String(100000 + i) })).status, 401, `guess ${i + 1}`);
            const locked = await api.post('/login/2fa', { challenge, code: codeFor(secret, 1) });
            assert.equal(locked.status, 429);
            assert.equal((await api.post('/login', { password: ADMIN_PASSWORD })).status, 429, 'the password step is locked too');
        } finally { await api.stop(); }
    });

    it('without ADMIN_2FA_KEY on the server it cannot be set up, and says why', async () => {
        const api = await startBackend({ env: { ADMIN_2FA_KEY: '' } });
        try {
            const token = await api.adminToken();
            assert.equal((await api.get('/admin/2fa', { token })).body.keyConfigured, false);
            const r = await api.post('/admin/2fa/setup', undefined, { token });
            assert.equal(r.status, 503);
            assert.equal(r.body.code, 'NO_KEY');
        } finally { await api.stop(); }
    });
});
