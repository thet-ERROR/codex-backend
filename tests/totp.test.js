// The TOTP code generator against the RFC's own test vectors, and the base32 the QR code carries.
// Run: npm test

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const totp = require('../src/lib/totp.js');

describe('TOTP (RFC 6238)', () => {
    // RFC 6238 appendix B, SHA1, secret "12345678901234567890", 8 digits
    const secret = Buffer.from('12345678901234567890');
    const vectors = [[59, '94287082'], [1111111109, '07081804'], [1111111111, '14050471'], [1234567890, '89005924'], [2000000000, '69279037'], [20000000000, '65353130']];
    for (const [time, expected] of vectors) {
        it(`T=${time} gives ${expected}`, () => {
            assert.equal(totp.hotp(secret, Math.floor(time / 30), 8), expected);
        });
    }

    it('verifies the current code and one step either side, nothing further', () => {
        const now = 1_700_000_000_000;
        const step = totp.stepAt(now);
        for (const s of [step - 1, step, step + 1]) assert.equal(totp.verify(secret, totp.hotp(secret, s), { now }), s);
        assert.equal(totp.verify(secret, totp.hotp(secret, step + 2), { now }), null);
        assert.equal(totp.verify(secret, totp.hotp(secret, step - 2), { now }), null);
        assert.equal(totp.verify(secret, '12345', { now }), null);
        assert.equal(totp.verify(secret, 'abcdef', { now }), null);
    });

    it('base32 round-trips, as authenticator apps expect it (RFC 4648)', () => {
        assert.equal(totp.base32Encode(Buffer.from('foobar')), 'MZXW6YTBOI');
        assert.deepEqual(totp.base32Decode('MZXW6YTBOI'), Buffer.from('foobar'));
        const s = totp.generateSecret();
        assert.deepEqual(totp.base32Decode(totp.base32Encode(s)), s);
    });

    it('the QR link carries what Google Authenticator reads', () => {
        const url = totp.otpauthUrl(Buffer.from('foobar'));
        assert.equal(url, 'otpauth://totp/PHOENIX%20CODEX%3Aadmin?secret=MZXW6YTBOI&issuer=PHOENIX%20CODEX&algorithm=SHA1&digits=6&period=30');
    });
});
