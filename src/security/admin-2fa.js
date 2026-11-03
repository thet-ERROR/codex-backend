// What the admin sign-in and the two-factor settings share: the password check, the second factor
// (a code from the authenticator app, or a one-time recovery code), recovery codes, and issuing the
// admin session token. Failures of either factor count towards the same admin lockout
// (login-lockout.js), so knowing the password is no licence to guess six-digit codes.
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { ADMIN_PASSWORD, JWT_SECRET } = require('../config');
const { AdminSecurity } = require('../models/admin-security');
const { verify } = require('../lib/totp');
const { open } = require('../lib/secret-box');

// Constant-time: both sides hashed first so the buffers are the same length
function adminPasswordMatches(supplied) {
    if (!ADMIN_PASSWORD) return false;
    const a = crypto.createHash('sha256').update(String(supplied || '')).digest();
    const b = crypto.createHash('sha256').update(ADMIN_PASSWORD).digest();
    return crypto.timingSafeEqual(a, b);
}

const issueAdminToken = (securityVersion) => jwt.sign({ role: 'admin', sv: securityVersion || 0 }, JWT_SECRET, { expiresIn: '8h' });

// The short-lived proof that the password was right, traded for a session once the code is too
const issueChallenge = (securityVersion) => jwt.sign({ role: 'admin-2fa', sv: securityVersion || 0 }, JWT_SECRET, { expiresIn: '5m' });
function readChallenge(token) {
    try {
        const d = jwt.verify(String(token || ''), JWT_SECRET);
        return d.role === 'admin-2fa' ? d : null;
    } catch (e) { return null; }
}

// --- recovery codes ---
const RECOVERY_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'; // no 0/O, 1/I/L
const RECOVERY_COUNT = 10;
const normaliseRecovery = (c) => String(c || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
const hashRecovery = (c) => crypto.createHash('sha256').update(normaliseRecovery(c)).digest('hex');
function newRecoveryCodes() {
    const codes = Array.from({ length: RECOVERY_COUNT }, () => {
        let s = '';
        for (let i = 0; i < 8; i++) s += RECOVERY_ALPHABET[crypto.randomInt(RECOVERY_ALPHABET.length)];
        return `${s.slice(0, 4)}-${s.slice(4)}`;
    });
    return { codes, hashes: codes.map(hashRecovery) };
}

// Checks the second factor against the stored (enabled) secret and spends it: a code's step is
// recorded so the same code can't be replayed, a recovery code is removed. Both writes are
// conditional updates, so two requests with the same code can't both pass.
// Returns { ok: true, usedRecovery } or { ok: false, status, error }.
async function spendSecondFactor({ code, recoveryCode }) {
    const sec = await AdminSecurity.findById('admin');
    if (!sec || !sec.totpEnabled) return { ok: false, status: 400, error: 'Two-factor sign-in is not on' };

    if (recoveryCode) {
        const spent = await AdminSecurity.updateOne(
            { _id: 'admin', recoveryHashes: hashRecovery(recoveryCode) },
            { $pull: { recoveryHashes: hashRecovery(recoveryCode) } }
        );
        return spent.modifiedCount ? { ok: true, usedRecovery: true } : { ok: false, status: 401, error: 'Wrong or already used recovery code' };
    }

    let secret;
    try { secret = open(sec.totpSecret); }
    catch (e) { return { ok: false, status: 503, error: 'The server cannot read the authenticator secret (ADMIN_2FA_KEY). Use a recovery code.' }; }
    const step = verify(secret, code);
    if (step === null) return { ok: false, status: 401, error: 'Wrong code' };
    const spent = await AdminSecurity.updateOne({ _id: 'admin', lastStep: { $lt: step } }, { $set: { lastStep: step } });
    return spent.modifiedCount ? { ok: true, usedRecovery: false } : { ok: false, status: 401, error: 'That code was already used — wait for the next one' };
}

module.exports = { adminPasswordMatches, issueAdminToken, issueChallenge, readChallenge, newRecoveryCodes, spendSecondFactor, RECOVERY_COUNT };
