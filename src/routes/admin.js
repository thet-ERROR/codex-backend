// Admin sign-in (password, then the authenticator code when two-factor sign-in is on), the
// two-factor settings, and the accounts list.
const { ADMIN_PASSWORD } = require('../config');
const { loginLimiter } = require('../security/rate-limits');
const { accountLockMinutesLeft, recordFailedLogin, clearFailedLogins } = require('../security/login-lockout');
const { requireAuthConfig, auth } = require('../security/auth');
const { adminPasswordMatches, issueAdminToken, issueChallenge, readChallenge, newRecoveryCodes, spendSecondFactor } = require('../security/admin-2fa');
const { asString } = require('../lib/validation');
const { generateSecret, verify, otpauthUrl, base32Encode } = require('../lib/totp');
const { keyConfigured, seal, open } = require('../lib/secret-box');
const User = require('../models/user');
const { AdminSecurity, getAdminSecurity } = require('../models/admin-security');

const router = require('express').Router();

router.get('/api/users/count', auth, async (req, res) => { const count = await User.countDocuments(); res.json({ count }); });

// Admin user management — added so test/duplicate accounts (which block re-registering an email,
// by design — see /api/register's uniqueness check) can be cleared from the panel instead of
// needing direct database access every time. Password hash and tokens are never selected.
router.get('/api/users', auth, async (req, res) => {
    try {
        const users = await User.find()
            .select('username email joined subscribed emailVerified wishlist achievements securityLockedUntil')
            .sort({ joined: -1 })
            .limit(500); // demo-scale cap — swap for real pagination if the user base grows
        res.json(users);
    } catch (e) { console.error("List users failed:", e); res.status(500).json({ error: "Server Error" }); }
});

router.delete('/api/users/:id', auth, async (req, res) => {
    try {
        const deleted = await User.findByIdAndDelete(req.params.id);
        if (!deleted) return res.status(404).json({ error: "User not found" });
        res.json({ success: true });
    } catch (e) { console.error("Delete user failed:", e); res.status(400).json({ error: "Invalid user id" }); }
});
// Only one admin account exists, so a single fixed key is enough to lock it out after repeated
// failures — same account-lockout mechanism as user-login. Wrong second-factor codes count too.
function lockedOut(res) {
    const lockedMin = accountLockMinutesLeft('admin');
    if (lockedMin > 0) {
        res.status(429).json({ success: false, error: `Too many failed attempts. Try again in ${lockedMin} minute(s).` });
        return true;
    }
    return false;
}

router.post('/api/login', loginLimiter, requireAuthConfig, async (req, res) => {
    if (!ADMIN_PASSWORD) return res.status(503).json({ success: false, error: "ADMIN PASSWORD NOT CONFIGURED" });
    if (lockedOut(res)) return;

    // Constant-time compare: a plain === leaks how many leading characters were right, which is
    // enough to recover a password one byte at a time (see adminPasswordMatches)
    if (!adminPasswordMatches(asString(req.body.password))) { recordFailedLogin('admin'); return res.status(403).json({ success: false }); }

    const sec = await getAdminSecurity();
    // With two-factor sign-in on, the right password only earns a 5-minute challenge, traded at
    // /api/login/2fa for a session once the authenticator code is right as well. The failure count
    // is not cleared yet: a wrong code still counts against the lockout.
    if (sec.totpEnabled) {
        return res.json({ success: true, twoFactorRequired: true, challenge: issueChallenge(sec.securityVersion) });
    }
    clearFailedLogins('admin');
    // The panel gets a scoped, expiring token instead of holding the password in a JS variable
    res.json({ success: true, token: issueAdminToken(sec.securityVersion) });
});

// Second step: the challenge from /api/login plus a code from the authenticator app, or one of the
// recovery codes (a lost phone)
router.post('/api/login/2fa', loginLimiter, requireAuthConfig, async (req, res) => {
    if (lockedOut(res)) return;
    const challenge = readChallenge(req.body?.challenge);
    const sec = await getAdminSecurity();
    if (!challenge || !sec.totpEnabled || (challenge.sv || 0) !== sec.securityVersion) {
        return res.status(401).json({ success: false, error: 'Sign-in expired — enter the password again', code: 'CHALLENGE_EXPIRED' });
    }
    const result = await spendSecondFactor({ code: asString(req.body.code), recoveryCode: asString(req.body.recoveryCode) });
    if (!result.ok) {
        if (result.status === 401) recordFailedLogin('admin');
        return res.status(result.status).json({ success: false, error: result.error });
    }
    clearFailedLogins('admin');
    const fresh = await AdminSecurity.findById('admin').select('recoveryHashes securityVersion').lean();
    res.json({ success: true, token: issueAdminToken(fresh.securityVersion), usedRecovery: result.usedRecovery, recoveryCodesLeft: fresh.recoveryHashes.length });
});

// --- two-factor settings (signed in as admin) ---
router.get('/api/admin/2fa', auth, async (req, res) => {
    const sec = await getAdminSecurity();
    res.json({ enabled: !!sec.totpEnabled, keyConfigured: keyConfigured(), recoveryCodesLeft: (sec.recoveryHashes || []).length, enabledAt: sec.enabledAt || null });
});

// Step 1 of turning it on: a new secret, kept aside until a code proves the app has it
router.post('/api/admin/2fa/setup', auth, async (req, res) => {
    if (!keyConfigured()) return res.status(503).json({ error: 'ADMIN_2FA_KEY is not set on the server', code: 'NO_KEY' });
    const sec = await getAdminSecurity();
    if (sec.totpEnabled) return res.status(409).json({ error: 'Two-factor sign-in is already on — turn it off first' });
    const secret = generateSecret();
    await AdminSecurity.updateOne({ _id: 'admin' }, { $set: { totpPending: seal(secret) } }, { upsert: true });
    res.json({ otpauthUrl: otpauthUrl(secret), secret: base32Encode(secret) });
});

// Step 2: a code from the app. Turns it on, hands out the recovery codes (shown this once), and ends
// every other admin session; this one continues with the new token.
router.post('/api/admin/2fa/enable', auth, async (req, res) => {
    if (lockedOut(res)) return;
    const sec = await AdminSecurity.findById('admin');
    if (!sec || !sec.totpPending) return res.status(400).json({ error: 'Start the setup first' });
    if (sec.totpEnabled) return res.status(409).json({ error: 'Two-factor sign-in is already on' });
    const step = verify(open(sec.totpPending), asString(req.body?.code));
    if (step === null) { recordFailedLogin('admin'); return res.status(400).json({ error: 'Wrong code — check the phone\'s clock and try the current one' }); }
    const { codes, hashes } = newRecoveryCodes();
    const updated = await AdminSecurity.findOneAndUpdate(
        { _id: 'admin', totpEnabled: { $ne: true } },
        { $set: { totpEnabled: true, totpSecret: sec.totpPending, recoveryHashes: hashes, lastStep: step, enabledAt: new Date() }, $unset: { totpPending: 1 }, $inc: { securityVersion: 1 } },
        { new: true }
    );
    if (!updated) return res.status(409).json({ error: 'Two-factor sign-in is already on' });
    clearFailedLogins('admin');
    res.json({ success: true, recoveryCodes: codes, token: issueAdminToken(updated.securityVersion) });
});

// New recovery codes (the old ones stop working) — needs a current code from the app
router.post('/api/admin/2fa/recovery-codes', auth, async (req, res) => {
    if (lockedOut(res)) return;
    const result = await spendSecondFactor({ code: asString(req.body?.code) });
    if (!result.ok) {
        if (result.status === 401) recordFailedLogin('admin');
        return res.status(result.status).json({ error: result.error });
    }
    const { codes, hashes } = newRecoveryCodes();
    await AdminSecurity.updateOne({ _id: 'admin' }, { $set: { recoveryHashes: hashes } });
    res.json({ success: true, recoveryCodes: codes });
});

// Turning it off needs the password and a second factor, so a session left open on someone else's
// screen can't quietly drop it. Ends every other admin session too.
router.post('/api/admin/2fa/disable', auth, async (req, res) => {
    if (lockedOut(res)) return;
    if (!adminPasswordMatches(asString(req.body?.password))) { recordFailedLogin('admin'); return res.status(403).json({ error: 'Wrong password' }); }
    const result = await spendSecondFactor({ code: asString(req.body?.code), recoveryCode: asString(req.body?.recoveryCode) });
    if (!result.ok) {
        if (result.status === 401) recordFailedLogin('admin');
        return res.status(result.status).json({ error: result.error });
    }
    const updated = await AdminSecurity.findOneAndUpdate(
        { _id: 'admin' },
        { $set: { totpEnabled: false, recoveryHashes: [] }, $unset: { totpSecret: 1, totpPending: 1, enabledAt: 1 }, $inc: { securityVersion: 1 } },
        { new: true }
    );
    clearFailedLogins('admin');
    res.json({ success: true, token: issueAdminToken(updated.securityVersion) });
});

module.exports = router;
