// Admin sign-in and the accounts list.
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { ADMIN_PASSWORD, JWT_SECRET } = require('../config');
const { loginLimiter } = require('../security/rate-limits');
const { accountLockMinutesLeft, recordFailedLogin, clearFailedLogins } = require('../security/login-lockout');
const { requireAuthConfig, auth } = require('../security/auth');
const { asString } = require('../lib/validation');
const User = require('../models/user');

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
router.post('/api/login', loginLimiter, requireAuthConfig, (req, res) => {
    const supplied = asString(req.body.password);
    if (!ADMIN_PASSWORD) return res.status(503).json({ success: false, error: "ADMIN PASSWORD NOT CONFIGURED" });

    // Only one admin account exists, so a single fixed key is enough to lock it out after
    // repeated failures — same account-lockout mechanism as user-login, above.
    const lockedMin = accountLockMinutesLeft('admin');
    if (lockedMin > 0) {
        return res.status(429).json({ success: false, error: `Too many failed attempts. Try again in ${lockedMin} minute(s).` });
    }

    // Constant-time compare: a plain === leaks how many leading characters were right, which is
    // enough to recover a password one byte at a time. Hashing both sides first keeps the
    // buffers equal-length, which timingSafeEqual requires.
    const a = crypto.createHash('sha256').update(supplied).digest();
    const b = crypto.createHash('sha256').update(ADMIN_PASSWORD).digest();
    if (!crypto.timingSafeEqual(a, b)) { recordFailedLogin('admin'); return res.status(403).json({ success: false }); }

    clearFailedLogins('admin');
    // The panel gets a scoped, expiring token instead of holding the password in a JS variable
    const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ success: true, token });
});

module.exports = router;
