// Accounts: sign-up, email verification, sign-in, the profile, password reset.
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../config');
const { authLimiter, loginLimiter } = require('../security/rate-limits');
const { accountLockMinutesLeft, recordFailedLogin, clearFailedLogins } = require('../security/login-lockout');
const { BcryptBusyError, withBcrypt, BUSY_ERROR } = require('../security/bcrypt-queue');
const { requireAuthConfig, authUser, requireVerified } = require('../security/auth');
const { asString, isValidEmail, isDisposableEmail, domainAcceptsMail } = require('../lib/validation');
const User = require('../models/user');
const Newsletter = require('../models/newsletter');
const { syncAchievements } = require('../lib/achievements');
const { sendMail, issueEmailVerification, issueSecurityReportToken, sendVerificationEmail } = require('../lib/email');
const { couponsFor } = require('../lib/wheel');

const router = require('express').Router();

router.post('/api/register', authLimiter, requireAuthConfig, async (req, res) => {
    try {
        const username = asString(req.body.username).trim();
        const email = asString(req.body.email).trim().toLowerCase();
        const password = asString(req.body.password);
        const subscribed = req.body.subscribed === true;

        if (username.length < 3 || username.length > 24 || !/^[a-zA-Z0-9_.-]+$/.test(username)) {
            return res.status(400).json({ error: "Username must be 3-24 characters (letters, numbers, . _ - only)" });
        }
        if (!isValidEmail(email)) {
            return res.status(400).json({ error: "Please enter a valid email address" });
        }
        if (isDisposableEmail(email)) {
            return res.status(400).json({ error: "Temporary/disposable email addresses are not accepted" });
        }
        if (password.length < 8 || password.length > 200) {
            return res.status(400).json({ error: "Password must be at least 8 characters" });
        }
        // Checked after the cheap validations so a DNS round trip only happens for plausible input
        if (!await domainAcceptsMail(email)) {
            return res.status(400).json({ error: "That email domain can't receive mail — please check the address" });
        }

        if (await User.findOne({ email })) return res.status(400).json({ error: "Email exists" });
        // Checked explicitly — the unique index alone would surface as an unhelpful 500
        if (await User.findOne({ username })) return res.status(400).json({ error: "Username already taken" });

        const hashedPassword = await withBcrypt(() => bcrypt.hash(password, 12));
        const newUser = new User({ username, email, password: hashedPassword, subscribed });
        const rawVerifyToken = issueEmailVerification(newUser);
        const rawReportToken = issueSecurityReportToken(newUser);
        newUser.lastVerificationEmailSentAt = new Date();
        await newUser.save();
        if (subscribed) {
            try { await new Newsletter({ email }).save(); } catch (e) { console.error("Newsletter subscribe failed:", e); }
        }
        // Fire-and-forget: NOT awaited. Gmail SMTP occasionally takes several seconds (or hangs)
        // to respond, and this used to block the response until it finished — from the browser's
        // side that looked exactly like clicking Register "did nothing", even though the account
        // was already saved above. The account still exists and can request a fresh link via
        // /api/resend-verification, so a slow or failed send here must never hold up the reply.
        sendVerificationEmail(newUser, rawVerifyToken, rawReportToken).catch(e => console.error("Verification email send failed:", e));

        const token = jwt.sign({ id: newUser._id, username: newUser.username, tokenVersion: newUser.tokenVersion }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ success: true, username: newUser.username, token, emailVerified: false });
    } catch (e) {
        if (e instanceof BcryptBusyError) return res.status(503).json(BUSY_ERROR);
        console.error("Register failed:", e); res.status(500).json({ error: "Error" });
    }
});

// Public — proving you control the emailed token IS the auth. Called by the frontend's own POST
// after the verification link's page loads (see js/main.js), never by a bare GET, so a mail
// client's automatic link-preview scan can't verify an account no one asked it to.
router.post('/api/verify-email', authLimiter, async (req, res) => {
    try {
        const token = asString(req.body.token).trim();
        if (!token) return res.status(400).json({ success: false, error: "Missing token" });
        const hashed = crypto.createHash('sha256').update(token).digest('hex');
        const user = await User.findOne({ emailVerifyTokenHash: hashed, emailVerifyExpiry: { $gt: Date.now() } });
        if (!user) return res.status(400).json({ success: false, error: "Invalid or expired verification link" });
        user.emailVerified = true;
        user.emailVerifyTokenHash = undefined;
        user.emailVerifyExpiry = undefined;
        // This IS the account owner completing signup — the "wasn't you?" link from this same
        // email (and any earlier resend) stops working the moment that's proven, so a genuine
        // owner can never dig up an old email later and lock themselves out by clicking it.
        user.securityReportTokenHash = undefined;
        user.securityReportTokenExpiry = undefined;
        await user.save();
        res.json({ success: true });
    } catch (e) { console.error("Verify email failed:", e); res.status(500).json({ success: false, error: "Server Error" }); }
});

// Requires a valid session but deliberately NOT requireVerified — this is the one way out of the
// unverified state, so gating it behind the same gate would be a dead end for anyone whose first
// email never arrived.
const RESEND_VERIFICATION_COOLDOWN_MS = 60 * 1000;

router.post('/api/resend-verification', authLimiter, authUser, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: "User not found" });
        if (user.emailVerified) return res.json({ success: true, alreadyVerified: true });

        // Separate from authLimiter (100 requests/15min, shared across every auth route — loose
        // enough that mashing this button ten times would queue ten emails before it ever
        // engaged). retryAfterMs lets the frontend show a live countdown instead of a flat "wait".
        const elapsed = user.lastVerificationEmailSentAt ? Date.now() - user.lastVerificationEmailSentAt.getTime() : Infinity;
        if (elapsed < RESEND_VERIFICATION_COOLDOWN_MS) {
            return res.status(429).json({
                error: "Please wait before requesting another verification email",
                retryAfterMs: RESEND_VERIFICATION_COOLDOWN_MS - elapsed
            });
        }

        const rawVerifyToken = issueEmailVerification(user);
        const rawReportToken = issueSecurityReportToken(user);
        user.lastVerificationEmailSentAt = new Date();
        await user.save();
        // Same reasoning as /api/register — don't let a slow mail server hold up the response.
        sendVerificationEmail(user, rawVerifyToken, rawReportToken).catch(e => console.error("Resend verification email send failed:", e));
        res.json({ success: true });
    } catch (e) { console.error("Resend verification failed:", e); res.status(500).json({ error: "Server Error" }); }
});

// Public — the raw token IS the proof, same shape as /api/verify-email. Deliberately NOT
// single-use: the real owner may open several old copies of this email over the following days,
// and each click should just reconfirm the lock rather than fail on the second attempt.
router.post('/api/report-unauthorized-signup', authLimiter, async (req, res) => {
    try {
        const token = asString(req.body.token).trim();
        if (!token) return res.status(400).json({ success: false, error: "Missing token" });
        const hashed = crypto.createHash('sha256').update(token).digest('hex');
        const user = await User.findOne({ securityReportTokenHash: hashed, securityReportTokenExpiry: { $gt: Date.now() } });
        if (!user) return res.status(400).json({ success: false, error: "Invalid or expired security link" });

        // The token survives verification's undefined-ing race only if verification happened in
        // the same instant — in practice this means someone reporting their OWN, already-confirmed
        // account from a stale email. Treat that as inert rather than locking a legitimate owner
        // out of their own account.
        if (user.emailVerified) {
            return res.json({ success: true, alreadyVerified: true });
        }

        user.securityLockedUntil = new Date(Date.now() + 5 * 24 * 60 * 60 * 1000);
        // Whoever registered can no longer complete verification with the link already mailed to
        // the real owner's inbox...
        user.emailVerifyTokenHash = undefined;
        user.emailVerifyExpiry = undefined;
        // ...and if they're already mid-session, tokenVersion is what the existing authUser check
        // enforces — this kills that session on its very next request, not just future logins.
        user.tokenVersion = (user.tokenVersion || 0) + 1;
        await user.save();
        res.json({ success: true, lockedUntil: user.securityLockedUntil });
    } catch (e) { console.error("Report unauthorized signup failed:", e); res.status(500).json({ success: false, error: "Server Error" }); }
});

router.post('/api/user-login', loginLimiter, requireAuthConfig, async (req, res) => {
    // Coerced to strings first: a body of {"username": {"$ne": null}} would otherwise make
    // findOne match the first user in the collection.
    const username = asString(req.body.username).trim();
    const password = asString(req.body.password);
    const lockKey = `user:${username.toLowerCase()}`;
    try {
        if (!username || !password) return res.status(400).json({ error: "Invalid Credentials" });

        const lockedMin = accountLockMinutesLeft(lockKey);
        if (lockedMin > 0) {
            return res.status(429).json({ error: `Too many failed attempts for this account. Try again in ${lockedMin} minute(s).` });
        }

        const user = await User.findOne({ username });
        if (!user) { recordFailedLogin(lockKey); return res.status(400).json({ error: "Invalid Credentials" }); }
        const isMatch = await withBcrypt(() => bcrypt.compare(password, user.password));
        if (isMatch) {
            // Checked only AFTER the password matches, deliberately: revealing "this account is
            // locked" to someone who doesn't actually hold the password would let a brute-force
            // attempt confirm a username is real and reported, without proving anything else.
            if (user.securityLockedUntil && user.securityLockedUntil > new Date()) {
                const hoursLeft = Math.ceil((user.securityLockedUntil - new Date()) / (60 * 60 * 1000));
                return res.status(403).json({
                    error: `This account was reported as unauthorized and is locked for ${hoursLeft} more hour(s).`,
                    code: "ACCOUNT_LOCKED"
                });
            }
            clearFailedLogins(lockKey);
            const token = jwt.sign({ id: user._id, username: user.username, tokenVersion: user.tokenVersion }, JWT_SECRET, { expiresIn: '30d' });
            res.json({ success: true, username: user.username, token, emailVerified: user.emailVerified });
        }
        else { recordFailedLogin(lockKey); res.status(400).json({ error: "Invalid Credentials" }); }
    } catch (e) {
        if (e instanceof BcryptBusyError) return res.status(503).json(BUSY_ERROR);
        console.error("Login failed:", e); res.status(500).json({ error: "Server Error" });
    }
});

router.get('/api/me', authUser, requireVerified, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: "User not found" });
        // Every read is also a re-verification: a badge earned by state the account no longer has
        // (say a wishlist trimmed back below five) is dropped here rather than lingering forever.
        // Run before populate so the save inside it writes a plain id array, same as the wishlist
        // routes do.
        const profile = await syncAchievements(user);
        await user.populate('wishlist');
        res.json({ username: user.username, wishlist: user.wishlist, ...profile, coupons: couponsFor(user), unlockedColors: user.unlockedColors || [] });
    } catch (e) { console.error("/api/me failed:", e); res.status(500).json({ error: "Server Error" }); }
});

router.post('/api/forgot-password', authLimiter, async (req, res) => {
    const email = asString(req.body.email).trim().toLowerCase();
    try {
        const user = await User.findOne({ email });

        if (user) {
            const token = crypto.randomBytes(32).toString('hex');
            // Only the hash is stored: a leaked database dump then can't be used to reset accounts
            user.resetToken = crypto.createHash('sha256').update(token).digest('hex');
            user.resetTokenExpiry = Date.now() + 3600000;
            await user.save();
            await sendMail({
                to: user.email,
                subject: '🔐 PASSWORD RECOVERY',
                text: `AGENT ${user.username},\n\nYOUR RESET TOKEN:\n${token}\n\nValid for 60 minutes.\n- CODEX HQ`
            });
        }

        // Always the same answer, whether or not the address exists — a 404 here would let
        // anyone test which emails have accounts.
        res.json({ success: true });
    } catch (e) {
        console.error("Password recovery failed:", e);
        res.json({ success: true });
    }
});

router.post('/api/reset-password', authLimiter, async (req, res) => {
    const token = asString(req.body.token).trim();
    const newPass = asString(req.body.newPass);
    try {
        if (!token) return res.status(400).json({ error: "Invalid Token" });
        if (newPass.length < 8 || newPass.length > 200) {
            return res.status(400).json({ error: "Password must be at least 8 characters" });
        }
        // Compare against the stored hash, not the raw token
        const hashed = crypto.createHash('sha256').update(token).digest('hex');
        const user = await User.findOne({ resetToken: hashed, resetTokenExpiry: { $gt: Date.now() } });
        if (!user) return res.status(400).json({ error: "Invalid Token" });
        user.password = await withBcrypt(() => bcrypt.hash(newPass, 12));
        user.resetToken = undefined;
        user.resetTokenExpiry = undefined;
        // Invalidates every token issued before this moment — if the reset was prompted by a
        // compromised account, whoever had the old session is logged out right now, not just
        // whenever their 30-day token happens to expire.
        user.tokenVersion = (user.tokenVersion || 0) + 1;
        await user.save();
        res.json({ success: true });
    } catch (e) {
        if (e instanceof BcryptBusyError) return res.status(503).json(BUSY_ERROR);
        console.error("Reset password failed:", e); res.status(500).json({ error: "Error" });
    }
});

module.exports = router;
