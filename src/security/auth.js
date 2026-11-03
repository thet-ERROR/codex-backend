// Who is calling: admin and user sessions (JWTs), and the gates routes put in front of themselves.
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../config');
const User = require('../models/user');
const { getAdminSecurity } = require('../models/admin-security');

// Deliberately no fallback secret: a hardcoded default would let anyone mint valid tokens.
// Auth routes fail closed with a clear 503 instead, so the public catalogue keeps working.
const requireAuthConfig = (req, res, next) => {
    if (!JWT_SECRET) return res.status(503).json({ error: "SERVER MISCONFIGURED: authentication unavailable" });
    next();
};

const bearerToken = (req) => {
    const header = req.headers['authorization'] || '';
    return header.startsWith('Bearer ') ? header.slice(7) : null;
};

// Admin routes used to accept the raw password in a header on every single request, compared
// with ===. That meant the shared secret travelled constantly, never expired, and the compare
// leaked timing. Now the password is exchanged once at /api/login for a short-lived scoped JWT.
// The token also carries the admin's securityVersion (models/admin-security.js): turning two-factor
// sign-in on or off bumps it, which ends every admin session started before. Tokens from before this
// existed carry none and count as version 0.
const auth = async (req, res, next) => {
    if (!JWT_SECRET) return res.status(503).json({ error: "SERVER MISCONFIGURED: authentication unavailable" });
    const token = bearerToken(req);
    if (!token) return res.status(401).json({ error: "⛔ ACCESS DENIED: ADMIN TOKEN REQUIRED" });
    let decoded;
    try {
        decoded = jwt.verify(token, JWT_SECRET);
    } catch (e) {
        return res.status(401).json({ error: "⛔ ACCESS DENIED: ADMIN SESSION EXPIRED" });
    }
    if (decoded.role !== 'admin') return res.status(403).json({ error: "⛔ ACCESS DENIED: NOT AN ADMIN TOKEN" });
    const { securityVersion = 0 } = await getAdminSecurity();
    if ((decoded.sv || 0) !== securityVersion) return res.status(401).json({ error: "⛔ ACCESS DENIED: ADMIN SESSION ENDED, SIGN IN AGAIN" });
    next();
};

const authUser = async (req, res, next) => {
    if (!JWT_SECRET) return res.status(503).json({ error: "SERVER MISCONFIGURED: authentication unavailable" });
    const token = bearerToken(req);
    if (!token) return res.status(401).json({ error: "ACCESS DENIED: NO TOKEN PROVIDED" });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        // A valid signature only proves the token was once legitimately issued — tokenVersion is
        // what lets a password reset actually kill an older token instead of leaving it valid for
        // the rest of its 30-day life. Costs one extra lookup per request; worth it for a revoke
        // path that otherwise doesn't exist at all with pure stateless JWTs.
        const user = await User.findById(decoded.id).select('tokenVersion emailVerified');
        if (!user || user.tokenVersion !== decoded.tokenVersion) {
            return res.status(401).json({ error: "ACCESS DENIED: SESSION REVOKED, PLEASE LOG IN AGAIN" });
        }
        req.userId = decoded.id;
        req.emailVerified = user.emailVerified;
        next();
    } catch (e) {
        res.status(401).json({ error: "ACCESS DENIED: INVALID OR EXPIRED TOKEN" });
    }
};

// For routes that stay open to guests but do more when a session happens to be present (posting a
// review credits the account it came from, if any). Never a substitute for authUser: it returns
// null on anything missing or invalid instead of refusing the request.
const optionalUserId = (req) => {
    if (!JWT_SECRET) return null;
    const token = bearerToken(req);
    if (!token) return null;
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        return decoded.role === 'admin' ? null : (decoded.id || null);
    } catch (e) {
        return null;
    }
};

// Chain after authUser on any route that must be hard-gated behind a verified email (dossier,
// wishlist, achievements, voting). `code` lets the frontend distinguish this from a plain auth
// failure and show "check your email" instead of "please log in".
const requireVerified = (req, res, next) => {
    if (!req.emailVerified) {
        return res.status(403).json({ error: "EMAIL NOT VERIFIED", code: "EMAIL_NOT_VERIFIED" });
    }
    next();
};

// --- 🛡️ SECURITY LAYER 5: MAINTENANCE KILL SWITCH ---
// Lets the admin keep working on the site while it's in maintenance for everyone else
const isAdminRequest = (req) => {
    if (!JWT_SECRET) return false;
    const token = bearerToken(req);
    if (!token) return false;
    try {
        return jwt.verify(token, JWT_SECRET).role === 'admin';
    } catch (e) {
        return false;
    }
};

// The signed-in account behind a request, or null for a guest. Unlike optionalUserId it applies the
// same checks as authUser (tokenVersion, so a session ended by a password reset is a guest here too)
// and returns the full document — checkout spends the account's coupons and reads its email status.
async function optionalSessionUser(req) {
    if (!JWT_SECRET) return null;
    const token = bearerToken(req);
    if (!token) return null;
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role === 'admin' || !decoded.id) return null;
        const user = await User.findById(decoded.id);
        return user && user.tokenVersion === decoded.tokenVersion ? user : null;
    } catch (e) {
        return null;
    }
}

module.exports = { requireAuthConfig, bearerToken, auth, authUser, optionalUserId, optionalSessionUser, requireVerified, isAdminRequest };
