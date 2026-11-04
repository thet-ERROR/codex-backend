const rateLimit = require('express-rate-limit');
// --- 🛡️ SECURITY LAYER 3: RATE LIMITING ---
// The three public reads every page load makes (status, PCs, vote event) have their own, looser
// bucket. They used to share the 100-per-15-minutes one with everything else, and one IP is often
// many people — a household, an office, and above all a mobile network, where carriers put whole
// neighbourhoods behind one address. A few dozen visitors browsing there would lock each other out
// of the site, login included. Those reads are served from memory now (see the read caches), so a
// generous limit costs little; it still stops a script hammering them.
const PUBLIC_READS = new Set(['/status', '/drops', '/vote-event']);
const isPublicRead = (req) => req.method === 'GET' && PUBLIC_READS.has(req.path);
const publicReadLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 600,
    standardHeaders: 'draft-8', legacyHeaders: false,
    skip: (req) => !isPublicRead(req),
    message: { error: "⚠️ SYSTEM ALERT: Too many requests. Initiating cooldown sequence." }
});
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: 'draft-8', legacyHeaders: false,
    skip: isPublicRead,
    message: { error: "⚠️ SYSTEM ALERT: Too many requests. Initiating cooldown sequence." }
});
const authLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 50,
    message: { error: "⛔ ACCESS DENIED: Max authentication attempts reached." }
});

// Tighter, IP-based, specifically for the two password-guessing endpoints (user + admin login).
// 50/hour was shared with register/forgot/reset too — generous enough for password guessing,
// and meant one IP hammering login could also lock a genuine user out of forgot-password.
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: "⛔ ACCESS DENIED: Too many login attempts. Try again in 15 minutes." }
});

// Placing an order holds stock, so a script placing fake orders could empty the shop. A real customer
// places one or two; twenty an hour from one address is far past anything genuine.
const orderLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 20,
    message: { error: "⛔ Too many orders from this connection. Try again later." }
});

// A return or problem report emails the shop, so a script could flood the inbox. Its own allowance:
// it must not eat into the one for placing orders, nor the other way round.
const requestLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 30,
    message: { error: "⛔ Too many requests from this connection. Try again later." }
});

module.exports = { publicReadLimiter, apiLimiter, authLimiter, loginLimiter, orderLimiter, requestLimiter };
