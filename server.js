require('dotenv').config(); 
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit'); 

const app = express();
const PORT = process.env.PORT || 5000;

// Render sits in front of this app behind its own reverse proxy — trust the first hop so
// express-rate-limit (and req.ip generally) reads the real client IP from X-Forwarded-For
// instead of Render's proxy IP.
app.set('trust proxy', 1);

// --- 🛡️ SECURITY LAYER 1: HTTP HEADERS ---
app.use(helmet());
app.use(helmet.crossOriginResourcePolicy({ policy: "cross-origin" })); 

// --- 🛡️ SECURITY LAYER 2: CORS ---
// FRONTEND_URL may hold several comma-separated origins (prod domain + Vercel preview).
// No '*' fallback: an unset env var must fail closed, not silently open the API to every site.
// A browser Origin is always scheme + host + port with no path and no trailing slash. Pasting
// "https://site.app/" or a capitalised host into the env var is the easy mistake, so both sides
// are normalised before comparing rather than failing on a stray character.
const normaliseOrigin = (value) => String(value || '').trim().replace(/\/+$/, '').toLowerCase();

const ALLOWED_ORIGINS = (process.env.FRONTEND_URL || '')
    .split(',').map(normaliseOrigin).filter(Boolean);

if (!ALLOWED_ORIGINS.length) {
    console.error("⚠️ FRONTEND_URL is not set — every browser request will be refused by CORS. Set it to your site's origin, e.g. https://codex-iota-nine.vercel.app");
} else {
    console.log(`🌐 CORS allowing: ${ALLOWED_ORIGINS.join(', ')}`);
}

const isOriginAllowed = (origin) => ALLOWED_ORIGINS.includes(normaliseOrigin(origin));

const corsOptions = {
    origin(origin, callback) {
        // No Origin header = same-origin, curl, or a mobile app — nothing for CORS to protect
        if (!origin) return callback(null, true);
        if (isOriginAllowed(origin)) return callback(null, true);

        // Refuse by omitting the CORS headers rather than throwing: a thrown error here becomes
        // an opaque 500 on every request, which looks like the API is down instead of like a
        // misconfigured allowlist. Logged so the exact value to add is visible in the logs.
        console.error(`⛔ CORS refused origin "${origin}". FRONTEND_URL currently allows: ${ALLOWED_ORIGINS.join(', ') || '(nothing — env var not set)'}`);
        callback(null, false);
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    // 'Authorization' carries the user/admin JWT. Leaving it out made the browser block every
    // authenticated request at the preflight stage.
    allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));
// Cap the body size so a single request can't tie up memory
app.use(express.json({ limit: '100kb' }));

// --- 🛡️ SECURITY LAYER 3: RATE LIMITING ---
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100, 
    message: { error: "⚠️ SYSTEM ALERT: Too many requests. Initiating cooldown sequence." }
});
app.use('/api/', apiLimiter);

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

// Per-ACCOUNT lockout, independent of the IP-based limiters above. Those stop one IP from
// hammering the API; this stops credential stuffing against one specific account from many
// rotating IPs, which the IP limiter alone can't see. In-memory, so it resets on a redeploy or
// when the free-tier dyno sleeps — an acceptable trade for this site's scale. A periodic sweep
// keeps the map from growing unbounded if someone tries thousands of fake usernames.
const failedLogins = new Map(); // key (e.g. "user:bob" or "admin") -> { count, windowStart, lockedUntil }
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_LOCKOUT_MS = 15 * 60 * 1000;

function accountLockMinutesLeft(key) {
    const entry = failedLogins.get(key);
    if (!entry || !entry.lockedUntil || Date.now() >= entry.lockedUntil) return 0;
    return Math.ceil((entry.lockedUntil - Date.now()) / 60000);
}
function recordFailedLogin(key) {
    const now = Date.now();
    const entry = failedLogins.get(key);
    const fresh = !entry || (now - entry.windowStart) > LOGIN_LOCKOUT_MS;
    const next = fresh ? { count: 1, windowStart: now, lockedUntil: 0 } : { ...entry, count: entry.count + 1 };
    if (next.count >= LOGIN_MAX_ATTEMPTS) next.lockedUntil = now + LOGIN_LOCKOUT_MS;
    failedLogins.set(key, next);
}
function clearFailedLogins(key) { failedLogins.delete(key); }

setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of failedLogins) {
        if (now >= entry.lockedUntil && (now - entry.windowStart) > LOGIN_LOCKOUT_MS) failedLogins.delete(key);
    }
}, 10 * 60 * 1000).unref();

// --- 🛡️ SECURITY LAYER 4: PREVENT API CACHING (GHOST CACHE FIX) ---
app.use('/api', (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');
    next();
});

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const JWT_SECRET = process.env.JWT_SECRET;
const dbURI = process.env.DB_URI;

if (!JWT_SECRET) {
    console.error("🚨 JWT_SECRET is not set. Every authenticated route (login, register, admin, vote) will refuse to work until it is. Generate one with: node -e \"console.log(require('crypto').randomBytes(48).toString('hex'))\"");
}
if (!ADMIN_PASSWORD) {
    console.error("🚨 ADMIN_PASSWORD is not set. The admin panel cannot be used until it is.");
}

// Deliberately no fallback secret: a hardcoded default would let anyone mint valid tokens.
// Auth routes fail closed with a clear 503 instead, so the public catalogue keeps working.
const requireAuthConfig = (req, res, next) => {
    if (!JWT_SECRET) return res.status(503).json({ error: "SERVER MISCONFIGURED: authentication unavailable" });
    next();
};

// Rejects strings that aren't strings — a JSON body can smuggle {"$ne": null} into a query and
// turn findOne() into "match any user". Everything that reaches a query goes through here.
const asString = v => (typeof v === 'string' ? v : '');

console.log("⏳ Connecting to MongoDB...");
mongoose.connect(dbURI, { serverSelectionTimeoutMS: 30000, socketTimeoutMS: 45000 })
.then(() => console.log("✅ SERVER ONLINE: DATABASE CONNECTED (SECURE MODE)"))
.catch((err) => console.error("❌ DB CONNECTION ERROR:", err.message));

// --- SCHEMAS ---
const pcSchema = new mongoose.Schema({
    name: String, price: String, description: String, lore: String, loreEl: String, stock: { type: Number, default: 1 },
    images: [String], status: { type: String, default: 'available' }, category: { type: String, default: 'drop' },    
    multitasking: { type: Number, default: 0 },
    specs: { cpu: String, gpu: String, ram: String, ssd: String, mobo: String, psu: String, case: String },
    specDetails: { type: Map, of: String, default: {} },
    fps: [{ game: String, score: Number }],
    reviews: [{ user: String, text: String, rating: Number, date: { type: Date, default: Date.now } }],
    votes: { type: Number, default: 0 },
    // Per-build purchasable extras. Every sub-field has a default so PCs created before this
    // existed still render (the frontend also guards with optional chaining).
    options: {
        storage: {
            enabled: { type: Boolean, default: true },
            hdd: { type: Number, default: 50 },   // 0 hides that line from the dropdown
            ssd: { type: Number, default: 80 }
        },
        // Pro Config price is global (SiteConfig.proConfigPrice) — the service is identical on
        // every build, so only availability is per-PC.
        proConfig: { enabled: { type: Boolean, default: false } },
        paint: {
            enabled: { type: Boolean, default: false },
            colorName: { type: String, default: '' },
            colorNameEl: { type: String, default: '' },
            colorHex: { type: String, default: '#1a1a1a' },
            price: { type: Number, default: 40 },
            leadTimeHours: { type: Number, default: 48 },
            images: { type: [String], default: [] }
        }
    }
});
const PC = mongoose.model('PC', pcSchema);

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    joined: { type: Date, default: Date.now },
    subscribed: { type: Boolean, default: false },
    resetToken: String,
    resetTokenExpiry: Date,
    wishlist: [{ type: mongoose.Schema.Types.ObjectId, ref: 'PC' }],
    achievements: { type: [String], default: [] },
    // Baked into every issued JWT and checked on every authenticated request (see authUser).
    // Bumping this instantly invalidates every token already out there for this account — the
    // only way to kill a stolen session, since the API has no other server-side session store.
    // Bumped automatically on password reset.
    tokenVersion: { type: Number, default: 0 },
    // Hard gate: nothing account-specific (dossier, wishlist, achievements, voting) works until
    // this is true. Protects the one-vote-per-account guarantee from being trivially defeated by
    // mass-registering with throwaway addresses — without this, "one vote per account" only ever
    // meant "one vote per email you were willing to type," which costs nothing to fake.
    emailVerified: { type: Boolean, default: false },
    emailVerifyTokenHash: String,
    emailVerifyExpiry: Date
});
const User = mongoose.model('User', userSchema);

const voteEventSchema = new mongoose.Schema({
    title: String,
    image: String,
    targetVotes: Number,
    currentVotes: { type: Number, default: 0 },
    // One vote per account: the ledger of who already voted. Never sent to the browser — the
    // public endpoint replaces it with a plain hasVoted boolean for the requesting agent.
    votedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    startDate: Date,
    durationDays: Number,
    price: String,
    specs: { cpu: String, gpu: String, ram: String, ssd: String, mobo: String, psu: String, case: String },
    // Mirrors the PC fields so the vote drop can open in the same inspect card as every other
    // build (flip to specs, show FPS, lore on the front).
    description: String,
    lore: String,
    loreEl: String,
    multitasking: { type: Number, default: 0 },
    fps: [{ game: String, score: Number }]
});
const VoteEvent = mongoose.model('VoteEvent', voteEventSchema);

const reviewTicketSchema = new mongoose.Schema({ 
    code: String, pcId: String, pcName: String, 
    status: { type: String, default: 'pending' }, 
    generatedAt: { type: Date, default: Date.now }, 
    firstScan: { type: Date, default: null } 
});
const ReviewTicket = mongoose.model('ReviewTicket', reviewTicketSchema);

const newsletterSchema = new mongoose.Schema({ email: String, date: { type: Date, default: Date.now } });
const Newsletter = mongoose.model('Newsletter', newsletterSchema);

const siteConfigSchema = new mongoose.Schema({
    maintenanceMode: { type: Boolean, default: false },
    maintenanceMessage: { type: String, default: "PHOENIX CODEX is currently undergoing scheduled maintenance. We'll be back online shortly." },
    // Pro Config is the same service on every build, so its price lives here rather than per-PC.
    // Exposed publicly through /api/status (the frontend needs it to price the option).
    proConfigPrice: { type: Number, default: 30 }
});
const SiteConfig = mongoose.model('SiteConfig', siteConfigSchema);

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

const bearerToken = (req) => {
    const header = req.headers['authorization'] || '';
    return header.startsWith('Bearer ') ? header.slice(7) : null;
};

// Admin routes used to accept the raw password in a header on every single request, compared
// with ===. That meant the shared secret travelled constantly, never expired, and the compare
// leaked timing. Now the password is exchanged once at /api/login for a short-lived scoped JWT.
const auth = (req, res, next) => {
    if (!JWT_SECRET) return res.status(503).json({ error: "SERVER MISCONFIGURED: authentication unavailable" });
    const token = bearerToken(req);
    if (!token) return res.status(401).json({ error: "⛔ ACCESS DENIED: ADMIN TOKEN REQUIRED" });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role !== 'admin') return res.status(403).json({ error: "⛔ ACCESS DENIED: NOT AN ADMIN TOKEN" });
        next();
    } catch (e) {
        res.status(401).json({ error: "⛔ ACCESS DENIED: ADMIN SESSION EXPIRED" });
    }
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

// Chain after authUser on any route that must be hard-gated behind a verified email (dossier,
// wishlist, achievements, voting). `code` lets the frontend distinguish this from a plain auth
// failure and show "check your email" instead of "please log in".
const requireVerified = (req, res, next) => {
    if (!req.emailVerified) {
        return res.status(403).json({ error: "EMAIL NOT VERIFIED", code: "EMAIL_NOT_VERIFIED" });
    }
    next();
};

// Shared by /api/register and /api/resend-verification. Stores only the hash (same reasoning as
// the password-reset token) and returns the raw value, which is what actually goes in the email.
function issueEmailVerification(user) {
    const rawToken = crypto.randomBytes(32).toString('hex');
    user.emailVerifyTokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    user.emailVerifyExpiry = Date.now() + 24 * 60 * 60 * 1000; // 24h
    return rawToken;
}

async function sendVerificationEmail(user, rawToken) {
    // Points at the frontend, not the API — verification is done by that page's own POST call
    // once it loads (js/main.js), never by whatever GETs the link itself (a mail client's link
    // scanner never runs the page's JavaScript). Falls back to the API URL only if no frontend
    // origin is configured, so verification is never completely undeliverable.
    const base = ALLOWED_ORIGINS[0] || `https://codex-backend-9kij.onrender.com`;
    const link = `${base}/?verify=${rawToken}`;
    await transporter.sendMail({
        from: 'CODEX SYSTEMS',
        to: user.email,
        subject: '✅ CONFIRM YOUR AGENT IDENTITY',
        text: `AGENT ${user.username},\n\nConfirm your email to unlock your dossier, wishlist and voting rights:\n${link}\n\nThis link is valid for 24 hours.\n- CODEX HQ`
    });
}

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

app.use('/api', async (req, res, next) => {
    if (req.path === '/status' || req.path === '/login' || isAdminRequest(req)) return next();
    try {
        const config = await SiteConfig.findOne();
        if (config?.maintenanceMode) {
            return res.status(503).json({ maintenance: true, message: config.maintenanceMessage });
        }
    } catch (e) {
        console.error("Maintenance check failed, failing open:", e);
    }
    next();
});

// --- ROUTES ---
app.get('/api/status', async (req, res) => {
    const config = await SiteConfig.findOne();
    res.json({
        maintenance: !!config?.maintenanceMode,
        message: config?.maintenanceMessage || null,
        // Public on purpose: the storefront prices the Pro Config extra from this.
        proConfigPrice: config?.proConfigPrice ?? 30,
        // Diagnostics. Says whether the allowlist is configured at all and whether THIS caller's
        // origin is on it — the caller already knows its own origin, so nothing leaks, and a
        // silent CORS refusal becomes a one-request check instead of a log hunt.
        cors: {
            configured: ALLOWED_ORIGINS.length > 0,
            originAllowed: req.headers.origin ? isOriginAllowed(req.headers.origin) : null
        }
    });
});

app.get('/api/site-config', auth, async (req, res) => {
    try {
        let config = await SiteConfig.findOne();
        if (!config) config = await new SiteConfig().save();
        res.json(config);
    } catch (e) { console.error("Get site-config failed:", e); res.status(500).json({ error: "Server Error" }); }
});

app.post('/api/site-config', auth, async (req, res) => {
    try {
        const { maintenanceMode, maintenanceMessage, proConfigPrice } = req.body;
        let config = await SiteConfig.findOne();
        if (!config) config = new SiteConfig();
        if (typeof maintenanceMode === 'boolean') config.maintenanceMode = maintenanceMode;
        if (typeof maintenanceMessage === 'string') config.maintenanceMessage = maintenanceMessage;
        if (proConfigPrice !== undefined && !Number.isNaN(Number(proConfigPrice))) {
            config.proConfigPrice = Math.max(0, Number(proConfigPrice));
        }
        await config.save();
        res.json({ success: true, config });
    } catch (e) { console.error("Save site-config failed:", e); res.status(500).json({ error: "Server Error" }); }
});

app.post('/api/register', authLimiter, requireAuthConfig, async (req, res) => {
    try {
        const username = asString(req.body.username).trim();
        const email = asString(req.body.email).trim().toLowerCase();
        const password = asString(req.body.password);
        const subscribed = req.body.subscribed === true;

        if (username.length < 3 || username.length > 24 || !/^[a-zA-Z0-9_.-]+$/.test(username)) {
            return res.status(400).json({ error: "Username must be 3-24 characters (letters, numbers, . _ - only)" });
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
            return res.status(400).json({ error: "Please enter a valid email address" });
        }
        if (password.length < 8 || password.length > 200) {
            return res.status(400).json({ error: "Password must be at least 8 characters" });
        }

        if (await User.findOne({ email })) return res.status(400).json({ error: "Email exists" });
        // Checked explicitly — the unique index alone would surface as an unhelpful 500
        if (await User.findOne({ username })) return res.status(400).json({ error: "Username already taken" });

        const salt = await bcrypt.genSalt(12);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newUser = new User({ username, email, password: hashedPassword, subscribed });
        const rawVerifyToken = issueEmailVerification(newUser);
        await newUser.save();
        if (subscribed) {
            try { await new Newsletter({ email }).save(); } catch (e) { console.error("Newsletter subscribe failed:", e); }
        }
        try {
            await sendVerificationEmail(newUser, rawVerifyToken);
        } catch (e) {
            // The account still exists and can request a fresh link via /api/resend-verification,
            // so a flaky mail send here shouldn't fail the whole registration.
            console.error("Verification email send failed:", e);
        }
        const token = jwt.sign({ id: newUser._id, username: newUser.username, tokenVersion: newUser.tokenVersion }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ success: true, username: newUser.username, token, emailVerified: false });
    } catch (e) { console.error("Register failed:", e); res.status(500).json({ error: "Error" }); }
});

// Public — proving you control the emailed token IS the auth. Called by the frontend's own POST
// after the verification link's page loads (see js/main.js), never by a bare GET, so a mail
// client's automatic link-preview scan can't verify an account no one asked it to.
app.post('/api/verify-email', authLimiter, async (req, res) => {
    try {
        const token = asString(req.body.token).trim();
        if (!token) return res.status(400).json({ success: false, error: "Missing token" });
        const hashed = crypto.createHash('sha256').update(token).digest('hex');
        const user = await User.findOne({ emailVerifyTokenHash: hashed, emailVerifyExpiry: { $gt: Date.now() } });
        if (!user) return res.status(400).json({ success: false, error: "Invalid or expired verification link" });
        user.emailVerified = true;
        user.emailVerifyTokenHash = undefined;
        user.emailVerifyExpiry = undefined;
        await user.save();
        res.json({ success: true });
    } catch (e) { console.error("Verify email failed:", e); res.status(500).json({ success: false, error: "Server Error" }); }
});

// Requires a valid session but deliberately NOT requireVerified — this is the one way out of the
// unverified state, so gating it behind the same gate would be a dead end for anyone whose first
// email never arrived.
app.post('/api/resend-verification', authLimiter, authUser, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: "User not found" });
        if (user.emailVerified) return res.json({ success: true, alreadyVerified: true });
        const rawVerifyToken = issueEmailVerification(user);
        await user.save();
        await sendVerificationEmail(user, rawVerifyToken);
        res.json({ success: true });
    } catch (e) { console.error("Resend verification failed:", e); res.status(500).json({ error: "Server Error" }); }
});

app.post('/api/user-login', loginLimiter, requireAuthConfig, async (req, res) => {
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
        const isMatch = await bcrypt.compare(password, user.password);
        if (isMatch) {
            clearFailedLogins(lockKey);
            const token = jwt.sign({ id: user._id, username: user.username, tokenVersion: user.tokenVersion }, JWT_SECRET, { expiresIn: '30d' });
            res.json({ success: true, username: user.username, token, emailVerified: user.emailVerified });
        }
        else { recordFailedLogin(lockKey); res.status(400).json({ error: "Invalid Credentials" }); }
    } catch (e) { console.error("Login failed:", e); res.status(500).json({ error: "Server Error" }); }
});

app.get('/api/me', authUser, requireVerified, async (req, res) => {
    try {
        const user = await User.findById(req.userId).populate('wishlist');
        if (!user) return res.status(404).json({ error: "User not found" });
        res.json({ username: user.username, wishlist: user.wishlist, achievements: user.achievements });
    } catch (e) { console.error("/api/me failed:", e); res.status(500).json({ error: "Server Error" }); }
});

app.post('/api/wishlist/:pcId', authUser, requireVerified, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: "User not found" });
        if (!user.wishlist.some(id => id.toString() === req.params.pcId)) {
            user.wishlist.push(req.params.pcId);
            await user.save();
        }
        await user.populate('wishlist');
        res.json({ success: true, wishlist: user.wishlist });
    } catch (e) { console.error("Wishlist add failed:", e); res.status(500).json({ error: "Server Error" }); }
});

app.delete('/api/wishlist/:pcId', authUser, requireVerified, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: "User not found" });
        user.wishlist = user.wishlist.filter(id => id.toString() !== req.params.pcId);
        await user.save();
        await user.populate('wishlist');
        res.json({ success: true, wishlist: user.wishlist });
    } catch (e) { console.error("Wishlist remove failed:", e); res.status(500).json({ error: "Server Error" }); }
});

app.post('/api/achievements', authUser, requireVerified, async (req, res) => {
    try {
        const { id } = req.body;
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: "User not found" });
        if (id && !user.achievements.includes(id)) {
            user.achievements.push(id);
            await user.save();
        }
        res.json({ success: true, achievements: user.achievements });
    } catch (e) { res.status(500).json({ error: "Server Error" }); }
});

app.post('/api/forgot-password', authLimiter, async (req, res) => {
    const email = asString(req.body.email).trim().toLowerCase();
    try {
        const user = await User.findOne({ email });

        if (user) {
            const token = crypto.randomBytes(32).toString('hex');
            // Only the hash is stored: a leaked database dump then can't be used to reset accounts
            user.resetToken = crypto.createHash('sha256').update(token).digest('hex');
            user.resetTokenExpiry = Date.now() + 3600000;
            await user.save();
            await transporter.sendMail({
                from: 'CODEX SYSTEMS',
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

app.post('/api/reset-password', authLimiter, async (req, res) => {
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
        const salt = await bcrypt.genSalt(12);
        user.password = await bcrypt.hash(newPass, salt);
        user.resetToken = undefined;
        user.resetTokenExpiry = undefined;
        // Invalidates every token issued before this moment — if the reset was prompted by a
        // compromised account, whoever had the old session is logged out right now, not just
        // whenever their 30-day token happens to expire.
        user.tokenVersion = (user.tokenVersion || 0) + 1;
        await user.save();
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: "Error" }); }
});

app.get('/api/users/count', auth, async (req, res) => { const count = await User.countDocuments(); res.json({ count }); });

// Admin user management — added so test/duplicate accounts (which block re-registering an email,
// by design — see /api/register's uniqueness check) can be cleared from the panel instead of
// needing direct database access every time. Password hash and tokens are never selected.
app.get('/api/users', auth, async (req, res) => {
    try {
        const users = await User.find()
            .select('username email joined subscribed emailVerified wishlist achievements')
            .sort({ joined: -1 })
            .limit(500); // demo-scale cap — swap for real pagination if the user base grows
        res.json(users);
    } catch (e) { console.error("List users failed:", e); res.status(500).json({ error: "Server Error" }); }
});

app.delete('/api/users/:id', auth, async (req, res) => {
    try {
        const deleted = await User.findByIdAndDelete(req.params.id);
        if (!deleted) return res.status(404).json({ error: "User not found" });
        res.json({ success: true });
    } catch (e) { console.error("Delete user failed:", e); res.status(400).json({ error: "Invalid user id" }); }
});
app.post('/api/login', loginLimiter, requireAuthConfig, (req, res) => {
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

app.get('/api/drops', async (req, res) => {
    try { res.json(await PC.find()); }
    catch (e) { console.error("Fetch drops failed:", e); res.status(500).json({ error: "Server Error" }); }
});
app.post('/api/drops', auth, async (req, res) => {
    try { const n = new PC(req.body); await n.save(); res.json(n); }
    catch (e) { console.error("Create drop failed:", e); res.status(400).json({ error: "Invalid system data" }); }
});
app.put('/api/drops/:id', auth, async (req, res) => {
    try {
        // findByIdAndUpdate throws a CastError on a malformed :id (not a valid ObjectId) — was
        // uncaught here, which without this try/catch depends on the global error handler below
        // (and, before that existed, could surface a raw stack trace instead of a clean 400).
        const u = await PC.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true });
        if (!u) return res.status(404).json({ error: "PC not found" });
        res.json(u);
    } catch (e) { console.error("Update drop failed:", e); res.status(400).json({ error: "Invalid system data or id" }); }
});
app.delete('/api/drops/:id', auth, async (req, res) => {
    try {
        const deleted = await PC.findByIdAndDelete(req.params.id);
        if (!deleted) return res.status(404).json({ error: "PC not found" });
        res.json({ msg: "Deleted" });
    } catch (e) { console.error("Delete drop failed:", e); res.status(400).json({ error: "Invalid id" }); }
});

app.get('/api/vote-event', async (req, res) => {
    try {
        const event = await VoteEvent.findOne();
        if (event && event.startDate) {
            const end = new Date(new Date(event.startDate).getTime() + (event.durationDays || 0) * 24 * 60 * 60 * 1000);
            const expired = new Date() > end;
            const secured = event.currentVotes >= event.targetVotes;
            // Un-secured community drops auto-convert to a normal Live Drop once their timer runs out
            // (checked lazily here, on read, rather than a background timer — this dyno sleeps on
            // idle on Render's free tier, so a setInterval wouldn't reliably fire anyway).
            if (expired && !secured) {
                await new PC({
                    name: event.title,
                    price: event.price || '',
                    images: event.image ? [event.image] : [],
                    status: 'available',
                    category: 'drop',
                    stock: 1,
                    specs: event.specs || {}
                }).save();
                await VoteEvent.deleteMany({});
                return res.json({});
            }
        }
        if (!event) return res.json({});

        // Optional auth: this route stays public (guests must still see the drop), but when a
        // valid token is present we tell that agent whether they've already used their vote.
        let hasVoted = false;
        const header = req.headers['authorization'] || '';
        const token = header.startsWith('Bearer ') ? header.slice(7) : null;
        if (token && JWT_SECRET) {
            try {
                const decoded = jwt.verify(token, JWT_SECRET);
                hasVoted = (event.votedBy || []).some(id => id.toString() === decoded.id);
            } catch (e) { /* expired/invalid token: treat as a guest */ }
        }

        const payload = event.toObject();
        delete payload.votedBy; // never leak the voter list
        res.json({ ...payload, hasVoted });
    } catch (e) {
        console.error("Vote event fetch/expiry check failed:", e);
        res.json({});
    }
});
app.post('/api/vote-event', auth, async (req, res) => {
    try {
        await VoteEvent.deleteMany({});
        const n = new VoteEvent(req.body);
        await n.save();
        res.json(n);
    } catch (e) { console.error("Create vote-event failed:", e); res.status(400).json({ error: "Invalid vote event data" }); }
});
app.post('/api/cast-vote', authUser, requireVerified, async (req, res) => {
    try {
        const event = await VoteEvent.findOne();
        if (!event) return res.status(404).json({ error: "No active vote" });

        // One vote per account — this is what makes the counter mean anything
        if ((event.votedBy || []).some(id => id.toString() === req.userId)) {
            return res.status(409).json({ error: "ALREADY VOTED", votes: event.currentVotes, hasVoted: true });
        }

        // The client disables the button outside the window, but the API has to enforce it too
        if (event.startDate) {
            const now = new Date();
            const start = new Date(event.startDate);
            const end = new Date(start.getTime() + (event.durationDays || 0) * 24 * 60 * 60 * 1000);
            if (now < start) return res.status(403).json({ error: "VOTING HAS NOT OPENED YET" });
            if (now > end) return res.status(403).json({ error: "VOTING HAS CLOSED" });
        }

        event.votedBy.push(req.userId);
        event.currentVotes += 1;
        await event.save();
        res.json({ votes: event.currentVotes, hasVoted: true });
    } catch (e) {
        console.error("Cast vote failed:", e);
        res.status(500).json({ error: "Server Error" });
    }
});

app.post('/api/generate-code', auth, async (req, res) => {
    try {
        const { pcId, pcName } = req.body;
        // 5 bytes = 10 hex chars ≈ 1.1 trillion combinations (was 3 bytes / 6 chars ≈ 16.7
        // million) — the smaller space was small enough that a distributed brute-force against
        // /api/check-code could plausibly land on a real pending code within its lifetime.
        const code = 'CDX-' + crypto.randomBytes(5).toString('hex').toUpperCase();
        const ticket = new ReviewTicket({ code, pcId, pcName });
        await ticket.save();
        res.json(ticket);
    } catch (e) { console.error("Generate code failed:", e); res.status(500).json({ error: "Server Error" }); }
});
app.get('/api/tickets', auth, async (req, res) => { const tickets = await ReviewTicket.find().sort({ generatedAt: -1 }); res.json(tickets); });

app.post('/api/activate-ticket/:id', auth, async (req, res) => {
    try {
        const ticket = await ReviewTicket.findById(req.params.id);
        if(ticket) { ticket.status = 'active'; await ticket.save(); res.json({ success: true }); } 
        else { res.status(404).json({ error: "Ticket not found" }); }
    } catch(e) { res.status(500).json({ error: "Server error" }); }
});

// Read-only on purpose. This used to start the 48h validation window as a side effect of a GET
// — meaning any automated client that fetches URLs (a chat app's link-preview bot, an uptime
// monitor, a crawler, a browser prefetch) could silently burn a customer's window before they
// ever typed the code in. GET now only ever reports status; POST /activate (below) is the only
// thing that starts the clock, and only fires from an explicit user action in the frontend.
app.get('/api/check-code/:code', authLimiter, async (req, res) => {
    try {
        const ticket = await ReviewTicket.findOne({ code: req.params.code });
        if (!ticket) return res.json({ valid: false, msg: "❌ INVALID CODE" });
        if (ticket.status === 'used') return res.json({ valid: false, msg: "⚠️ ALREADY REDEEMED" });
        if (!ticket.firstScan) return res.json({ valid: true, activated: false, pcName: ticket.pcName });
        const now = new Date(); const expiry = new Date(ticket.firstScan); expiry.setHours(expiry.getHours() + 48);
        if (now > expiry) { return res.json({ valid: true, activated: true, expired: true, pcName: ticket.pcName }); }
        res.json({ valid: true, activated: true, expired: false, pcName: ticket.pcName, timeLeft: expiry - now });
    } catch(e) { console.error(e); res.status(500).json({ valid: false, msg: "SERVER ERROR" }); }
});

// The only route that starts the 48h window. Idempotent: calling it again after activation just
// returns the already-running timer instead of resetting it, so a retried request can't extend it.
app.post('/api/check-code/:code/activate', authLimiter, async (req, res) => {
    try {
        const ticket = await ReviewTicket.findOne({ code: req.params.code });
        if (!ticket) return res.status(404).json({ valid: false, msg: "❌ INVALID CODE" });
        if (ticket.status === 'used') return res.status(409).json({ valid: false, msg: "⚠️ ALREADY REDEEMED" });
        if (!ticket.firstScan) { ticket.firstScan = new Date(); ticket.status = 'active'; await ticket.save(); }
        const now = new Date(); const expiry = new Date(ticket.firstScan); expiry.setHours(expiry.getHours() + 48);
        if (now > expiry) return res.json({ valid: true, expired: true, pcName: ticket.pcName });
        res.json({ valid: true, expired: false, pcName: ticket.pcName, timeLeft: expiry - now });
    } catch(e) { console.error(e); res.status(500).json({ valid: false, msg: "SERVER ERROR" }); }
});

app.post('/api/submit-review', authLimiter, async (req, res) => {
    try {
        const code = asString(req.body.code).trim();
        const user = asString(req.body.user).trim().slice(0, 40);
        const text = asString(req.body.text).trim().slice(0, 1000);
        const rating = Number(req.body.rating);

        if (!code || !user || !text) return res.status(400).json({ error: "All fields required" });
        if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
            return res.status(400).json({ error: "Rating must be a whole number from 1 to 5" });
        }

        const ticket = await ReviewTicket.findOne({ code });
        if (!ticket) return res.status(400).json({ error: "Invalid Ticket" });
        // Previously any known code could be replayed to post unlimited reviews
        if (ticket.status === 'used') return res.status(409).json({ error: "This code has already been redeemed" });

        // Same 48h window /api/check-code enforces — it was checked on read but never on write
        if (ticket.firstScan) {
            const expiry = new Date(ticket.firstScan);
            expiry.setHours(expiry.getHours() + 48);
            if (new Date() > expiry) return res.status(403).json({ error: "This code has expired" });
        }

        const pc = await PC.findById(ticket.pcId);
        if (!pc) return res.status(404).json({ error: "PC not found" });

        pc.reviews.push({ user, rating, text, date: new Date() });
        await pc.save();
        ticket.status = 'used';
        await ticket.save();
        res.json({ success: true });
    } catch (e) {
        console.error("Submit review failed:", e);
        res.status(500).json({ error: "Server Error" });
    }
});

app.post('/api/newsletter', authLimiter, async (req, res) => {
    const email = asString(req.body.email).trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
        return res.status(400).json({ error: "Please enter a valid email address" });
    }
    // Don't pile up duplicates every time someone re-submits the form
    if (await Newsletter.findOne({ email })) return res.json({ success: true });
    await new Newsletter({ email }).save();
    res.json({ success: true });
});
app.get('/api/newsletter', auth, async (req, res) => {
    try { res.json(await Newsletter.find().sort({ date: -1 })); }
    catch (e) { console.error("Fetch newsletter failed:", e); res.status(500).json({ error: "Server Error" }); }
});

// --- 🛡️ SECURITY LAYER 6: UNKNOWN ROUTES & UNCAUGHT ERRORS ---
// Anything under /api/ that doesn't match a route above (typos, probing, old client versions)
app.use('/api', (req, res) => res.status(404).json({ error: "Not Found" }));

// Final safety net. Express 5 auto-forwards a rejected promise from any async handler here, so
// without this, an error from a route with no try/catch of its own falls through to Express's
// built-in handler — which prints a full stack trace (file paths, package versions, internal
// structure) to the client whenever NODE_ENV isn't exactly 'production'. This runs first and
// unconditionally, so the response is always the same generic message no matter how NODE_ENV
// ends up configured on the host. Must be the last app.use() — Express only routes to an error
// handler (4-arg signature) that's registered after the route that threw.
app.use((err, req, res, next) => {
    console.error("🚨 UNCAUGHT ERROR:", err);
    if (res.headersSent) return next(err);
    res.status(500).json({ error: "Server Error" });
});

app.listen(PORT, '0.0.0.0', () => { console.log(`🚀 Server running on port ${PORT}`); });