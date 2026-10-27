require('dotenv').config();

// Render's outbound network has no IPv6 route, and Node resolves AAAA (IPv6) records first by
// default — outbound connections to any host with both record types can hang on ENETUNREACH
// before ever trying IPv4. Applies to every outbound call this server makes (the Mailjet email
// API, MongoDB Atlas), so it's set once here rather than per call site. Node 17+.
require('dns').setDefaultResultOrder('ipv4first');

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const crypto = require('crypto');
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
app.use('/api/', publicReadLimiter, apiLimiter);

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

// Password hashing brake. A bcrypt round at cost 12 is deliberately slow — on this dyno's small
// CPU share likely around a second. A burst of logins/sign-ups (or someone scripting them from many
// IPs, which the per-IP limiters above can't see) would run several at once and starve every other
// request of CPU, so the whole site would crawl. At most BCRYPT_MAX_CONCURRENT run together, the
// rest wait their turn; with too many already waiting the request is turned away at once with a
// "busy" answer instead of joining a queue it would time out in.
const BCRYPT_MAX_CONCURRENT = 2;
const BCRYPT_MAX_WAITING = 20;
let bcryptRunning = 0;
const bcryptWaiting = [];
class BcryptBusyError extends Error {}
async function withBcrypt(fn) {
    if (bcryptRunning >= BCRYPT_MAX_CONCURRENT) {
        if (bcryptWaiting.length >= BCRYPT_MAX_WAITING) throw new BcryptBusyError();
        await new Promise(resolve => bcryptWaiting.push(resolve));
    } else {
        bcryptRunning++;
    }
    try { return await fn(); }
    finally {
        // Hand the slot straight to the next in line (the count stays), or free it
        const next = bcryptWaiting.shift();
        if (next) next(); else bcryptRunning--;
    }
}
const BUSY_ERROR = { error: "⚠️ SYSTEM BUSY: Too many sign-ins right now. Try again in a few seconds." };

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

// --- EMAIL ADDRESS SANITY CHECKS ---
// The previous pattern was /^[^\s@]+@[^\s@]+\.[^\s@]+$/ — "anything without spaces, with an @".
// That accepts "<svg/onload=fetch(...)>@gmail.com": it has no space, exactly one @, and the domain
// half is a real domain, so it also passed the MX check below. The address was then stored and
// rendered by the admin panel, which is how a public, unauthenticated signup form became a way to
// run script in an authenticated admin's browser.
//
// This pattern allows only characters that appear in addresses people actually use, which happens
// to exclude every HTML metacharacter (< > " ' / & =). RFC 5321 technically permits more in the
// local part, but no mainstream provider issues such addresses, and letting them through here is
// how the injection above became possible in the first place.
const EMAIL_PATTERN = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$/;
const isValidEmail = (email) => email.length <= 254 && EMAIL_PATTERN.test(email);

// A format regex alone accepts anything shaped like an address, so "asdf@asdf.com" sails through.
// These two checks raise the bar cheaply; the verification link remains the real proof of
// ownership, since only a mailbox that actually receives it can complete signup.
const DISPOSABLE_EMAIL_DOMAINS = new Set([
    'mailinator.com', '10minutemail.com', 'guerrillamail.com', 'guerrillamail.net',
    'tempmail.com', 'temp-mail.org', 'throwawaymail.com', 'yopmail.com', 'trashmail.com',
    'sharklasers.com', 'getnada.com', 'maildrop.cc', 'fakeinbox.com', 'dispostable.com',
    'mailnesia.com', 'mintemail.com', 'spamgourmet.com', 'mytemp.email', 'moakt.com',
    'emailondeck.com', 'burnermail.io', 'tempr.email', 'discard.email', 'mailcatch.com'
]);

const isDisposableEmail = (email) => DISPOSABLE_EMAIL_DOMAINS.has(email.split('@')[1] || '');

// Confirms the domain actually publishes mail servers — catches invented domains and typos like
// "gmial.com". Deliberately fails OPEN: a DNS hiccup must never block a legitimate signup.
async function domainAcceptsMail(email) {
    const domain = email.split('@')[1];
    if (!domain) return false;
    try {
        const records = await require('dns').promises.resolveMx(domain);
        return Array.isArray(records) && records.length > 0;
    } catch (e) {
        if (e.code === 'ENOTFOUND' || e.code === 'NODATA') return false; // domain has no mail
        console.error(`MX lookup failed for "${domain}", allowing through:`, e.code);
        return true;
    }
}

console.log("⏳ Connecting to MongoDB...");
mongoose.connect(dbURI, { serverSelectionTimeoutMS: 30000, socketTimeoutMS: 45000 })
.then(() => {
    console.log("✅ SERVER ONLINE: DATABASE CONNECTED (SECURE MODE)");
    migrateLegacyPrices(); // declared below the models; runs once the connection is up
})
.catch((err) => console.error("❌ DB CONNECTION ERROR:", err.message));

// --- SCHEMAS ---
const pcSchema = new mongoose.Schema({
    // priceCents is the source of truth (integer euro cents — no float rounding, no parsing a
    // free-text "€1.200" to do arithmetic). `price` is the legacy free-text field: kept rather than
    // dropped so nothing already in the database is lost, and mirrored from priceCents on every
    // write so a browser still running the old frontend mid-deploy doesn't break. See
    // normalizePriceFields() and migrateLegacyPrices().
    name: String, price: String, priceCents: { type: Number, min: 0 }, description: String, lore: String, loreEl: String, stock: { type: Number, default: 1 },
    images: [String], status: { type: String, default: 'available' }, category: { type: String, default: 'drop' },    
    multitasking: { type: Number, default: 0 },
    specs: { cpu: String, gpu: String, ram: String, ssd: String, mobo: String, psu: String, case: String },
    specDetails: { type: Map, of: String, default: {} },
    fps: [{ game: String, score: Number }],
    // rank: the reviewer's rank when they wrote it, if they were signed in (the badge by the name)
    reviews: [{ user: String, text: String, rating: Number, rank: String, date: { type: Date, default: Date.now } }],
    votes: { type: Number, default: 0 },
    // Set on the PC a community vote turned into a regular listing (resolveVoteEvent) — the card
    // shows a COMMUNITY DROP badge for it.
    communityDrop: { type: Boolean, default: false },
    // Early access: a drop the community unlocked before its timer ran out can be ordered only by
    // signed-in members until then (the vote's end), and by everyone after. Unset = public.
    membersOnlyUntil: Date,
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

// --- Read caches (in memory, one dyno) ---
// GET /api/drops is on every page load and used to read and serialise every PC with all its reviews
// each time; the maintenance check read SiteConfig on EVERY api request. Both now come from memory.
// A cache is only safe if no write can leave it stale (stock, prices, a new review), so instead of
// clearing it in each route that writes — seven of them, one inside the vote unlock — the models
// clear it themselves, on every kind of write mongoose can make. The TTL is only a backstop for a
// write made outside this process (someone editing the database by hand).
const CACHE_TTL_MS = 30 * 1000;
const WRITE_HOOKS = ['save', 'updateOne', 'updateMany', 'findOneAndUpdate', 'findOneAndDelete', 'findOneAndReplace', 'replaceOne', 'deleteOne', 'deleteMany', 'insertMany'];
let dropsCache = null;      // { body: JSON string, at }
let siteConfigCache = null; // { config: lean doc or null, at }
const clearDropsCache = () => { dropsCache = null; };
const clearSiteConfigCache = () => { siteConfigCache = null; };
pcSchema.post(WRITE_HOOKS, clearDropsCache);

const PC = mongoose.model('PC', pcSchema);

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    // Indexed: sorted by in the admin user list, and counted against by the 'founder' achievement
    joined: { type: Date, default: Date.now, index: true },
    subscribed: { type: Boolean, default: false },
    resetToken: String,
    resetTokenExpiry: Date,
    wishlist: [{ type: mongoose.Schema.Types.ObjectId, ref: 'PC' }],
    achievements: { type: [String], default: [] },
    // Durable counters behind the server-verified achievements. They exist because the events
    // themselves don't survive: a VoteEvent is deleted the moment it expires or is replaced, and
    // a ReviewTicket is a one-shot code. Without a counter on the account, "you voted" and "you
    // wrote a report" would silently un-earn themselves the next time the source row disappeared.
    votesCast: { type: Number, default: 0 },
    reviewsWritten: { type: Number, default: 0 },
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
    emailVerifyExpiry: Date,
    // Throttles /api/resend-verification independently of the shared authLimiter — that limiter is
    // 100 requests per 15 minutes across every auth route, loose enough that one impatient click of
    // "resend" ten times in a row would still queue ten emails before it ever engaged.
    lastVerificationEmailSentAt: Date,
    // The "wasn't you?" escape hatch mailed alongside every verification link. Deliberately a
    // SEPARATE token from emailVerifyTokenHash, on its own 7-day clock: the verify link is short-
    // lived by design, but whoever registered with a stranger's address holds the only password —
    // the real owner has no way to ask for a fresh email if they're late, so this one has to
    // outlive a single 24h window. Cleared the moment the account is legitimately verified (see
    // /api/verify-email) so a genuine owner can never lock themselves out by clicking a stale link
    // dug up from an old email.
    securityReportTokenHash: String,
    securityReportTokenExpiry: Date,
    // Set by /api/report-unauthorized-signup. Checked at login (after the password matches, so a
    // brute-force attempt without the real password never learns an account is in this state) and
    // enforced immediately on any live session via the tokenVersion bump that accompanies it.
    securityLockedUntil: Date,
    // Daily wheel, decided here rather than in the browser — a spin the client decides can be faked
    // from devtools, and a coupon is worth real money. See POST /api/wheel/spin.
    wheelAttemptsLeft: { type: Number, default: 3 },
    wheelNextAt: Date,
    unlockedColors: { type: [String], default: [] },
    // Rank rewards (grantRankRewards): the ranks already paid out, and the bonus spins they gave that
    // haven't been used yet — banked, spent only after the day's own attempts, and they never touch
    // the daily cooldown
    rankRewardsClaimed: { type: [String], default: [] },
    bonusSpins: { type: Number, default: 0, min: 0 },
    // Discount codes won on the wheel. The order is a WhatsApp message, so the shop checks a code in
    // the admin panel and redeems it there (usedAt).
    coupons: [{ code: String, percent: Number, issuedAt: Date, expiresAt: Date, usedAt: Date }]
});
userSchema.index({ 'coupons.code': 1 }, { sparse: true });
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
    priceCents: { type: Number, min: 0 }, // same arrangement as pcSchema — see the comment there
    specs: { cpu: String, gpu: String, ram: String, ssd: String, mobo: String, psu: String, case: String },
    // Mirrors the PC fields so the vote drop can open in the same inspect card as every other
    // build (flip to specs, show FPS, lore on the front).
    description: String,
    lore: String,
    loreEl: String,
    multitasking: { type: Number, default: 0 },
    fps: [{ game: String, score: Number }],
    // How the vote ended. 'open' while it runs; 'unlocked' when the community reached the target;
    // 'closed' when the timer ran out first. Either way the drop becomes a regular PC in LIVE DROPS
    // (pcId) and the event stays on the VOTE tab, pointing there, until the admin starts the next
    // one. Events saved before this field existed have no status and are treated as 'open'.
    status: { type: String, enum: ['open', 'unlocked', 'closed'], default: 'open' },
    pcId: { type: mongoose.Schema.Types.ObjectId, ref: 'PC' },
    resolvedAt: Date
});
const VoteEvent = mongoose.model('VoteEvent', voteEventSchema);

// [start, end] of a vote event's window; end is null when the event has no start date
function voteWindow(event) {
    if (!event.startDate) return { start: null, end: null };
    const start = new Date(event.startDate);
    return { start, end: new Date(start.getTime() + (event.durationDays || 0) * 24 * 60 * 60 * 1000) };
}

function voteResolved(event) {
    return event.status === 'unlocked' || event.status === 'closed';
}

// What the VOTE tab should show, decided here rather than from the visitor's own clock
function votePhase(event, now) {
    if (voteResolved(event)) return event.status;
    const { start } = voteWindow(event);
    return start && now < start ? 'upcoming' : 'open';
}

// Ends a community vote by turning the drop into a regular PC in LIVE DROPS — when the target is
// reached ('unlocked') or when the timer runs out without it ('closed'). The event is CLAIMED
// atomically first: only the request that flips it out of 'open' creates the PC, so a burst of last
// votes, or GETs queued while the free dyno wakes up, can't list the same drop twice (the old
// expiry code could). Every field the inspect card uses is copied — the old conversion dropped the
// lore, description and FPS.
async function resolveVoteEvent(event, outcome) {
    const pcId = new mongoose.Types.ObjectId();
    const claimed = await VoteEvent.findOneAndUpdate(
        { _id: event._id, status: { $nin: ['unlocked', 'closed'] } },
        { $set: { status: outcome, pcId, resolvedAt: new Date() } },
        { new: true }
    );
    if (!claimed) return (await VoteEvent.findById(event._id)) || event; // another request got there first

    const ev = claimed.toObject();
    const hasPrice = Number.isFinite(ev.priceCents) && ev.priceCents > 0;
    const { end } = voteWindow(claimed);
    try {
        await new PC({
            _id: pcId,
            name: ev.title,
            price: hasPrice ? ev.price : '',
            priceCents: hasPrice ? ev.priceCents : undefined,
            description: ev.description || '',
            lore: ev.lore || '',
            loreEl: ev.loreEl || '',
            images: ev.image ? [ev.image] : [],
            specs: ev.specs || {},
            fps: (ev.fps || []).map(f => ({ game: f.game, score: f.score })),
            multitasking: ev.multitasking || 0,
            // No price yet: listed as COMING SOON (shown, not orderable) until the admin sets one,
            // instead of an orderable PC at 0,00 €
            status: hasPrice ? 'available' : 'coming',
            category: 'drop',
            stock: 1,
            communityDrop: true,
            // Unlocked in time: members get it first, until the vote would have ended
            membersOnlyUntil: (outcome === 'unlocked' && end && end > new Date()) ? end : undefined
        }).save();
    } catch (e) {
        // Release the claim so the next read retries, instead of pointing at a PC that doesn't exist
        await VoteEvent.updateOne({ _id: claimed._id }, { $set: { status: 'open' }, $unset: { pcId: 1, resolvedAt: 1 } });
        throw e;
    }
    return claimed;
}

const reviewTicketSchema = new mongoose.Schema({
    code: { type: String, index: true }, pcId: String, pcName: String,
    status: { type: String, default: 'pending' }, 
    generatedAt: { type: Date, default: Date.now }, 
    firstScan: { type: Date, default: null } 
});
const ReviewTicket = mongoose.model('ReviewTicket', reviewTicketSchema);

// Indexed: the signup route looks up by email to avoid duplicates, and the achievement sync
// checks it once per unearned "signal_intercepted" — both are exact-match reads on every call.
const newsletterSchema = new mongoose.Schema({ email: { type: String, index: true }, date: { type: Date, default: Date.now } });
const Newsletter = mongoose.model('Newsletter', newsletterSchema);

// Default "How it works" text for the VOTE tab, until the admin writes their own (GLOBAL SETTINGS).
// One copy, used both as the schema default and as the /api/status fallback.
const DEFAULT_VOTE_INFO_EN = "Community drops: the network votes to unlock a mystery PC.\n\n1. Voting opens on the date shown.\n2. Every signed-in agent with a verified email gets one vote.\n3. Reach the target before time runs out and the PC unlocks straight into Live Drops — signed-in members can order it first, until the timer would have ended; then it is open to everyone.\n4. If time runs out first, the PC still comes to Live Drops when voting closes.";
const DEFAULT_VOTE_INFO_EL = "Κοινοτικά drops: η κοινότητα ψηφίζει για να ξεκλειδώσει ένα μυστηριώδες PC.\n\n1. Η ψηφοφορία ανοίγει την ημερομηνία που φαίνεται.\n2. Κάθε συνδεδεμένος πράκτορας με επιβεβαιωμένο email έχει μία ψήφο.\n3. Αν μαζευτούν οι ψήφοι πριν λήξει ο χρόνος, το PC ξεκλειδώνει και μπαίνει αμέσως στα Live Drops — με προτεραιότητα για τα συνδεδεμένα μέλη μέχρι να έληγε ο χρόνος, και μετά για όλους.\n4. Αν λήξει πρώτα ο χρόνος, το PC έρχεται κι αυτό στα Live Drops με το κλείσιμο της ψηφοφορίας.";

const siteConfigSchema = new mongoose.Schema({
    maintenanceMode: { type: Boolean, default: false },
    maintenanceMessage: { type: String, default: "PHOENIX CODEX is currently undergoing scheduled maintenance. We'll be back online shortly." },
    // Pro Config is the same service on every build, so its price lives here rather than per-PC.
    // Exposed publicly through /api/status (the frontend needs it to price the option).
    proConfigPrice: { type: Number, default: 30 },
    // The "?" button on the vote card explaining how community drops work. Lives here rather than
    // on VoteEvent because VoteEvent is deleted and recreated wholesale every time an event starts
    // (see POST /api/vote-event) — the admin would have to retype this explainer for every single
    // drop otherwise. Split EN/EL to match every other piece of admin-authored prose in this schema
    // (PC.lore/loreEl, VoteEvent.lore/loreEl) rather than being the one exception. Rendered with the
    // browser's own line-break handling (see .vote-info-text in vote.css), not as HTML, so no
    // escaping is needed and no markup can be injected through it.
    voteInfoText: {
        type: String,
        default: DEFAULT_VOTE_INFO_EN
    },
    voteInfoTextEl: {
        type: String,
        default: DEFAULT_VOTE_INFO_EL
    }
});
siteConfigSchema.post(WRITE_HOOKS, clearSiteConfigCache);
const SiteConfig = mongoose.model('SiteConfig', siteConfigSchema);

// The site config for READING (maintenance check, /api/status). Read-only: the admin routes that
// change it still load the real document. null when the admin panel has never created one.
async function getSiteConfig() {
    if (siteConfigCache && Date.now() - siteConfigCache.at < CACHE_TTL_MS) return siteConfigCache.config;
    // A full document turned into a plain object, not .lean(): lean skips the schema defaults, and an
    // older config saved before a field existed (the maintenance message, say) would come back without it
    const doc = await SiteConfig.findOne();
    const config = doc ? doc.toObject() : null;
    siteConfigCache = { config, at: Date.now() };
    return config;
}

// --- 💶 PRICES ---
// Reads the free-text prices the admin panel used to store ("340", "€340", "1.200", "449,99€").
// The last separator is a decimal point only when one or two digits follow it; three digits means
// a thousands separator. Returns integer cents, or null when there's no number in there at all.
function parseLegacyPriceToCents(value) {
    if (typeof value === 'number') return Number.isFinite(value) && value >= 0 ? Math.round(value * 100) : null;
    const s = String(value ?? '').replace(/[^\d.,]/g, '');
    if (!/\d/.test(s)) return null;
    const lastSep = Math.max(s.lastIndexOf('.'), s.lastIndexOf(','));
    let whole = s, frac = '';
    if (lastSep !== -1) {
        const after = s.slice(lastSep + 1);
        if (after.length === 1 || after.length === 2) { whole = s.slice(0, lastSep); frac = after; }
    }
    const cents = parseInt(whole.replace(/[.,]/g, '') || '0', 10) * 100 + (frac ? parseInt(frac.padEnd(2, '0'), 10) : 0);
    return Number.isFinite(cents) ? cents : null;
}

// Applied to every admin write of a PC or vote event. priceCents wins; a body that only has the
// old `price` (a stale admin tab from before this change) is converted instead of rejected. Either
// way `price` is rewritten as a whole-euro mirror for any old frontend still reading it — whole
// euros because that code strips every non-digit, so "449.99" would have read as 44999.
function normalizePriceFields(body) {
    if (!body || typeof body !== 'object') return body;
    let cents = null;
    if (body.priceCents !== undefined && body.priceCents !== null && body.priceCents !== '') {
        const n = Number(body.priceCents);
        cents = Number.isInteger(n) && n >= 0 ? n : null;
        if (cents === null) throw new Error('priceCents must be a non-negative integer');
    } else if (body.price !== undefined) {
        cents = parseLegacyPriceToCents(body.price);
    }
    if (cents !== null) {
        body.priceCents = cents;
        body.price = String(Math.round(cents / 100));
    }
    return body;
}

// One-time backfill, safe to run on every boot: only touches documents that still have no
// priceCents, and only ever adds a field — the original `price` text is left as it was.
async function migrateLegacyPrices() {
    for (const Model of [PC, VoteEvent]) {
        try {
            const docs = await Model.find({ priceCents: { $exists: false } }).select('price');
            let migrated = 0;
            for (const doc of docs) {
                const cents = parseLegacyPriceToCents(doc.price);
                if (cents === null) {
                    console.warn(`⚠️ ${Model.modelName} ${doc._id}: price "${doc.price}" has no number in it — left for the admin to fix`);
                    continue;
                }
                await Model.updateOne({ _id: doc._id }, { $set: { priceCents: cents } });
                migrated++;
            }
            if (migrated) console.log(`💶 Migrated ${migrated} ${Model.modelName} price(s) to priceCents`);
        } catch (e) { console.error(`Price migration for ${Model.modelName} failed:`, e); }
    }
}

// --- 🏅 ACHIEVEMENTS, XP & RANKS ---
// The previous version took the client at its word: POST /api/achievements accepted any string as
// an id and stored it, so a single fetch() from devtools granted anything. Ranks are about to be
// built on top of this, so the split below is the whole point of the rewrite:
//
//   source: 'server'  — the API works it out from its own data on every sync. The client cannot
//                       grant one, and cannot keep one it no longer qualifies for.
//   source: 'client'  — a UI action the server genuinely cannot observe (a card flip, a wheel
//                       spin). Still whitelisted by id so nothing can be invented, and worth
//                       little XP each, so the honest half of the ladder is the one that counts:
//                       all eight client badges together are worth less than one 'field_report'.
//
// XP lives here and nowhere else. The frontend renders whatever /api/me reports, so these numbers
// can be retuned without shipping a matching frontend change.
const ACHIEVEMENTS = [
    // Verified from account state
    { id: 'recruited',          xp: 25,  source: 'server' },
    { id: 'identity_confirmed', xp: 75,  source: 'server' },
    { id: 'first_target',       xp: 25,  source: 'server' },
    { id: 'collector',          xp: 75,  source: 'server' },
    { id: 'hoarder',            xp: 150, source: 'server' },
    { id: 'vote_caster',        xp: 50,  source: 'server' },
    { id: 'kingmaker',          xp: 150, source: 'server' },
    { id: 'signal_intercepted', xp: 25,  source: 'server' },
    { id: 'field_report',       xp: 200, source: 'server' },
    { id: 'veteran',            xp: 100, source: 'server' },
    { id: 'founder',            xp: 100, source: 'server' },
    // Reported by the UI
    { id: 'first_loot',         xp: 25,  source: 'client' },
    { id: 'comparator',         xp: 25,  source: 'client' },
    { id: 'deep_scan',          xp: 25,  source: 'client' },
    { id: 'benchmarker',        xp: 25,  source: 'client' },
    { id: 'hacker',             xp: 25,  source: 'client' },
    { id: 'terminal_access',    xp: 25,  source: 'client' },
    { id: 'polyglot',           xp: 25,  source: 'client' },
    { id: 'night_owl',          xp: 25,  source: 'client' }
];

const ACHIEVEMENT_XP = new Map(ACHIEVEMENTS.map(a => [a.id, a.xp]));
const CLIENT_ACHIEVEMENT_IDS = new Set(ACHIEVEMENTS.filter(a => a.source === 'client').map(a => a.id));

// Accounts created before this rewrite hold the three original ids. Mapped rather than dropped so
// nobody loses progress they already earned; anything else unrecognised is discarded on sync.
const LEGACY_ACHIEVEMENT_IDS = { login: 'recruited', cart: 'first_loot', vote: 'vote_caster' };

// Ascending by minXp — rankFor() walks it backwards, so the order here is what defines the ladder.
// What each rank gives, once, the first time the account reaches it (grantRankRewards): a badge (the
// rank itself — shown on the profile and next to the name on reviews), and maybe an accent colour that
// only a rank unlocks (never on the wheel) and bonus wheel spins. Decided and stored here, never by
// the browser — the same reason the wheel is server-side.
const RANKS = [
    { id: 'recruit',    minXp: 0,    rewards: {} },
    { id: 'operative',  minXp: 100,  rewards: { spins: 1 } },
    { id: 'fieldAgent', minXp: 250,  rewards: { color: 'ultraviolet' } },
    { id: 'specialist', minXp: 450,  rewards: { spins: 2 } },
    { id: 'eliteAgent', minXp: 700,  rewards: { color: 'arctic', spins: 1 } },
    { id: 'phantom',    minXp: 1000, rewards: { color: 'phantom', spins: 3 } }
];
// The ladder as the profile shows it (thresholds + rewards), sent with every profile so the frontend
// never keeps its own copy of the numbers
const RANK_LADDER = RANKS.map(r => ({ id: r.id, minXp: r.minXp, rewards: { ...r.rewards } }));

const xpOf = (achievementIds) => (achievementIds || []).reduce((sum, id) => sum + (ACHIEVEMENT_XP.get(id) || 0), 0);

// Hands out the rewards of every rank the account has reached but not been paid for yet, on the
// document (the caller saves). Each rank pays once, ever — rankRewardsClaimed — so XP dropping and
// rising again can't farm it. Returns what was granted just now, for the "rank up" notice.
function grantRankRewards(user, xp) {
    const claimed = new Set(user.rankRewardsClaimed || []);
    const granted = [];
    for (const r of RANKS) {
        if (xp < r.minXp || claimed.has(r.id)) continue;
        claimed.add(r.id);
        const g = { rank: r.id };
        if (r.rewards.color) {
            if (!(user.unlockedColors || []).includes(r.rewards.color)) user.unlockedColors.push(r.rewards.color);
            g.color = r.rewards.color;
        }
        if (r.rewards.spins) {
            user.bonusSpins = (user.bonusSpins || 0) + r.rewards.spins;
            g.spins = r.rewards.spins;
        }
        granted.push(g);
    }
    if (granted.length) user.rankRewardsClaimed = RANKS.map(r => r.id).filter(id => claimed.has(id));
    return granted;
}

function rankFor(xp) {
    let current = RANKS[0];
    for (const r of RANKS) if (xp >= r.minXp) current = r;
    const next = RANKS.find(r => r.minXp > xp) || null;
    return {
        rank: current.id,
        rankMinXp: current.minXp,
        nextRank: next ? next.id : null,
        nextRankXp: next ? next.minXp : null,
        // 0-100, measured across the current band rather than from zero, so the bar fills once per
        // promotion instead of creeping imperceptibly toward a distant maximum.
        progress: next
            ? Math.round(((xp - current.minXp) / (next.minXp - current.minXp)) * 100)
            : 100
    };
}

// Recomputes every server-verified badge from the account's own data, merges in the client-reported
// ones already banked, and writes back only if something actually changed. Returns the profile the
// frontend renders. `user` must be a full document (not a .select() projection) — it is saved here.
async function syncAchievements(user) {
    const banked = new Set(
        (user.achievements || [])
            .map(id => LEGACY_ACHIEVEMENT_IDS[id] || id)
            .filter(id => ACHIEVEMENT_XP.has(id))
    );

    const wishlistCount = (user.wishlist || []).length;
    const earned = new Set(banked);

    // Every account that exists at all has cleared this one
    earned.add('recruited');
    if (user.emailVerified) earned.add('identity_confirmed');
    if (wishlistCount >= 1) earned.add('first_target');
    if (wishlistCount >= 5) earned.add('collector');
    if (wishlistCount >= 10) earned.add('hoarder');
    if ((user.votesCast || 0) >= 1) earned.add('vote_caster');
    if ((user.votesCast || 0) >= 3) earned.add('kingmaker');
    if ((user.reviewsWritten || 0) >= 1) earned.add('field_report');
    if (user.joined && (Date.now() - new Date(user.joined).getTime()) >= 30 * 24 * 60 * 60 * 1000) {
        earned.add('veteran');
    }

    // The two that need a query run only while still unearned, so the steady state costs nothing.
    if (!earned.has('signal_intercepted')) {
        if (user.subscribed) earned.add('signal_intercepted');
        else if (await Newsletter.exists({ email: user.email })) earned.add('signal_intercepted');
    }
    if (!earned.has('founder')) {
        const earlier = await User.countDocuments({ joined: { $lt: user.joined } });
        if (earlier < 100) earned.add('founder');
    }

    // Stored in registry order so the array is stable between saves and reads predictably in the DB
    const list = ACHIEVEMENTS.map(a => a.id).filter(id => earned.has(id));
    const changed = list.length !== (user.achievements || []).length
        || list.some((id, i) => user.achievements[i] !== id);
    if (changed) user.achievements = list;

    const xp = xpOf(list);
    // Accounts that were already past a rank before rewards existed get paid on their next load
    const rankRewards = grantRankRewards(user, xp);
    if (changed || rankRewards.length) await user.save();

    return {
        achievements: list, xp, ...rankFor(xp),
        ranks: RANK_LADDER,
        bonusSpins: user.bonusSpins || 0,
        // Non-empty only on the request that paid them out — the frontend shows it once
        rankRewards
    };
}

// --- 📧 EMAIL DELIVERY (Mailjet Send API v3.1) ---
// Render's free tier blocks outbound SMTP (ports 25/465/587) since Sept 2025, so nodemailer over
// Gmail could never connect from here — every send died with ETIMEDOUT. This goes out over plain
// HTTPS instead, which is never blocked. It's also the right tool regardless: Gmail caps at
// ~500/day, has poor deliverability to strangers, and eventually flags automated sending.
const MAILJET_API_KEY = process.env.MAILJET_API_KEY;        // "API Key" (public) in Mailjet
const MAILJET_SECRET_KEY = process.env.MAILJET_SECRET_KEY;  // "Secret Key" (private) in Mailjet
const EMAIL_FROM = process.env.EMAIL_FROM || process.env.EMAIL_USER;
const EMAIL_FROM_NAME = process.env.EMAIL_FROM_NAME || 'CODEX SYSTEMS';

if (!MAILJET_API_KEY || !MAILJET_SECRET_KEY) {
    console.error("🚨 MAILJET_API_KEY / MAILJET_SECRET_KEY not set — no verification or password-reset email can be sent.");
}
if (!EMAIL_FROM) {
    console.error("🚨 EMAIL_FROM is not set — set it to the sender address you validated in Mailjet.");
}

// `html` is optional — every existing call site (forgot-password, reset-password) keeps sending
// text-only exactly as before. TextPart is still sent alongside HTMLPart even when html is given:
// Mailjet's spam scoring and any client that can't render HTML both fall back to it.
// Throws on failure; callers already log and carry on without failing the request.
async function sendMail({ to, subject, text, html }) {
    if (!MAILJET_API_KEY || !MAILJET_SECRET_KEY || !EMAIL_FROM) {
        throw new Error('Email is not configured (MAILJET_API_KEY / MAILJET_SECRET_KEY / EMAIL_FROM missing)');
    }

    // Mailjet authenticates with HTTP Basic: "apiKey:secretKey" base64-encoded
    const credentials = Buffer.from(`${MAILJET_API_KEY}:${MAILJET_SECRET_KEY}`).toString('base64');

    const res = await fetch('https://api.mailjet.com/v3.1/send', {
        method: 'POST',
        headers: {
            'Authorization': `Basic ${credentials}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            Messages: [{
                From: { Email: EMAIL_FROM, Name: EMAIL_FROM_NAME },
                To: [{ Email: to }],
                Subject: subject,
                TextPart: text,
                ...(html ? { HTMLPart: html } : {})
            }]
        })
    });

    if (!res.ok) {
        // Mailjet returns a JSON body explaining the rejection (unvalidated sender, bad key, quota)
        const detail = await res.text().catch(() => '');
        throw new Error(`Mailjet API ${res.status}: ${detail}`);
    }
    return res.json().catch(() => ({}));
}

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

// Shared by /api/register and /api/resend-verification. Stores only the hash (same reasoning as
// the password-reset token) and returns the raw value, which is what actually goes in the email.
function issueEmailVerification(user) {
    const rawToken = crypto.randomBytes(32).toString('hex');
    user.emailVerifyTokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    user.emailVerifyExpiry = Date.now() + 24 * 60 * 60 * 1000; // 24h
    return rawToken;
}

// The "wasn't you?" token. Re-issued (rotated) alongside the verify token on every send, same as
// issueEmailVerification — but on its own 7-day clock rather than 24h. See the schema comment on
// securityReportTokenHash for why the two can't share a lifetime.
function issueSecurityReportToken(user) {
    const rawToken = crypto.randomBytes(32).toString('hex');
    user.securityReportTokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    user.securityReportTokenExpiry = Date.now() + 7 * 24 * 60 * 60 * 1000; // 7 days
    return rawToken;
}

// Minimal HTML-escaping for the one piece of user data that reaches the email template. The
// username is already restricted to [a-zA-Z0-9_.-] at registration so this can never actually
// fire — kept anyway because "the input is validated elsewhere" is exactly the assumption that
// broke on the admin panel (see the newsletter-email XSS fix), and an email template is not a
// context worth trusting twice.
const escHtml = (v) => String(v ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));

// Table-based layout with every style inline: Outlook's rendering engine is Word, not a browser,
// and most clients strip <style> blocks outright, so anything depending on external CSS or flex/
// grid silently collapses. This is the plainest layout that still looks like a real product email
// rather than the raw-URL plaintext it replaces.
function buildVerificationEmailHtml({ username, confirmLink, reportLink }) {
    const font = "font-family:Arial,Helvetica,sans-serif;";
    return `
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0a0a0a;padding:32px 16px;">
<tr><td align="center">
<table role="presentation" width="480" cellpadding="0" cellspacing="0" style="max-width:480px;background:#141414;border:1px solid #262626;border-radius:12px;">
<tr><td style="padding:32px 32px 8px 32px;text-align:center;">
<span style="${font}font-size:12px;letter-spacing:3px;color:#ccff00;font-weight:bold;">PHOENIX CODEX</span>
</td></tr>
<tr><td style="padding:8px 32px 24px 32px;text-align:center;">
<div style="${font}font-size:20px;color:#ffffff;font-weight:bold;margin-bottom:12px;">Confirm your identity, Agent ${escHtml(username)}</div>
<div style="${font}font-size:14px;color:#999999;line-height:1.6;">One more step unlocks your dossier, wishlist and voting rights. This link is valid for 24 hours.</div>
</td></tr>
<tr><td style="padding:8px 32px 32px 32px;text-align:center;">
<a href="${confirmLink}" style="display:inline-block;background:#ccff00;color:#0a0a0a;${font}font-size:14px;font-weight:bold;text-decoration:none;padding:14px 32px;border-radius:8px;">CONFIRM MY EMAIL</a>
</td></tr>
<tr><td style="padding:20px 32px 32px 32px;border-top:1px solid #262626;">
<div style="${font}font-size:12px;color:#666666;line-height:1.6;text-align:center;">Didn't create this account? <a href="${reportLink}" style="color:#ff6666;">Secure it now</a> — this locks it for 5 days.</div>
</td></tr>
</table>
<div style="${font}font-size:11px;color:#444444;margin-top:16px;">CODEX HQ</div>
</td></tr>
</table>`.trim();
}

async function sendVerificationEmail(user, rawVerifyToken, rawReportToken) {
    // Points at the frontend, not the API — verification is done by that page's own POST call
    // once it loads (js/main.js), never by whatever GETs the link itself (a mail client's link
    // scanner never runs the page's JavaScript). Falls back to the API URL only if no frontend
    // origin is configured, so verification is never completely undeliverable. The report link
    // uses the identical reasoning and the identical protection.
    const base = ALLOWED_ORIGINS[0] || `https://codex-backend-9kij.onrender.com`;
    const confirmLink = `${base}/?verify=${rawVerifyToken}`;
    const reportLink = `${base}/?report=${rawReportToken}`;
    await sendMail({
        to: user.email,
        subject: '✅ CONFIRM YOUR AGENT IDENTITY',
        text: `AGENT ${user.username},\n\nConfirm your email to unlock your dossier, wishlist and voting rights:\n${confirmLink}\n\nThis link is valid for 24 hours.\n\nDidn't create this account? Secure it now (locks it for 5 days):\n${reportLink}\n\n- CODEX HQ`,
        html: buildVerificationEmailHtml({ username: user.username, confirmLink, reportLink })
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
        const config = await getSiteConfig();
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
    const config = await getSiteConfig();
    res.json({
        maintenance: !!config?.maintenanceMode,
        message: config?.maintenanceMessage || null,
        // Public on purpose: the storefront prices the Pro Config extra from this.
        proConfigPrice: config?.proConfigPrice ?? 30,
        // Public on purpose too: the vote card's "?" button reads these straight from state. Fall
        // back to the schema defaults (duplicated here, same as proConfigPrice above) because this
        // route never creates a SiteConfig document — only the admin GET does, on first visit —
        // so a site where the admin panel has never been opened must still show sensible copy.
        voteInfoText: config?.voteInfoText || DEFAULT_VOTE_INFO_EN,
        voteInfoTextEl: config?.voteInfoTextEl || DEFAULT_VOTE_INFO_EL,
        // Diagnostics. Says whether the allowlist is configured at all and whether THIS caller's
        // origin is on it — the caller already knows its own origin, so nothing leaks, and a
        // silent CORS refusal becomes a one-request check instead of a log hunt.
        cors: {
            configured: ALLOWED_ORIGINS.length > 0,
            originAllowed: req.headers.origin ? isOriginAllowed(req.headers.origin) : null
        },
        // Same idea for email: says only whether the keys are present, never their values, so a
        // silently undelivered verification mail is a one-request check instead of a log hunt.
        email: {
            configured: !!(MAILJET_API_KEY && MAILJET_SECRET_KEY && EMAIL_FROM),
            sender: EMAIL_FROM || null
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
        const { maintenanceMode, maintenanceMessage, proConfigPrice, voteInfoText, voteInfoTextEl } = req.body;
        let config = await SiteConfig.findOne();
        if (!config) config = new SiteConfig();
        if (typeof maintenanceMode === 'boolean') config.maintenanceMode = maintenanceMode;
        if (typeof maintenanceMessage === 'string') config.maintenanceMessage = maintenanceMessage;
        if (proConfigPrice !== undefined && !Number.isNaN(Number(proConfigPrice))) {
            config.proConfigPrice = Math.max(0, Number(proConfigPrice));
        }
        // Capped well above anything a real explainer needs — this is admin-only input, but the
        // cap still guards against a stray paste turning the modal into an unreadable wall.
        if (typeof voteInfoText === 'string' && voteInfoText.length <= 2000) {
            config.voteInfoText = voteInfoText;
        }
        if (typeof voteInfoTextEl === 'string' && voteInfoTextEl.length <= 2000) {
            config.voteInfoTextEl = voteInfoTextEl;
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

app.post('/api/resend-verification', authLimiter, authUser, async (req, res) => {
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
app.post('/api/report-unauthorized-signup', authLimiter, async (req, res) => {
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

app.get('/api/me', authUser, requireVerified, async (req, res) => {
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

// --- DAILY WHEEL + COUPONS ---
// Same slice order as WHEEL slices in the frontend (js/modules/wheel.js) — the server answers with an
// index and the wheel animates to it.
const WHEEL_SLICES = [
    { type: 'blank' }, { type: 'color', id: 'cyberGold' }, { type: 'coupon' }, { type: 'color', id: 'toxicOrange' },
    { type: 'blank' }, { type: 'color', id: 'neonPink' }, { type: 'coupon' }, { type: 'color', id: 'matrixGreen' }
];
const WHEEL_MAX_ATTEMPTS = 3;
const WHEEL_COOLDOWN_MS = 24 * 60 * 60 * 1000;
const COUPON_PERCENT = 5;
const COUPON_DAYS = 30;
const COUPON_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'; // no 0/O, 1/I/L — read aloud over WhatsApp
// One spin at a time per account (a double tap must not become two spins)
const spinsInFlight = new Set();

function wheelStatus(user, now = new Date()) {
    let left = Number.isFinite(user.wheelAttemptsLeft) ? user.wheelAttemptsLeft : WHEEL_MAX_ATTEMPTS;
    let next = user.wheelNextAt || null;
    if (left <= 0 && (!next || now >= next)) { left = WHEEL_MAX_ATTEMPTS; next = null; }
    // bonusSpins: banked rank rewards, usable whenever the day's attempts are gone
    return { attemptsLeft: left, maxAttempts: WHEEL_MAX_ATTEMPTS, nextAvailableAt: left > 0 ? null : next, bonusSpins: user.bonusSpins || 0 };
}

// What the account sees: codes not past expiry (used ones stay listed, marked used, for 30 days)
function couponsFor(user, now = new Date()) {
    return (user.coupons || [])
        .filter(c => c.expiresAt && c.expiresAt > now)
        .map(c => ({ code: c.code, percent: c.percent, issuedAt: c.issuedAt, expiresAt: c.expiresAt, usedAt: c.usedAt || null }))
        .sort((a, b) => new Date(b.issuedAt) - new Date(a.issuedAt));
}

async function newCouponCode() {
    for (let i = 0; i < 6; i++) {
        let code = 'CDX-';
        for (let j = 0; j < 6; j++) code += COUPON_ALPHABET[crypto.randomInt(COUPON_ALPHABET.length)];
        if (!(await User.exists({ 'coupons.code': code }))) return code;
    }
    throw new Error('Could not generate a unique coupon code');
}

app.get('/api/wheel', authUser, requireVerified, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: "User not found" });
        res.json({ ...wheelStatus(user), coupons: couponsFor(user), unlockedColors: user.unlockedColors || [] });
    } catch (e) { console.error("Wheel status failed:", e); res.status(500).json({ error: "Server Error" }); }
});

app.post('/api/wheel/spin', authUser, requireVerified, async (req, res) => {
    if (spinsInFlight.has(req.userId)) return res.status(429).json({ error: "SPIN IN PROGRESS", code: "SPIN_BUSY" });
    spinsInFlight.add(req.userId);
    try {
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: "User not found" });
        const now = new Date();
        const status = wheelStatus(user, now);
        const useBonus = status.attemptsLeft <= 0 && status.bonusSpins > 0;
        if (status.attemptsLeft <= 0 && !useBonus) {
            return res.status(429).json({ error: "NO SPINS LEFT", code: "NO_SPINS", nextAvailableAt: status.nextAvailableAt });
        }

        const index = crypto.randomInt(WHEEL_SLICES.length);
        const slice = WHEEL_SLICES[index];
        const win = slice.type !== 'blank';
        if (useBonus) {
            // A banked rank spin: spent on its own, the daily cycle and its cooldown stay as they are
            user.bonusSpins = status.bonusSpins - 1;
        } else {
            const left = status.attemptsLeft - 1;
            // A win ends the cycle at once; so does using the last attempt
            user.wheelAttemptsLeft = win ? 0 : left;
            user.wheelNextAt = (win || left <= 0) ? new Date(now.getTime() + WHEEL_COOLDOWN_MS) : null;
        }

        const reward = { type: slice.type };
        if (slice.type === 'color') {
            reward.id = slice.id;
            reward.alreadyUnlocked = (user.unlockedColors || []).includes(slice.id);
            if (!reward.alreadyUnlocked) user.unlockedColors.push(slice.id);
        } else if (slice.type === 'coupon') {
            const coupon = { code: await newCouponCode(), percent: COUPON_PERCENT, issuedAt: now, expiresAt: new Date(now.getTime() + COUPON_DAYS * 24 * 60 * 60 * 1000) };
            user.coupons.push(coupon);
            reward.coupon = { code: coupon.code, percent: coupon.percent, expiresAt: coupon.expiresAt };
        }
        await user.save();

        const after = wheelStatus(user, now);
        res.json({ index, reward, ...after, coupons: couponsFor(user, now), unlockedColors: user.unlockedColors });
    } catch (e) {
        console.error("Wheel spin failed:", e);
        res.status(500).json({ error: "Server Error" });
    } finally {
        spinsInFlight.delete(req.userId);
    }
});

// Admin: look a code up (whose it is, valid or not), and mark it used once the order is agreed
app.get('/api/admin/coupons/:code', auth, async (req, res) => {
    try {
        const code = String(req.params.code || '').trim().toUpperCase();
        const user = await User.findOne({ 'coupons.code': code }).select('username email coupons');
        const c = user && user.coupons.find(x => x.code === code);
        if (!c) return res.status(404).json({ error: "Coupon not found" });
        res.json({ code: c.code, percent: c.percent, username: user.username, email: user.email, issuedAt: c.issuedAt, expiresAt: c.expiresAt, usedAt: c.usedAt || null, expired: c.expiresAt <= new Date() });
    } catch (e) { console.error("Coupon lookup failed:", e); res.status(500).json({ error: "Server Error" }); }
});

app.post('/api/admin/coupons/:code/redeem', auth, async (req, res) => {
    try {
        const code = String(req.params.code || '').trim().toUpperCase();
        // Atomic: only an unused, unexpired code flips to used — redeeming twice can't succeed twice
        const user = await User.findOneAndUpdate(
            { coupons: { $elemMatch: { code, usedAt: null, expiresAt: { $gt: new Date() } } } },
            { $set: { 'coupons.$.usedAt': new Date() } },
            { new: true }
        );
        if (!user) return res.status(409).json({ error: "Coupon not found, already used or expired" });
        res.json({ success: true, code, username: user.username });
    } catch (e) { console.error("Coupon redeem failed:", e); res.status(500).json({ error: "Server Error" }); }
});

app.post('/api/wishlist/:pcId', authUser, requireVerified, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: "User not found" });
        if (!user.wishlist.some(id => id.toString() === req.params.pcId)) {
            user.wishlist.push(req.params.pcId);
            await user.save();
        }
        // Three of the badges are wishlist-size thresholds, so the profile has to come back with
        // the write — otherwise crossing one only shows up after a reload.
        const profile = await syncAchievements(user);
        await user.populate('wishlist');
        res.json({ success: true, wishlist: user.wishlist, ...profile });
    } catch (e) { console.error("Wishlist add failed:", e); res.status(500).json({ error: "Server Error" }); }
});

app.delete('/api/wishlist/:pcId', authUser, requireVerified, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: "User not found" });
        user.wishlist = user.wishlist.filter(id => id.toString() !== req.params.pcId);
        await user.save();
        const profile = await syncAchievements(user);
        await user.populate('wishlist');
        res.json({ success: true, wishlist: user.wishlist, ...profile });
    } catch (e) { console.error("Wishlist remove failed:", e); res.status(500).json({ error: "Server Error" }); }
});

// Only ever grants a badge the server genuinely cannot observe for itself (a card flip, a wheel
// spin). Anything outside that whitelist — an unknown id, or the id of a server-verified badge
// someone is trying to hand themselves — is refused, and the reply is still the real profile, so
// a client that guesses wrong is simply corrected rather than desynced.
app.post('/api/achievements', authUser, requireVerified, async (req, res) => {
    try {
        const id = asString(req.body.id);
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: "User not found" });

        if (!CLIENT_ACHIEVEMENT_IDS.has(id)) {
            const profile = await syncAchievements(user);
            return res.status(400).json({ error: "UNKNOWN OR NON-REPORTABLE ACHIEVEMENT", ...profile });
        }

        if (!user.achievements.includes(id)) {
            user.achievements.push(id);
            await user.save();
        }
        const profile = await syncAchievements(user);
        res.json({ success: true, ...profile });
    } catch (e) { console.error("Achievement save failed:", e); res.status(500).json({ error: "Server Error" }); }
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

app.get('/api/users/count', auth, async (req, res) => { const count = await User.countDocuments(); res.json({ count }); });

// Admin user management — added so test/duplicate accounts (which block re-registering an email,
// by design — see /api/register's uniqueness check) can be cleared from the panel instead of
// needing direct database access every time. Password hash and tokens are never selected.
app.get('/api/users', auth, async (req, res) => {
    try {
        const users = await User.find()
            .select('username email joined subscribed emailVerified wishlist achievements securityLockedUntil')
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
    try {
        if (!dropsCache || Date.now() - dropsCache.at >= CACHE_TTL_MS) {
            // Full documents (not lean), so schema defaults still fill fields older PCs never had;
            // serialised once here, exactly as res.json() did, then reused until the next write
            dropsCache = { body: JSON.stringify(await PC.find()), at: Date.now() };
        }
        res.type('application/json').send(dropsCache.body);
    }
    catch (e) { console.error("Fetch drops failed:", e); res.status(500).json({ error: "Server Error" }); }
});
app.post('/api/drops', auth, async (req, res) => {
    try { const n = new PC(normalizePriceFields(req.body)); await n.save(); res.json(n); }
    catch (e) { console.error("Create drop failed:", e); res.status(400).json({ error: "Invalid system data" }); }
});
app.put('/api/drops/:id', auth, async (req, res) => {
    try {
        // findByIdAndUpdate throws a CastError on a malformed :id (not a valid ObjectId) — was
        // uncaught here, which without this try/catch depends on the global error handler below
        // (and, before that existed, could surface a raw stack trace instead of a clean 400).
        //
        // `reviews` is stripped: the panel loads a PC's reviews when EDIT is clicked and used to send
        // that whole array back on save, so any customer review posted in between was silently
        // overwritten by the admin's stale copy. Reviews on an existing PC are only ever changed
        // through the dedicated add/remove routes below, which touch one entry at a time.
        const { reviews, ...update } = normalizePriceFields(req.body || {});
        const u = await PC.findByIdAndUpdate(req.params.id, update, { new: true, runValidators: true });
        if (!u) return res.status(404).json({ error: "PC not found" });
        res.json(u);
    } catch (e) { console.error("Update drop failed:", e); res.status(400).json({ error: "Invalid system data or id" }); }
});

// Manual reviews added from the admin panel. One entry per call via $push / $pull, so an admin
// edit and a customer's review landing at the same moment can no longer overwrite each other.
app.post('/api/drops/:id/reviews', auth, async (req, res) => {
    try {
        const user = asString(req.body.user).trim().slice(0, 40);
        const text = asString(req.body.text).trim().slice(0, 1000);
        const rating = Number(req.body.rating);
        if (!user || !text) return res.status(400).json({ error: "User and text required" });
        if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
            return res.status(400).json({ error: "Rating must be a whole number from 1 to 5" });
        }
        const u = await PC.findByIdAndUpdate(
            req.params.id,
            { $push: { reviews: { user, text, rating, date: new Date() } } },
            { new: true }
        );
        if (!u) return res.status(404).json({ error: "PC not found" });
        res.json({ success: true, reviews: u.reviews });
    } catch (e) { console.error("Add review failed:", e); res.status(400).json({ error: "Invalid id" }); }
});

app.delete('/api/drops/:id/reviews/:reviewId', auth, async (req, res) => {
    try {
        const u = await PC.findByIdAndUpdate(
            req.params.id,
            { $pull: { reviews: { _id: req.params.reviewId } } },
            { new: true }
        );
        if (!u) return res.status(404).json({ error: "PC not found" });
        res.json({ success: true, reviews: u.reviews });
    } catch (e) { console.error("Remove review failed:", e); res.status(400).json({ error: "Invalid id" }); }
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
        let event = await VoteEvent.findOne();
        if (!event) return res.json({});

        // Resolved lazily, on read, rather than by a background timer — this dyno sleeps on idle on
        // Render's free tier, so a setInterval wouldn't reliably fire. Catches an expired event, and
        // one that reached its target some other way (an event from before unlocking existed, or
        // the admin lowering the target).
        const now = new Date();
        if (!voteResolved(event)) {
            const { end } = voteWindow(event);
            try {
                if (event.targetVotes > 0 && event.currentVotes >= event.targetVotes) event = await resolveVoteEvent(event, 'unlocked');
                else if (end && now > end) event = await resolveVoteEvent(event, 'closed');
            } catch (e) {
                // Still answer with the event as it stands; the next read tries again
                console.error("Resolving vote event failed:", e);
            }
        }

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
        // phase/endsAt/serverNow: the tab's state comes from the server's clock, not the visitor's
        res.json({ ...payload, hasVoted, phase: votePhase(event, now), endsAt: voteWindow(event).end, serverNow: now });
    } catch (e) {
        console.error("Vote event fetch/expiry check failed:", e);
        res.json({});
    }
});
app.post('/api/vote-event', auth, async (req, res) => {
    try {
        // Validated before anything is deleted: a bad price used to wipe the running event first
        // and only then fail to create its replacement, leaving no event at all.
        const n = new VoteEvent(normalizePriceFields(req.body));
        // A new event always starts open, whatever the request body says
        n.status = 'open';
        n.pcId = undefined;
        n.resolvedAt = undefined;
        await n.validate();
        await VoteEvent.deleteMany({});
        await n.save();
        res.json(n);
    } catch (e) { console.error("Create vote-event failed:", e); res.status(400).json({ error: "Invalid vote event data" }); }
});
// Clears the VOTE tab (after a drop has been resolved, or to cancel one). A PC the event already
// turned into stays in LIVE DROPS — that's a normal PC now, edited or deleted like any other.
app.delete('/api/vote-event', auth, async (req, res) => {
    try {
        await VoteEvent.deleteMany({});
        res.json({ msg: "Deleted" });
    } catch (e) { console.error("Delete vote-event failed:", e); res.status(500).json({ error: "Server Error" }); }
});
app.post('/api/cast-vote', authUser, requireVerified, async (req, res) => {
    try {
        const event = await VoteEvent.findOne();
        if (!event) return res.status(404).json({ error: "No active vote" });

        // One vote per account — this is what makes the counter mean anything
        if ((event.votedBy || []).some(id => id.toString() === req.userId)) {
            return res.status(409).json({ error: "ALREADY VOTED", votes: event.currentVotes, hasVoted: true });
        }

        // Already unlocked or closed: the drop is a regular PC in LIVE DROPS now
        if (voteResolved(event)) {
            return res.status(409).json({ error: "VOTING HAS CLOSED", code: "VOTE_CLOSED", phase: event.status, pcId: event.pcId, votes: event.currentVotes });
        }

        // The client disables the button outside the window, but the API has to enforce it too
        const { start, end } = voteWindow(event);
        if (start) {
            const now = new Date();
            if (now < start) return res.status(403).json({ error: "VOTING HAS NOT OPENED YET", code: "VOTE_NOT_OPEN" });
            if (now > end) return res.status(409).json({ error: "VOTING HAS CLOSED", code: "VOTE_CLOSED" });
        }

        // Read-modify-write on the document lost votes under concurrency: two requests landing
        // together both read the same currentVotes and the second save overwrote the first. One
        // atomic update instead, with "hasn't voted yet" — and "still open" — as part of the match,
        // so the database, not a prior read, enforces one vote per account and no votes after unlock.
        const updated = await VoteEvent.findOneAndUpdate(
            { _id: event._id, votedBy: { $ne: req.userId }, status: { $nin: ['unlocked', 'closed'] } },
            { $addToSet: { votedBy: req.userId }, $inc: { currentVotes: 1 } },
            { new: true }
        );
        if (!updated) {
            // Matched nothing: either this account's vote landed between the check above and here
            // (double-click, two tabs), or the vote just before this one unlocked the drop.
            const fresh = await VoteEvent.findById(event._id).select('currentVotes status pcId');
            if (fresh && voteResolved(fresh)) {
                return res.status(409).json({ error: "VOTING HAS CLOSED", code: "VOTE_CLOSED", phase: fresh.status, pcId: fresh.pcId, votes: fresh.currentVotes });
            }
            return res.status(409).json({ error: "ALREADY VOTED", votes: fresh?.currentVotes ?? event.currentVotes, hasVoted: true });
        }

        // This vote reached the target: the drop unlocks now and goes straight to LIVE DROPS
        let unlocked = null;
        if (updated.targetVotes > 0 && updated.currentVotes >= updated.targetVotes) {
            // The vote itself is already counted; if creating the PC fails, the next GET retries the
            // unlock (resolveVoteEvent released its claim), so this must not turn into a failed vote.
            try { unlocked = await resolveVoteEvent(updated, 'unlocked'); }
            catch (e) { console.error("Unlocking vote drop failed (will retry on next read):", e); }
        }

        // Counted on the account as well as the event, because the event is deleted when it
        // expires — see the votesCast comment on userSchema.
        const user = await User.findById(req.userId);
        let profile = null;
        if (user) {
            user.votesCast = (user.votesCast || 0) + 1;
            await user.save();
            profile = await syncAchievements(user);
        }

        res.json({
            votes: updated.currentVotes, hasVoted: true, profile,
            // The client plays the "unlocked → LIVE DROPS" sequence when this vote is the one that did it
            phase: unlocked ? unlocked.status : 'open',
            pcId: unlocked ? unlocked.pcId : undefined
        });
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

        // The display name is shown in the admin panel and on the storefront. Both escape it, so
        // this is the second layer — it keeps the value safe for any future consumer that is not an
        // escaped HTML template (a CSV export, an email body). Only the NAME is restricted: review
        // text legitimately contains angle brackets in this shop ("temps <70°C"), and accented and
        // Greek letters stay allowed in both.
        if (/[<>]/.test(user)) {
            return res.status(400).json({ error: "Name cannot contain < or > characters" });
        }
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

        if (!await PC.exists({ _id: ticket.pcId })) return res.status(404).json({ error: "PC not found" });

        // Claim the ticket atomically BEFORE writing the review. The old order was read status ->
        // push review -> mark used, so two submits with the same code landing together (a double
        // tap, a retried request) both passed the `status === 'used'` check above and both posted.
        // Putting "not yet used" in the match means only one request can ever flip it.
        const claimed = await ReviewTicket.findOneAndUpdate(
            { _id: ticket._id, status: { $ne: 'used' } },
            { $set: { status: 'used' } }
        );
        if (!claimed) return res.status(409).json({ error: "This code has already been redeemed" });

        // Signed in: the review carries the reviewer's rank at this moment, for the badge by the name
        // (the name itself is free text, so the badge is the account's, read here from the session)
        const reviewerId = optionalUserId(req);
        let reviewerRank;
        if (reviewerId) {
            try {
                const reviewer = await User.findById(reviewerId).select('achievements').lean();
                if (reviewer) reviewerRank = rankFor(xpOf(reviewer.achievements)).rank;
            } catch (e) { console.error("Reading reviewer rank failed:", e); }
        }

        // $push rather than load-modify-save of the whole PC document: a concurrent admin edit of
        // this same PC then can't be overwritten by this write, or vice versa.
        const pushed = await PC.updateOne(
            { _id: ticket.pcId },
            { $push: { reviews: { user, rating, text, date: new Date(), ...(reviewerRank ? { rank: reviewerRank } : {}) } } }
        );
        if (!pushed.matchedCount) {
            // The PC was deleted between the check above and here — give the customer their code back
            await ReviewTicket.updateOne({ _id: ticket._id }, { $set: { status: ticket.status } });
            return res.status(404).json({ error: "PC not found" });
        }

        // The route stays open to guests — a mission code is the proof of purchase, not a login —
        // but when the browser does have a session, credit the account so 'field_report' becomes
        // earnable. The ticket is already marked used above, so this can't be farmed.
        if (reviewerId) {
            try {
                await User.updateOne({ _id: reviewerId }, { $inc: { reviewsWritten: 1 } });
            } catch (e) { console.error("Crediting review to account failed:", e); }
        }

        res.json({ success: true });
    } catch (e) {
        console.error("Submit review failed:", e);
        res.status(500).json({ error: "Server Error" });
    }
});

app.post('/api/newsletter', authLimiter, async (req, res) => {
    const email = asString(req.body.email).trim().toLowerCase();
    // This route takes no authentication at all, so it is the widest opening on the API — and its
    // output is read back by the admin panel. Validate it exactly as strictly as registration.
    if (!isValidEmail(email)) {
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