// Which browser origins may call the API.
// --- 🛡️ SECURITY LAYER 2: CORS ---
// FRONTEND_URL may hold several comma-separated origins (prod domain + Vercel preview).
// No '*' fallback: an unset env var must fail closed, not silently open the API to every site.
// A browser Origin is always scheme + host + port with no path and no trailing slash. Pasting
// "https://site.app/" or a capitalised host into the env var is the easy mistake, so both sides
// are normalised before comparing rather than failing on a stray character.
const normaliseOrigin = (value) => String(value || '').trim().replace(/\/+$/, '').toLowerCase();

const ALLOWED_ORIGINS = (process.env.FRONTEND_URL || '')
    .split(',').map(normaliseOrigin).filter(Boolean);

// Vercel gives every preview deployment its own address (codex-<hash>-phoenix-codex.vercel.app), so
// an exact list goes stale on the next push. An entry may therefore hold one '*', standing for the
// changing part — e.g. https://codex-*-phoenix-codex.vercel.app. Kept narrow on purpose: https only,
// the '*' only inside the host's first label, and it never matches a dot, so it can't reach past
// the account's own vercel.app names onto someone else's domain.
const WILDCARD_RE = /^https:\/\/([a-z0-9-]*)\*([a-z0-9-]*)(\.[a-z0-9-]+(?:\.[a-z0-9-]+)+)$/;
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const ORIGIN_PATTERNS = [];
for (const entry of ALLOWED_ORIGINS.filter(o => o.includes('*'))) {
    const m = entry.match(WILDCARD_RE);
    if (!m) {
        console.error(`⚠️ FRONTEND_URL entry "${entry}" ignored: a '*' is only allowed in the first part of an https host, e.g. https://codex-*-phoenix-codex.vercel.app`);
        continue;
    }
    ORIGIN_PATTERNS.push(new RegExp(`^https://${escapeRe(m[1])}[a-z0-9-]+${escapeRe(m[2])}${escapeRe(m[3])}$`));
}
const EXACT_ORIGINS = ALLOWED_ORIGINS.filter(o => !o.includes('*'));
// The site's own address, for links in emails: always a real origin, never a pattern
const PRIMARY_ORIGIN = EXACT_ORIGINS[0] || null;

if (!ALLOWED_ORIGINS.length) {
    console.error("⚠️ FRONTEND_URL is not set — every browser request will be refused by CORS. Set it to your site's origin, e.g. https://codex-iota-nine.vercel.app");
} else {
    console.log(`🌐 CORS allowing: ${ALLOWED_ORIGINS.join(', ')}`);
}

const isOriginAllowed = (origin) => {
    const o = normaliseOrigin(origin);
    return EXACT_ORIGINS.includes(o) || ORIGIN_PATTERNS.some(re => re.test(o));
};

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

module.exports = { ALLOWED_ORIGINS, PRIMARY_ORIGIN, isOriginAllowed, corsOptions };
