require('dotenv').config();

// Render's outbound network has no IPv6 route, and Node resolves AAAA (IPv6) records first by
// default — outbound connections to any host with both record types can hang on ENETUNREACH
// before ever trying IPv4. Applies to every outbound call this server makes (the Mailjet email
// API, MongoDB Atlas), so it's set once here rather than per call site. Node 17+.
require('dns').setDefaultResultOrder('ipv4first');

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const helmet = require('helmet');

// The API's parts live in src/: config (environment), security (CORS, rate limits, sessions),
// models (MongoDB schemas and the read caches), lib (prices, ranks, email, vote, wheel) and
// routes (one file per area). This file wires them together in the order requests meet them.
const { dbURI } = require('./src/config');
const { corsOptions } = require('./src/security/cors');
const { publicReadLimiter, apiLimiter } = require('./src/security/rate-limits');
const { isAdminRequest } = require('./src/security/auth');
const { getSiteConfig } = require('./src/models/site-config');
const { migrateLegacyPrices } = require('./src/lib/prices');

const app = express();
const PORT = process.env.PORT || 5000;

// Render sits in front of this app behind its own reverse proxy — trust the first hop so
// express-rate-limit (and req.ip generally) reads the real client IP from X-Forwarded-For
// instead of Render's proxy IP.
app.set('trust proxy', 1);

// --- 🛡️ SECURITY LAYER 1: HTTP HEADERS ---
app.use(helmet());
app.use(helmet.crossOriginResourcePolicy({ policy: "cross-origin" }));

// --- 🛡️ SECURITY LAYER 2: CORS (the allowlist: src/security/cors.js) ---
app.use(cors(corsOptions));
// Cap the body size so a single request can't tie up memory
app.use(express.json({ limit: '100kb' }));

// --- 🛡️ SECURITY LAYER 3: RATE LIMITING (src/security/rate-limits.js; the per-route ones are on the routes) ---
app.use('/api/', publicReadLimiter, apiLimiter);

// --- 🛡️ SECURITY LAYER 4: PREVENT API CACHING (GHOST CACHE FIX) ---
app.use('/api', (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');
    next();
});

console.log("⏳ Connecting to MongoDB...");
mongoose.connect(dbURI, { serverSelectionTimeoutMS: 30000, socketTimeoutMS: 45000 })
.then(() => {
    console.log("✅ SERVER ONLINE: DATABASE CONNECTED (SECURE MODE)");
    migrateLegacyPrices(); // src/lib/prices.js; runs once the connection is up
})
.catch((err) => console.error("❌ DB CONNECTION ERROR:", err.message));

// --- 🛡️ SECURITY LAYER 5: MAINTENANCE KILL SWITCH ---
// Lets the admin keep working on the site while it's in maintenance for everyone else
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
app.use(require('./src/routes/status'));
app.use(require('./src/routes/accounts'));
app.use(require('./src/routes/wheel'));
app.use(require('./src/routes/member'));
app.use(require('./src/routes/admin'));
app.use(require('./src/routes/drops'));
app.use(require('./src/routes/vote'));
app.use(require('./src/routes/reviews'));
app.use(require('./src/routes/newsletter'));

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
