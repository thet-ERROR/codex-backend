// Public status (maintenance, prices, diagnostics) and the admin's global settings.
const { ALLOWED_ORIGINS, isOriginAllowed } = require('../security/cors');
const { auth } = require('../security/auth');
const { ORDERS_LIVE } = require('../config');
const { DEFAULT_VOTE_INFO_EN, DEFAULT_VOTE_INFO_EL, MIN_RETURN_DAYS, SiteConfig, getSiteConfig, orderSettings } = require('../models/site-config');
const { MAILJET_API_KEY, MAILJET_SECRET_KEY, EMAIL_FROM } = require('../lib/email');

const router = require('express').Router();

router.get('/api/status', async (req, res) => {
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
        // The checkout reads these: whether orders are real yet (the DEMO notice), the return window,
        // and the hand-delivery areas and map circle
        orders: { live: ORDERS_LIVE, ...orderSettings(config) },
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

router.get('/api/site-config', auth, async (req, res) => {
    try {
        let config = await SiteConfig.findOne();
        if (!config) config = await new SiteConfig().save();
        res.json(config);
    } catch (e) { console.error("Get site-config failed:", e); res.status(500).json({ error: "Server Error" }); }
});

router.post('/api/site-config', auth, async (req, res) => {
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
        // Order settings. Anything out of range is refused outright rather than clamped, so the admin
        // sees their value wasn't taken instead of finding a different one saved.
        const { returnDays, handDeliveryAreas, handDeliveryCenter, handDeliveryRadiusKm } = req.body;
        if (returnDays !== undefined) {
            const n = Number(returnDays);
            if (!Number.isInteger(n) || n < MIN_RETURN_DAYS || n > 365) {
                return res.status(400).json({ error: `Return window must be a whole number of days, ${MIN_RETURN_DAYS} to 365` });
            }
            config.returnDays = n;
        }
        if (handDeliveryAreas !== undefined) {
            const areas = Array.isArray(handDeliveryAreas)
                ? handDeliveryAreas.map(a => (typeof a === 'string' ? a.trim() : '')).filter(Boolean)
                : null;
            if (!areas || !areas.length || areas.length > 50 || areas.some(a => a.length > 60 || /[<>]/.test(a))) {
                return res.status(400).json({ error: "Hand-delivery areas: 1 to 50 names, each up to 60 characters" });
            }
            config.handDeliveryAreas = [...new Set(areas)];
        }
        if (handDeliveryCenter !== undefined) {
            const lat = Number(handDeliveryCenter?.lat), lng = Number(handDeliveryCenter?.lng);
            if (!Number.isFinite(lat) || !Number.isFinite(lng) || Math.abs(lat) > 90 || Math.abs(lng) > 180) {
                return res.status(400).json({ error: "Map centre must be a latitude and a longitude" });
            }
            config.handDeliveryCenter = { lat, lng };
        }
        if (handDeliveryRadiusKm !== undefined) {
            const km = Number(handDeliveryRadiusKm);
            if (!Number.isFinite(km) || km < 1 || km > 100) return res.status(400).json({ error: "Delivery radius must be 1 to 100 km" });
            config.handDeliveryRadiusKm = km;
        }
        await config.save();
        res.json({ success: true, config });
    } catch (e) { console.error("Save site-config failed:", e); res.status(500).json({ error: "Server Error" }); }
});

module.exports = router;
