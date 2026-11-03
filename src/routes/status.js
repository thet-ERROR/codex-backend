// Public status (maintenance, prices, diagnostics) and the admin's global settings.
const { ALLOWED_ORIGINS, isOriginAllowed } = require('../security/cors');
const { auth } = require('../security/auth');
const { DEFAULT_VOTE_INFO_EN, DEFAULT_VOTE_INFO_EL, SiteConfig, getSiteConfig } = require('../models/site-config');
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
        await config.save();
        res.json({ success: true, config });
    } catch (e) { console.error("Save site-config failed:", e); res.status(500).json({ error: "Server Error" }); }
});

module.exports = router;
