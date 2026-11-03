// Drop-alert sign-ups.
const { authLimiter } = require('../security/rate-limits');
const { auth } = require('../security/auth');
const { asString, isValidEmail } = require('../lib/validation');
const Newsletter = require('../models/newsletter');

const router = require('express').Router();

router.post('/api/newsletter', authLimiter, async (req, res) => {
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
router.get('/api/newsletter', auth, async (req, res) => {
    try { res.json(await Newsletter.find().sort({ date: -1 })); }
    catch (e) { console.error("Fetch newsletter failed:", e); res.status(500).json({ error: "Server Error" }); }
});

module.exports = router;
