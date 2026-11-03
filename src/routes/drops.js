// The PC catalogue: the public list (from memory) and the admin's edits, reviews included.
const { auth } = require('../security/auth');
const { asString } = require('../lib/validation');
const PC = require('../models/pc');
const { CACHE_TTL_MS, caches } = require('../models/cache');
const { normalizePriceFields } = require('../lib/prices');

const router = require('express').Router();

router.get('/api/drops', async (req, res) => {
    try {
        if (!caches.drops || Date.now() - caches.drops.at >= CACHE_TTL_MS) {
            // Full documents (not lean), so schema defaults still fill fields older PCs never had;
            // serialised once here, exactly as res.json() did, then reused until the next write
            caches.drops = { body: JSON.stringify(await PC.find()), at: Date.now() };
        }
        res.type('application/json').send(caches.drops.body);
    }
    catch (e) { console.error("Fetch drops failed:", e); res.status(500).json({ error: "Server Error" }); }
});
router.post('/api/drops', auth, async (req, res) => {
    try { const n = new PC(normalizePriceFields(req.body)); await n.save(); res.json(n); }
    catch (e) { console.error("Create drop failed:", e); res.status(400).json({ error: "Invalid system data" }); }
});
router.put('/api/drops/:id', auth, async (req, res) => {
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
router.post('/api/drops/:id/reviews', auth, async (req, res) => {
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

router.delete('/api/drops/:id/reviews/:reviewId', auth, async (req, res) => {
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
router.delete('/api/drops/:id', auth, async (req, res) => {
    try {
        const deleted = await PC.findByIdAndDelete(req.params.id);
        if (!deleted) return res.status(404).json({ error: "PC not found" });
        res.json({ msg: "Deleted" });
    } catch (e) { console.error("Delete drop failed:", e); res.status(400).json({ error: "Invalid id" }); }
});

module.exports = router;
