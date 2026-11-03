// A member's wishlist and the badges the UI reports.
const { authUser, requireVerified } = require('../security/auth');
const { asString } = require('../lib/validation');
const User = require('../models/user');
const { CLIENT_ACHIEVEMENT_IDS, syncAchievements } = require('../lib/achievements');

const router = require('express').Router();

router.post('/api/wishlist/:pcId', authUser, requireVerified, async (req, res) => {
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

router.delete('/api/wishlist/:pcId', authUser, requireVerified, async (req, res) => {
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
router.post('/api/achievements', authUser, requireVerified, async (req, res) => {
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

module.exports = router;
