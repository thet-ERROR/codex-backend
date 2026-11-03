// The daily wheel, and the admin's coupon lookup / redeem.
const crypto = require('crypto');
const { auth, authUser, requireVerified } = require('../security/auth');
const User = require('../models/user');
const { WHEEL_SLICES, WHEEL_COOLDOWN_MS, COUPON_PERCENT, COUPON_DAYS, spinsInFlight, wheelStatus, couponsFor, newCouponCode } = require('../lib/wheel');

const router = require('express').Router();

router.get('/api/wheel', authUser, requireVerified, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: "User not found" });
        res.json({ ...wheelStatus(user), coupons: couponsFor(user), unlockedColors: user.unlockedColors || [] });
    } catch (e) { console.error("Wheel status failed:", e); res.status(500).json({ error: "Server Error" }); }
});

router.post('/api/wheel/spin', authUser, requireVerified, async (req, res) => {
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
router.get('/api/admin/coupons/:code', auth, async (req, res) => {
    try {
        const code = String(req.params.code || '').trim().toUpperCase();
        const user = await User.findOne({ 'coupons.code': code }).select('username email coupons');
        const c = user && user.coupons.find(x => x.code === code);
        if (!c) return res.status(404).json({ error: "Coupon not found" });
        res.json({ code: c.code, percent: c.percent, username: user.username, email: user.email, issuedAt: c.issuedAt, expiresAt: c.expiresAt, usedAt: c.usedAt || null, expired: c.expiresAt <= new Date() });
    } catch (e) { console.error("Coupon lookup failed:", e); res.status(500).json({ error: "Server Error" }); }
});

router.post('/api/admin/coupons/:code/redeem', auth, async (req, res) => {
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

module.exports = router;
