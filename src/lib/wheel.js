const crypto = require('crypto');
const User = require('../models/user');

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

module.exports = { WHEEL_SLICES, WHEEL_COOLDOWN_MS, COUPON_PERCENT, COUPON_DAYS, spinsInFlight, wheelStatus, couponsFor, newCouponCode };
