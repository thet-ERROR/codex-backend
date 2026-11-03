const mongoose = require('mongoose');

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

module.exports = User;
