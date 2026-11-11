const User = require('../models/user');
const Newsletter = require('../models/newsletter');

// --- 🏅 ACHIEVEMENTS, XP & RANKS ---
// The previous version took the client at its word: POST /api/achievements accepted any string as
// an id and stored it, so a single fetch() from devtools granted anything. Ranks are about to be
// built on top of this, so the split below is the whole point of the rewrite:
//
//   source: 'server'  — the API works it out from its own data on every sync. The client cannot
//                       grant one, and cannot keep one it no longer qualifies for.
//   source: 'client'  — a UI action the server genuinely cannot observe (a card flip, a wheel
//                       spin). Still whitelisted by id so nothing can be invented, and worth
//                       little XP each, so the honest half of the ladder is the one that counts:
//                       the everyday client badges together are worth about one 'field_report' (the terminal secrets add a token 10 each).
//
// XP lives here and nowhere else. The frontend renders whatever /api/me reports, so these numbers
// can be retuned without shipping a matching frontend change.
const ACHIEVEMENTS = [
    // Verified from account state
    { id: 'recruited',          xp: 25,  source: 'server' },
    { id: 'identity_confirmed', xp: 75,  source: 'server' },
    { id: 'first_target',       xp: 25,  source: 'server' },
    { id: 'collector',          xp: 75,  source: 'server' },
    { id: 'hoarder',            xp: 150, source: 'server' },
    { id: 'vote_caster',        xp: 50,  source: 'server' },
    { id: 'kingmaker',          xp: 150, source: 'server' },
    { id: 'signal_intercepted', xp: 25,  source: 'server' },
    { id: 'field_report',       xp: 200, source: 'server' },
    { id: 'veteran',            xp: 100, source: 'server' },
    { id: 'founder',            xp: 100, source: 'server' },
    // Reported by the UI
    { id: 'first_loot',         xp: 25,  source: 'client' },
    { id: 'comparator',         xp: 25,  source: 'client' },
    { id: 'deep_scan',          xp: 25,  source: 'client' },
    { id: 'benchmarker',        xp: 25,  source: 'client' },
    { id: 'hacker',             xp: 25,  source: 'client' },
    { id: 'terminal_access',    xp: 25,  source: 'client' },
    { id: 'polyglot',           xp: 25,  source: 'client' },
    { id: 'night_owl',          xp: 25,  source: 'client' },
    // Secrets: found by trying things in the terminal. Worth very little — they are for fun, not for rank.
    { id: 'nice_try',           xp: 10,  source: 'client' },
    { id: 'scorched_earth',     xp: 10,  source: 'client' },
    { id: 'curious_agent',      xp: 10,  source: 'client' }
];

const ACHIEVEMENT_XP = new Map(ACHIEVEMENTS.map(a => [a.id, a.xp]));
const CLIENT_ACHIEVEMENT_IDS = new Set(ACHIEVEMENTS.filter(a => a.source === 'client').map(a => a.id));

// Accounts created before this rewrite hold the three original ids. Mapped rather than dropped so
// nobody loses progress they already earned; anything else unrecognised is discarded on sync.
const LEGACY_ACHIEVEMENT_IDS = { login: 'recruited', cart: 'first_loot', vote: 'vote_caster' };

// Ascending by minXp — rankFor() walks it backwards, so the order here is what defines the ladder.
// What each rank gives, once, the first time the account reaches it (grantRankRewards): a badge (the
// rank itself — shown on the profile and next to the name on reviews), and maybe an accent colour that
// only a rank unlocks (never on the wheel) and bonus wheel spins. Decided and stored here, never by
// the browser — the same reason the wheel is server-side.
const RANKS = [
    { id: 'recruit',    minXp: 0,    rewards: {} },
    { id: 'operative',  minXp: 100,  rewards: { spins: 1 } },
    { id: 'fieldAgent', minXp: 250,  rewards: { color: 'ultraviolet' } },
    { id: 'specialist', minXp: 450,  rewards: { spins: 2 } },
    { id: 'eliteAgent', minXp: 700,  rewards: { color: 'arctic', spins: 1 } },
    { id: 'phantom',    minXp: 1000, rewards: { color: 'phantom', spins: 3 } }
];
// The ladder as the profile shows it (thresholds + rewards), sent with every profile so the frontend
// never keeps its own copy of the numbers
const RANK_LADDER = RANKS.map(r => ({ id: r.id, minXp: r.minXp, rewards: { ...r.rewards } }));

const xpOf = (achievementIds) => (achievementIds || []).reduce((sum, id) => sum + (ACHIEVEMENT_XP.get(id) || 0), 0);

// Hands out the rewards of every rank the account has reached but not been paid for yet, on the
// document (the caller saves). Each rank pays once, ever — rankRewardsClaimed — so XP dropping and
// rising again can't farm it. Returns what was granted just now, for the "rank up" notice.
function grantRankRewards(user, xp) {
    const claimed = new Set(user.rankRewardsClaimed || []);
    const granted = [];
    for (const r of RANKS) {
        if (xp < r.minXp || claimed.has(r.id)) continue;
        claimed.add(r.id);
        const g = { rank: r.id };
        if (r.rewards.color) {
            if (!(user.unlockedColors || []).includes(r.rewards.color)) user.unlockedColors.push(r.rewards.color);
            g.color = r.rewards.color;
        }
        if (r.rewards.spins) {
            user.bonusSpins = (user.bonusSpins || 0) + r.rewards.spins;
            g.spins = r.rewards.spins;
        }
        granted.push(g);
    }
    if (granted.length) user.rankRewardsClaimed = RANKS.map(r => r.id).filter(id => claimed.has(id));
    return granted;
}

function rankFor(xp) {
    let current = RANKS[0];
    for (const r of RANKS) if (xp >= r.minXp) current = r;
    const next = RANKS.find(r => r.minXp > xp) || null;
    return {
        rank: current.id,
        rankMinXp: current.minXp,
        nextRank: next ? next.id : null,
        nextRankXp: next ? next.minXp : null,
        // 0-100, measured across the current band rather than from zero, so the bar fills once per
        // promotion instead of creeping imperceptibly toward a distant maximum.
        progress: next
            ? Math.round(((xp - current.minXp) / (next.minXp - current.minXp)) * 100)
            : 100
    };
}

// Recomputes every server-verified badge from the account's own data, merges in the client-reported
// ones already banked, and writes back only if something actually changed. Returns the profile the
// frontend renders. `user` must be a full document (not a .select() projection) — it is saved here.
async function syncAchievements(user) {
    const banked = new Set(
        (user.achievements || [])
            .map(id => LEGACY_ACHIEVEMENT_IDS[id] || id)
            .filter(id => ACHIEVEMENT_XP.has(id))
    );

    const wishlistCount = (user.wishlist || []).length;
    const earned = new Set(banked);

    // Every account that exists at all has cleared this one
    earned.add('recruited');
    if (user.emailVerified) earned.add('identity_confirmed');
    if (wishlistCount >= 1) earned.add('first_target');
    if (wishlistCount >= 5) earned.add('collector');
    if (wishlistCount >= 10) earned.add('hoarder');
    if ((user.votesCast || 0) >= 1) earned.add('vote_caster');
    if ((user.votesCast || 0) >= 3) earned.add('kingmaker');
    if ((user.reviewsWritten || 0) >= 1) earned.add('field_report');
    if (user.joined && (Date.now() - new Date(user.joined).getTime()) >= 30 * 24 * 60 * 60 * 1000) {
        earned.add('veteran');
    }

    // The two that need a query run only while still unearned, so the steady state costs nothing.
    if (!earned.has('signal_intercepted')) {
        if (user.subscribed) earned.add('signal_intercepted');
        else if (await Newsletter.exists({ email: user.email })) earned.add('signal_intercepted');
    }
    if (!earned.has('founder')) {
        const earlier = await User.countDocuments({ joined: { $lt: user.joined } });
        if (earlier < 100) earned.add('founder');
    }

    // Stored in registry order so the array is stable between saves and reads predictably in the DB
    const list = ACHIEVEMENTS.map(a => a.id).filter(id => earned.has(id));
    const changed = list.length !== (user.achievements || []).length
        || list.some((id, i) => user.achievements[i] !== id);
    if (changed) user.achievements = list;

    const xp = xpOf(list);
    // Accounts that were already past a rank before rewards existed get paid on their next load
    const rankRewards = grantRankRewards(user, xp);
    if (changed || rankRewards.length) await user.save();

    return {
        achievements: list, xp, ...rankFor(xp),
        ranks: RANK_LADDER,
        bonusSpins: user.bonusSpins || 0,
        // Non-empty only on the request that paid them out — the frontend shows it once
        rankRewards
    };
}

module.exports = { CLIENT_ACHIEVEMENT_IDS, xpOf, rankFor, syncAchievements };
