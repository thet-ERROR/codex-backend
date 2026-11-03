const mongoose = require('mongoose');
const { CACHE_TTL_MS, WRITE_HOOKS, caches, clearSiteConfigCache } = require('./cache');

// Default "How it works" text for the VOTE tab, until the admin writes their own (GLOBAL SETTINGS).
// One copy, used both as the schema default and as the /api/status fallback.
const DEFAULT_VOTE_INFO_EN = "Community drops: the network votes to unlock a mystery PC.\n\n1. Voting opens on the date shown.\n2. Every signed-in agent with a verified email gets one vote.\n3. Reach the target before time runs out and the PC unlocks straight into Live Drops — signed-in members can order it first, until the timer would have ended; then it is open to everyone.\n4. If time runs out first, the PC still comes to Live Drops when voting closes.";
const DEFAULT_VOTE_INFO_EL = "Κοινοτικά drops: η κοινότητα ψηφίζει για να ξεκλειδώσει ένα μυστηριώδες PC.\n\n1. Η ψηφοφορία ανοίγει την ημερομηνία που φαίνεται.\n2. Κάθε συνδεδεμένος πράκτορας με επιβεβαιωμένο email έχει μία ψήφο.\n3. Αν μαζευτούν οι ψήφοι πριν λήξει ο χρόνος, το PC ξεκλειδώνει και μπαίνει αμέσως στα Live Drops — με προτεραιότητα για τα συνδεδεμένα μέλη μέχρι να έληγε ο χρόνος, και μετά για όλους.\n4. Αν λήξει πρώτα ο χρόνος, το PC έρχεται κι αυτό στα Live Drops με το κλείσιμο της ψηφοφορίας.";

const siteConfigSchema = new mongoose.Schema({
    maintenanceMode: { type: Boolean, default: false },
    maintenanceMessage: { type: String, default: "PHOENIX CODEX is currently undergoing scheduled maintenance. We'll be back online shortly." },
    // Pro Config is the same service on every build, so its price lives here rather than per-PC.
    // Exposed publicly through /api/status (the frontend needs it to price the option).
    proConfigPrice: { type: Number, default: 30 },
    // The "?" button on the vote card explaining how community drops work. Lives here rather than
    // on VoteEvent because VoteEvent is deleted and recreated wholesale every time an event starts
    // (see POST /api/vote-event) — the admin would have to retype this explainer for every single
    // drop otherwise. Split EN/EL to match every other piece of admin-authored prose in this schema
    // (PC.lore/loreEl, VoteEvent.lore/loreEl) rather than being the one exception. Rendered with the
    // browser's own line-break handling (see .vote-info-text in vote.css), not as HTML, so no
    // escaping is needed and no markup can be injected through it.
    voteInfoText: {
        type: String,
        default: DEFAULT_VOTE_INFO_EN
    },
    voteInfoTextEl: {
        type: String,
        default: DEFAULT_VOTE_INFO_EL
    }
});
siteConfigSchema.post(WRITE_HOOKS, clearSiteConfigCache);
const SiteConfig = mongoose.model('SiteConfig', siteConfigSchema);

// The site config for READING (maintenance check, /api/status). Read-only: the admin routes that
// change it still load the real document. null when the admin panel has never created one.
async function getSiteConfig() {
    if (caches.siteConfig && Date.now() - caches.siteConfig.at < CACHE_TTL_MS) return caches.siteConfig.config;
    // A full document turned into a plain object, not .lean(): lean skips the schema defaults, and an
    // older config saved before a field existed (the maintenance message, say) would come back without it
    const doc = await SiteConfig.findOne();
    const config = doc ? doc.toObject() : null;
    caches.siteConfig = { config, at: Date.now() };
    return config;
}

module.exports = { DEFAULT_VOTE_INFO_EN, DEFAULT_VOTE_INFO_EL, SiteConfig, getSiteConfig };
