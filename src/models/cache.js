// --- Read caches (in memory, one dyno) ---
// GET /api/drops is on every page load and used to read and serialise every PC with all its reviews
// each time; the maintenance check read SiteConfig on EVERY api request. Both now come from memory.
// A cache is only safe if no write can leave it stale (stock, prices, a new review), so instead of
// clearing it in each route that writes — seven of them, one inside the vote unlock — the models
// clear it themselves, on every kind of write mongoose can make. The TTL is only a backstop for a
// write made outside this process (someone editing the database by hand).
const CACHE_TTL_MS = 30 * 1000;
const WRITE_HOOKS = ['save', 'updateOne', 'updateMany', 'findOneAndUpdate', 'findOneAndDelete', 'findOneAndReplace', 'replaceOne', 'deleteOne', 'deleteMany', 'insertMany'];
// One shared object rather than two variables: the models clear these and the read paths (the
// /api/drops route, getSiteConfig) fill them, from different files.
const caches = {
    drops: null,      // { body: JSON string, at }
    siteConfig: null  // { config: lean doc or null, at }
};
const clearDropsCache = () => { caches.drops = null; };
const clearSiteConfigCache = () => { caches.siteConfig = null; };

module.exports = { CACHE_TTL_MS, WRITE_HOOKS, caches, clearDropsCache, clearSiteConfigCache };
