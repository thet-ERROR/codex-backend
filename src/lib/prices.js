const PC = require('../models/pc');
const VoteEvent = require('../models/vote-event');

// --- 💶 PRICES ---
// Reads the free-text prices the admin panel used to store ("340", "€340", "1.200", "449,99€").
// The last separator is a decimal point only when one or two digits follow it; three digits means
// a thousands separator. Returns integer cents, or null when there's no number in there at all.
function parseLegacyPriceToCents(value) {
    if (typeof value === 'number') return Number.isFinite(value) && value >= 0 ? Math.round(value * 100) : null;
    const s = String(value ?? '').replace(/[^\d.,]/g, '');
    if (!/\d/.test(s)) return null;
    const lastSep = Math.max(s.lastIndexOf('.'), s.lastIndexOf(','));
    let whole = s, frac = '';
    if (lastSep !== -1) {
        const after = s.slice(lastSep + 1);
        if (after.length === 1 || after.length === 2) { whole = s.slice(0, lastSep); frac = after; }
    }
    const cents = parseInt(whole.replace(/[.,]/g, '') || '0', 10) * 100 + (frac ? parseInt(frac.padEnd(2, '0'), 10) : 0);
    return Number.isFinite(cents) ? cents : null;
}

// Applied to every admin write of a PC or vote event. priceCents wins; a body that only has the
// old `price` (a stale admin tab from before this change) is converted instead of rejected. Either
// way `price` is rewritten as a whole-euro mirror for any old frontend still reading it — whole
// euros because that code strips every non-digit, so "449.99" would have read as 44999.
function normalizePriceFields(body) {
    if (!body || typeof body !== 'object') return body;
    let cents = null;
    if (body.priceCents !== undefined && body.priceCents !== null && body.priceCents !== '') {
        const n = Number(body.priceCents);
        cents = Number.isInteger(n) && n >= 0 ? n : null;
        if (cents === null) throw new Error('priceCents must be a non-negative integer');
    } else if (body.price !== undefined) {
        cents = parseLegacyPriceToCents(body.price);
    }
    if (cents !== null) {
        body.priceCents = cents;
        body.price = String(Math.round(cents / 100));
    }
    return body;
}

// One-time backfill, safe to run on every boot: only touches documents that still have no
// priceCents, and only ever adds a field — the original `price` text is left as it was.
async function migrateLegacyPrices() {
    for (const Model of [PC, VoteEvent]) {
        try {
            const docs = await Model.find({ priceCents: { $exists: false } }).select('price');
            let migrated = 0;
            for (const doc of docs) {
                const cents = parseLegacyPriceToCents(doc.price);
                if (cents === null) {
                    console.warn(`⚠️ ${Model.modelName} ${doc._id}: price "${doc.price}" has no number in it — left for the admin to fix`);
                    continue;
                }
                await Model.updateOne({ _id: doc._id }, { $set: { priceCents: cents } });
                migrated++;
            }
            if (migrated) console.log(`💶 Migrated ${migrated} ${Model.modelName} price(s) to priceCents`);
        } catch (e) { console.error(`Price migration for ${Model.modelName} failed:`, e); }
    }
}

module.exports = { parseLegacyPriceToCents, normalizePriceFields, migrateLegacyPrices };
