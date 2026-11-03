const mongoose = require('mongoose');
const { WRITE_HOOKS, clearDropsCache } = require('./cache');

// --- SCHEMAS ---
const pcSchema = new mongoose.Schema({
    // priceCents is the source of truth (integer euro cents — no float rounding, no parsing a
    // free-text "€1.200" to do arithmetic). `price` is the legacy free-text field: kept rather than
    // dropped so nothing already in the database is lost, and mirrored from priceCents on every
    // write so a browser still running the old frontend mid-deploy doesn't break. See
    // normalizePriceFields() and migrateLegacyPrices().
    name: String, price: String, priceCents: { type: Number, min: 0 }, description: String, lore: String, loreEl: String, stock: { type: Number, default: 1 },
    images: [String], status: { type: String, default: 'available' }, category: { type: String, default: 'drop' },    
    multitasking: { type: Number, default: 0 },
    specs: { cpu: String, gpu: String, ram: String, ssd: String, mobo: String, psu: String, case: String },
    // Benchmark scores for the CPU and the GPU (one scale for every PC, e.g. PassMark), typed in by
    // the admin. The VS window turns two of them into a real "+X%" — a CPU's name alone can't say
    // how fast it is. Unset = no percentage shown for that part.
    benchScores: { cpu: { type: Number, min: 0 }, gpu: { type: Number, min: 0 } },
    specDetails: { type: Map, of: String, default: {} },
    fps: [{ game: String, score: Number }],
    // rank: the reviewer's rank when they wrote it, if they were signed in (the badge by the name)
    reviews: [{ user: String, text: String, rating: Number, rank: String, date: { type: Date, default: Date.now } }],
    votes: { type: Number, default: 0 },
    // Set on the PC a community vote turned into a regular listing (resolveVoteEvent) — the card
    // shows a COMMUNITY DROP badge for it.
    communityDrop: { type: Boolean, default: false },
    // Early access: a drop the community unlocked before its timer ran out can be ordered only by
    // signed-in members until then (the vote's end), and by everyone after. Unset = public.
    membersOnlyUntil: Date,
    // Per-build purchasable extras. Every sub-field has a default so PCs created before this
    // existed still render (the frontend also guards with optional chaining).
    options: {
        storage: {
            enabled: { type: Boolean, default: true },
            hdd: { type: Number, default: 50 },   // 0 hides that line from the dropdown
            ssd: { type: Number, default: 80 }
        },
        // Pro Config price is global (SiteConfig.proConfigPrice) — the service is identical on
        // every build, so only availability is per-PC.
        proConfig: { enabled: { type: Boolean, default: false } },
        paint: {
            enabled: { type: Boolean, default: false },
            colorName: { type: String, default: '' },
            colorNameEl: { type: String, default: '' },
            colorHex: { type: String, default: '#1a1a1a' },
            price: { type: Number, default: 40 },
            leadTimeHours: { type: Number, default: 48 },
            images: { type: [String], default: [] }
        }
    }
});

pcSchema.post(WRITE_HOOKS, clearDropsCache);

const PC = mongoose.model('PC', pcSchema);

module.exports = PC;
