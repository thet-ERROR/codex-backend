const mongoose = require('mongoose');

const voteEventSchema = new mongoose.Schema({
    title: String,
    image: String,
    targetVotes: Number,
    currentVotes: { type: Number, default: 0 },
    // One vote per account: the ledger of who already voted. Never sent to the browser — the
    // public endpoint replaces it with a plain hasVoted boolean for the requesting agent.
    votedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    startDate: Date,
    durationDays: Number,
    price: String,
    priceCents: { type: Number, min: 0 }, // same arrangement as pcSchema — see the comment there
    specs: { cpu: String, gpu: String, ram: String, ssd: String, mobo: String, psu: String, case: String },
    // Mirrors the PC fields so the vote drop can open in the same inspect card as every other
    // build (flip to specs, show FPS, lore on the front).
    description: String,
    lore: String,
    loreEl: String,
    multitasking: { type: Number, default: 0 },
    fps: [{ game: String, score: Number }],
    // How the vote ended. 'open' while it runs; 'unlocked' when the community reached the target;
    // 'closed' when the timer ran out first. Either way the drop becomes a regular PC in LIVE DROPS
    // (pcId) and the event stays on the VOTE tab, pointing there, until the admin starts the next
    // one. Events saved before this field existed have no status and are treated as 'open'.
    status: { type: String, enum: ['open', 'unlocked', 'closed'], default: 'open' },
    pcId: { type: mongoose.Schema.Types.ObjectId, ref: 'PC' },
    resolvedAt: Date
});
const VoteEvent = mongoose.model('VoteEvent', voteEventSchema);

module.exports = VoteEvent;
