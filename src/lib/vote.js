// The community vote's clock and its outcome (a vote that unlocks or runs out becomes a PC).
const mongoose = require('mongoose');
const PC = require('../models/pc');
const VoteEvent = require('../models/vote-event');

// [start, end] of a vote event's window; end is null when the event has no start date
function voteWindow(event) {
    if (!event.startDate) return { start: null, end: null };
    const start = new Date(event.startDate);
    return { start, end: new Date(start.getTime() + (event.durationDays || 0) * 24 * 60 * 60 * 1000) };
}

function voteResolved(event) {
    return event.status === 'unlocked' || event.status === 'closed';
}

// What the VOTE tab should show, decided here rather than from the visitor's own clock
function votePhase(event, now) {
    if (voteResolved(event)) return event.status;
    const { start } = voteWindow(event);
    return start && now < start ? 'upcoming' : 'open';
}

// Ends a community vote by turning the drop into a regular PC in LIVE DROPS — when the target is
// reached ('unlocked') or when the timer runs out without it ('closed'). The event is CLAIMED
// atomically first: only the request that flips it out of 'open' creates the PC, so a burst of last
// votes, or GETs queued while the free dyno wakes up, can't list the same drop twice (the old
// expiry code could). Every field the inspect card uses is copied — the old conversion dropped the
// lore, description and FPS.
async function resolveVoteEvent(event, outcome) {
    const pcId = new mongoose.Types.ObjectId();
    const claimed = await VoteEvent.findOneAndUpdate(
        { _id: event._id, status: { $nin: ['unlocked', 'closed'] } },
        { $set: { status: outcome, pcId, resolvedAt: new Date() } },
        { new: true }
    );
    if (!claimed) return (await VoteEvent.findById(event._id)) || event; // another request got there first

    const ev = claimed.toObject();
    const hasPrice = Number.isFinite(ev.priceCents) && ev.priceCents > 0;
    const { end } = voteWindow(claimed);
    try {
        await new PC({
            _id: pcId,
            name: ev.title,
            price: hasPrice ? ev.price : '',
            priceCents: hasPrice ? ev.priceCents : undefined,
            description: ev.description || '',
            lore: ev.lore || '',
            loreEl: ev.loreEl || '',
            images: ev.image ? [ev.image] : [],
            specs: ev.specs || {},
            fps: (ev.fps || []).map(f => ({ game: f.game, score: f.score })),
            multitasking: ev.multitasking || 0,
            // No price yet: listed as COMING SOON (shown, not orderable) until the admin sets one,
            // instead of an orderable PC at 0,00 €
            status: hasPrice ? 'available' : 'coming',
            category: 'drop',
            stock: 1,
            communityDrop: true,
            // Unlocked in time: members get it first, until the vote would have ended
            membersOnlyUntil: (outcome === 'unlocked' && end && end > new Date()) ? end : undefined
        }).save();
    } catch (e) {
        // Release the claim so the next read retries, instead of pointing at a PC that doesn't exist
        await VoteEvent.updateOne({ _id: claimed._id }, { $set: { status: 'open' }, $unset: { pcId: 1, resolvedAt: 1 } });
        throw e;
    }
    return claimed;
}

module.exports = { voteWindow, voteResolved, votePhase, resolveVoteEvent };
