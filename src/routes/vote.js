// The community vote: the public event, the admin's controls, casting a vote.
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../config');
const { auth, authUser, requireVerified } = require('../security/auth');
const User = require('../models/user');
const VoteEvent = require('../models/vote-event');
const { voteWindow, voteResolved, votePhase, resolveVoteEvent } = require('../lib/vote');
const { normalizePriceFields } = require('../lib/prices');
const { syncAchievements } = require('../lib/achievements');

const router = require('express').Router();

router.get('/api/vote-event', async (req, res) => {
    try {
        let event = await VoteEvent.findOne();
        if (!event) return res.json({});

        // Resolved lazily, on read, rather than by a background timer — this dyno sleeps on idle on
        // Render's free tier, so a setInterval wouldn't reliably fire. Catches an expired event, and
        // one that reached its target some other way (an event from before unlocking existed, or
        // the admin lowering the target).
        const now = new Date();
        if (!voteResolved(event)) {
            const { end } = voteWindow(event);
            try {
                if (event.targetVotes > 0 && event.currentVotes >= event.targetVotes) event = await resolveVoteEvent(event, 'unlocked');
                else if (end && now > end) event = await resolveVoteEvent(event, 'closed');
            } catch (e) {
                // Still answer with the event as it stands; the next read tries again
                console.error("Resolving vote event failed:", e);
            }
        }

        // Optional auth: this route stays public (guests must still see the drop), but when a
        // valid token is present we tell that agent whether they've already used their vote.
        let hasVoted = false;
        const header = req.headers['authorization'] || '';
        const token = header.startsWith('Bearer ') ? header.slice(7) : null;
        if (token && JWT_SECRET) {
            try {
                const decoded = jwt.verify(token, JWT_SECRET);
                hasVoted = (event.votedBy || []).some(id => id.toString() === decoded.id);
            } catch (e) { /* expired/invalid token: treat as a guest */ }
        }

        const payload = event.toObject();
        delete payload.votedBy; // never leak the voter list
        // phase/endsAt/serverNow: the tab's state comes from the server's clock, not the visitor's
        res.json({ ...payload, hasVoted, phase: votePhase(event, now), endsAt: voteWindow(event).end, serverNow: now });
    } catch (e) {
        console.error("Vote event fetch/expiry check failed:", e);
        res.json({});
    }
});
router.post('/api/vote-event', auth, async (req, res) => {
    try {
        // Validated before anything is deleted: a bad price used to wipe the running event first
        // and only then fail to create its replacement, leaving no event at all.
        const n = new VoteEvent(normalizePriceFields(req.body));
        // A new event always starts open, whatever the request body says
        n.status = 'open';
        n.pcId = undefined;
        n.resolvedAt = undefined;
        await n.validate();
        await VoteEvent.deleteMany({});
        await n.save();
        res.json(n);
    } catch (e) { console.error("Create vote-event failed:", e); res.status(400).json({ error: "Invalid vote event data" }); }
});
// Clears the VOTE tab (after a drop has been resolved, or to cancel one). A PC the event already
// turned into stays in LIVE DROPS — that's a normal PC now, edited or deleted like any other.
router.delete('/api/vote-event', auth, async (req, res) => {
    try {
        await VoteEvent.deleteMany({});
        res.json({ msg: "Deleted" });
    } catch (e) { console.error("Delete vote-event failed:", e); res.status(500).json({ error: "Server Error" }); }
});
router.post('/api/cast-vote', authUser, requireVerified, async (req, res) => {
    try {
        const event = await VoteEvent.findOne();
        if (!event) return res.status(404).json({ error: "No active vote" });

        // One vote per account — this is what makes the counter mean anything
        if ((event.votedBy || []).some(id => id.toString() === req.userId)) {
            return res.status(409).json({ error: "ALREADY VOTED", votes: event.currentVotes, hasVoted: true });
        }

        // Already unlocked or closed: the drop is a regular PC in LIVE DROPS now
        if (voteResolved(event)) {
            return res.status(409).json({ error: "VOTING HAS CLOSED", code: "VOTE_CLOSED", phase: event.status, pcId: event.pcId, votes: event.currentVotes });
        }

        // The client disables the button outside the window, but the API has to enforce it too
        const { start, end } = voteWindow(event);
        if (start) {
            const now = new Date();
            if (now < start) return res.status(403).json({ error: "VOTING HAS NOT OPENED YET", code: "VOTE_NOT_OPEN" });
            if (now > end) return res.status(409).json({ error: "VOTING HAS CLOSED", code: "VOTE_CLOSED" });
        }

        // Read-modify-write on the document lost votes under concurrency: two requests landing
        // together both read the same currentVotes and the second save overwrote the first. One
        // atomic update instead, with "hasn't voted yet" — and "still open" — as part of the match,
        // so the database, not a prior read, enforces one vote per account and no votes after unlock.
        const updated = await VoteEvent.findOneAndUpdate(
            { _id: event._id, votedBy: { $ne: req.userId }, status: { $nin: ['unlocked', 'closed'] } },
            { $addToSet: { votedBy: req.userId }, $inc: { currentVotes: 1 } },
            { new: true }
        );
        if (!updated) {
            // Matched nothing: either this account's vote landed between the check above and here
            // (double-click, two tabs), or the vote just before this one unlocked the drop.
            const fresh = await VoteEvent.findById(event._id).select('currentVotes status pcId');
            if (fresh && voteResolved(fresh)) {
                return res.status(409).json({ error: "VOTING HAS CLOSED", code: "VOTE_CLOSED", phase: fresh.status, pcId: fresh.pcId, votes: fresh.currentVotes });
            }
            return res.status(409).json({ error: "ALREADY VOTED", votes: fresh?.currentVotes ?? event.currentVotes, hasVoted: true });
        }

        // This vote reached the target: the drop unlocks now and goes straight to LIVE DROPS
        let unlocked = null;
        if (updated.targetVotes > 0 && updated.currentVotes >= updated.targetVotes) {
            // The vote itself is already counted; if creating the PC fails, the next GET retries the
            // unlock (resolveVoteEvent released its claim), so this must not turn into a failed vote.
            try { unlocked = await resolveVoteEvent(updated, 'unlocked'); }
            catch (e) { console.error("Unlocking vote drop failed (will retry on next read):", e); }
        }

        // Counted on the account as well as the event, because the event is deleted when it
        // expires — see the votesCast comment on userSchema.
        const user = await User.findById(req.userId);
        let profile = null;
        if (user) {
            user.votesCast = (user.votesCast || 0) + 1;
            await user.save();
            profile = await syncAchievements(user);
        }

        res.json({
            votes: updated.currentVotes, hasVoted: true, profile,
            // The client plays the "unlocked → LIVE DROPS" sequence when this vote is the one that did it
            phase: unlocked ? unlocked.status : 'open',
            pcId: unlocked ? unlocked.pcId : undefined
        });
    } catch (e) {
        console.error("Cast vote failed:", e);
        res.status(500).json({ error: "Server Error" });
    }
});

module.exports = router;
