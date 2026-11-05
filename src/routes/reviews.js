// Mission codes (the code in the box) and the reviews posted with them.
const crypto = require('crypto');
const { authLimiter } = require('../security/rate-limits');
const { auth, optionalUserId } = require('../security/auth');
const { asString } = require('../lib/validation');
const PC = require('../models/pc');
const User = require('../models/user');
const ReviewTicket = require('../models/review-ticket');
const { ticketWindow } = require('../lib/order-lifecycle');
const { xpOf, rankFor } = require('../lib/achievements');

const router = require('express').Router();

router.post('/api/generate-code', auth, async (req, res) => {
    try {
        const { pcId, pcName } = req.body;
        // 5 bytes = 10 hex chars ≈ 1.1 trillion combinations (was 3 bytes / 6 chars ≈ 16.7
        // million) — the smaller space was small enough that a distributed brute-force against
        // /api/check-code could plausibly land on a real pending code within its lifetime.
        const code = 'CDX-' + crypto.randomBytes(5).toString('hex').toUpperCase();
        const ticket = new ReviewTicket({ code, pcId, pcName });
        await ticket.save();
        res.json(ticket);
    } catch (e) { console.error("Generate code failed:", e); res.status(500).json({ error: "Server Error" }); }
});
router.get('/api/tickets', auth, async (req, res) => { const tickets = await ReviewTicket.find().sort({ generatedAt: -1 }); res.json(tickets); });

router.post('/api/activate-ticket/:id', auth, async (req, res) => {
    try {
        const ticket = await ReviewTicket.findById(req.params.id);
        if(ticket) { ticket.status = 'active'; await ticket.save(); res.json({ success: true }); } 
        else { res.status(404).json({ error: "Ticket not found" }); }
    } catch(e) { res.status(500).json({ error: "Server error" }); }
});

// How a code's state is answered. The storefront reads valid / activated / expired / timeLeft.
function codeAnswer(w) {
    if (w.state === 'invalid') return { status: 404, body: { valid: false, msg: "❌ INVALID CODE" } };
    if (w.state === 'used') return { status: 409, body: { valid: false, msg: "⚠️ ALREADY REDEEMED" } };
    if (w.state === 'waiting') return { status: 200, body: { valid: true, activated: false, pcName: w.pcName } };
    const expired = w.state === 'expired';
    return { status: 200, body: { valid: true, activated: true, expired, pcName: w.pcName, ...(expired ? {} : { timeLeft: w.expiresAt - new Date() }) } };
}

// Read-only on purpose. This used to start the 48h validation window as a side effect of a GET
// — meaning any automated client that fetches URLs (a chat app's link-preview bot, an uptime
// monitor, a crawler, a browser prefetch) could silently burn a customer's window before they
// ever typed the code in. GET now only ever reports status; POST /activate (below) is the only
// thing that changes anything, and only fires from an explicit user action in the frontend.
// (Always 200 here: the storefront reads valid: false as "wrong code".)
router.get('/api/check-code/:code', authLimiter, async (req, res) => {
    try {
        const ticket = await ReviewTicket.findOne({ code: asString(req.params.code) });
        res.json(codeAnswer(await ticketWindow(ticket)).body);
    } catch(e) { console.error(e); res.status(500).json({ valid: false, msg: "SERVER ERROR" }); }
});

// The customer entering the code. A code from an order's box marks that order delivered if the admin
// hadn't yet (only whoever opened the box has it) and is open for reviews for two weeks from delivery;
// a hand-made code starts its 48 hours. Idempotent: entering it again never resets or extends anything.
router.post('/api/check-code/:code/activate', authLimiter, async (req, res) => {
    try {
        const ticket = await ReviewTicket.findOne({ code: asString(req.params.code) });
        const a = codeAnswer(await ticketWindow(ticket, { activate: true }));
        res.status(a.status).json(a.body);
    } catch(e) { console.error(e); res.status(500).json({ valid: false, msg: "SERVER ERROR" }); }
});

router.post('/api/submit-review', authLimiter, async (req, res) => {
    try {
        const code = asString(req.body.code).trim();
        const user = asString(req.body.user).trim().slice(0, 40);
        const text = asString(req.body.text).trim().slice(0, 1000);
        const rating = Number(req.body.rating);

        if (!code || !user || !text) return res.status(400).json({ error: "All fields required" });

        // The display name is shown in the admin panel and on the storefront. Both escape it, so
        // this is the second layer — it keeps the value safe for any future consumer that is not an
        // escaped HTML template (a CSV export, an email body). Only the NAME is restricted: review
        // text legitimately contains angle brackets in this shop ("temps <70°C"), and accented and
        // Greek letters stay allowed in both.
        if (/[<>]/.test(user)) {
            return res.status(400).json({ error: "Name cannot contain < or > characters" });
        }
        if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
            return res.status(400).json({ error: "Rating must be a whole number from 1 to 5" });
        }

        const ticket = await ReviewTicket.findOne({ code });
        if (!ticket || ticket.status === 'void') return res.status(400).json({ error: "Invalid Ticket" });
        // Previously any known code could be replayed to post unlimited reviews
        if (ticket.status === 'used') return res.status(409).json({ error: "This code has already been redeemed" });

        // The same window /api/check-code reports — checked here too, on the write. Submitting counts
        // as entering the code, so an order code marks its box delivered here as well.
        const w = await ticketWindow(ticket, { activate: true });
        if (w.state === 'invalid') return res.status(400).json({ error: "Invalid Ticket" });
        if (w.state === 'expired') return res.status(403).json({ error: "This code has expired" });
        if (w.state !== 'open') return res.status(409).json({ error: "This code can't be used yet" });

        if (!await PC.exists({ _id: ticket.pcId })) return res.status(404).json({ error: "PC not found" });

        // Claim the ticket atomically BEFORE writing the review. The old order was read status ->
        // push review -> mark used, so two submits with the same code landing together (a double
        // tap, a retried request) both passed the `status === 'used'` check above and both posted.
        // Putting "not yet used" in the match means only one request can ever flip it.
        const claimed = await ReviewTicket.findOneAndUpdate(
            { _id: ticket._id, status: { $ne: 'used' } },
            { $set: { status: 'used' } }
        );
        if (!claimed) return res.status(409).json({ error: "This code has already been redeemed" });

        // Signed in: the review carries the reviewer's rank at this moment, for the badge by the name
        // (the name itself is free text, so the badge is the account's, read here from the session)
        const reviewerId = optionalUserId(req);
        let reviewerRank;
        if (reviewerId) {
            try {
                const reviewer = await User.findById(reviewerId).select('achievements').lean();
                if (reviewer) reviewerRank = rankFor(xpOf(reviewer.achievements)).rank;
            } catch (e) { console.error("Reading reviewer rank failed:", e); }
        }

        // $push rather than load-modify-save of the whole PC document: a concurrent admin edit of
        // this same PC then can't be overwritten by this write, or vice versa.
        const pushed = await PC.updateOne(
            { _id: ticket.pcId },
            { $push: { reviews: { user, rating, text, verified: true, date: new Date(), ...(reviewerRank ? { rank: reviewerRank } : {}) } } }
        );
        if (!pushed.matchedCount) {
            // The PC was deleted between the check above and here — give the customer their code back
            await ReviewTicket.updateOne({ _id: ticket._id }, { $set: { status: ticket.status } });
            return res.status(404).json({ error: "PC not found" });
        }

        // The route stays open to guests — a mission code is the proof of purchase, not a login —
        // but when the browser does have a session, credit the account so 'field_report' becomes
        // earnable. The ticket is already marked used above, so this can't be farmed.
        if (reviewerId) {
            try {
                await User.updateOne({ _id: reviewerId }, { $inc: { reviewsWritten: 1 } });
            } catch (e) { console.error("Crediting review to account failed:", e); }
        }

        res.json({ success: true });
    } catch (e) {
        console.error("Submit review failed:", e);
        res.status(500).json({ error: "Server Error" });
    }
});

module.exports = router;
