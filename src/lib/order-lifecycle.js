// What happens to an order on its own, after the admin's steps: the review codes for the box, the
// customer's code proving the box arrived, closing the order once the return window has passed, and
// the "N deliveries" figure next to the reviews.
const crypto = require('crypto');
const { Order } = require('../models/order');
const ReviewTicket = require('../models/review-ticket');
const { getSiteConfig, orderSettings, deliveriesBadge } = require('../models/site-config');
const { STATUS_FLOW } = require('./orders');

const DAY_MS = 24 * 60 * 60 * 1000;
// A box code takes a review for this long after delivery (the user's choice: two weeks)
const REVIEW_DAYS = 14;
// Codes made by hand in the admin panel (sales outside the site) keep their old rule: 48 hours from
// the first time they are entered
const LEGACY_WINDOW_MS = 48 * 60 * 60 * 1000;

// 5 bytes = 10 hex characters ≈ 1.1 trillion codes (see routes/reviews.js)
const newCode = () => 'CDX-' + crypto.randomBytes(5).toString('hex').toUpperCase();

// What marking an order delivered sets, whoever does it: the date, and the return window from it
async function deliveredFields(now) {
    const { returnDays } = orderSettings(await getSiteConfig());
    return { status: 'delivered', deliveredAt: now, returnDeadline: new Date(now.getTime() + returnDays * DAY_MS) };
}

// --- the codes in the box ---
// One per PC in the order, made when it is packed (or skipped past packed), so the admin can print
// them before the box leaves. Safe to call again: an existing code is never replaced.
async function ensureOrderCodes(order) {
    if (STATUS_FLOW.indexOf(order.status) < STATUS_FLOW.indexOf('packed')) return [];
    for (let i = 0; i < order.items.length; i++) {
        const item = order.items[i];
        await ReviewTicket.updateOne(
            { orderId: order._id, itemIndex: i },
            { $setOnInsert: { code: newCode(), pcId: String(item.pcId), pcName: item.name, orderNumber: order.number, status: 'pending', generatedAt: new Date() } },
            { upsert: true }
        );
    }
    return orderCodes(order);
}
const orderCodes = (order) => ReviewTicket.find({ orderId: order._id }).sort({ itemIndex: 1 })
    .select('code pcName status itemIndex -_id').lean();
// A cancelled order's codes stop working (an unused one; a review already written stays)
const voidOrderCodes = (order) => ReviewTicket.updateMany({ orderId: order._id, status: { $ne: 'used' } }, { $set: { status: 'void' } });

// --- where a code stands ---
// { state, pcName, expiresAt? } where state is 'invalid', 'used', 'waiting' (an order code whose box
// isn't marked delivered — entering it does that), 'open' or 'expired'. With activate: true this is
// the customer entering it: an order code marks its order delivered (only whoever opened the box has
// it), a hand-made code starts its 48 hours.
async function ticketWindow(ticket, { activate = false, now = new Date() } = {}) {
    if (!ticket || ticket.status === 'void') return { state: 'invalid' };
    if (ticket.status === 'used') return { state: 'used' };
    const pcName = ticket.pcName;

    if (!ticket.orderId) {
        let firstScan = ticket.firstScan;
        if (!firstScan && activate) {
            firstScan = now;
            await ReviewTicket.updateOne({ _id: ticket._id, firstScan: null }, { $set: { firstScan, status: 'active' } });
        }
        if (!firstScan) return { state: 'waiting', pcName };
        const expiresAt = new Date(new Date(firstScan).getTime() + LEGACY_WINDOW_MS);
        return { state: now > expiresAt ? 'expired' : 'open', pcName, expiresAt };
    }

    let order = await Order.findById(ticket.orderId).select('status deliveredAt history');
    if (!order || order.status === 'cancelled') return { state: 'invalid' };
    if (!order.deliveredAt && activate && ['packed', 'shipped'].includes(order.status)) {
        // Conditional on the status just read: if the admin marks it at the same moment, theirs stands
        const set = await deliveredFields(now);
        order = await Order.findOneAndUpdate(
            { _id: order._id, status: order.status, deliveredAt: { $exists: false } },
            { $set: set, $push: { history: { status: 'delivered', at: now, by: 'customer', note: 'box code entered' } } },
            { new: true }
        ) || await Order.findById(ticket.orderId).select('status deliveredAt');
    }
    // For the admin's list: when the customer first entered it
    if (activate && ticket.status === 'pending') {
        await ReviewTicket.updateOne({ _id: ticket._id, status: 'pending' }, { $set: { status: 'active', firstScan: now } });
    }
    if (!order.deliveredAt) return { state: 'waiting', pcName };
    const expiresAt = new Date(new Date(order.deliveredAt).getTime() + REVIEW_DAYS * DAY_MS);
    return { state: now > expiresAt ? 'expired' : 'open', pcName, expiresAt };
}

// --- closing orders ---
// A delivered order whose return window has passed, with no return waiting on the admin, is
// completed — dated at the deadline, not whenever this happened to run. There is no scheduler on the
// free server, so this runs when orders are read (the admin's list, the customer's page) and, at most
// once a minute, on the storefront's status call.
let lastSweep = 0;
async function completeDueOrders({ now = new Date(), throttle = false } = {}) {
    if (throttle && now.getTime() - lastSweep < 60 * 1000) return;
    lastSweep = now.getTime();
    const r = await Order.updateMany(
        {
            status: 'delivered', returnDeadline: { $lte: now },
            requests: { $not: { $elemMatch: { type: 'return', handledAt: { $exists: false } } } }
        },
        [{ $set: { status: 'completed', history: { $concatArrays: ['$history', [{ status: 'completed', at: '$returnDeadline', by: 'auto' }]] } } }],
        { updatePipeline: true }
    );
    if (r.modifiedCount) deliveriesCache = null;
}

// --- "N deliveries" ---
// Real orders only (never DEMO), completed, and never a return asked for — a PC that may have come
// back isn't counted, even if the return was refused. Positive only: problems are not shown.
let deliveriesCache = null;
async function completedDeliveries() {
    if (deliveriesCache && Date.now() - deliveriesCache.at < 5 * 60 * 1000) return deliveriesCache.n;
    const n = await Order.countDocuments({ demo: false, status: 'completed', 'requests.type': { $ne: 'return' } });
    deliveriesCache = { n, at: Date.now() };
    return n;
}
// What the storefront shows: the number, or null while it's switched off or under the threshold
async function publicDeliveries(config) {
    const { on, min } = deliveriesBadge(config);
    if (!on) return null;
    const n = await completedDeliveries();
    return n >= min ? n : null;
}

// --- the admin's figures (only the admin sees these) ---
async function orderStats(now = new Date()) {
    const since = new Date(now.getTime() - 30 * DAY_MS);
    const orders = await Order.find({ status: { $in: ['delivered', 'completed'] } }).select('demo status deliveredAt requests').lean();
    const empty = () => ({ delivered: 0, delivered30: 0, completed: 0, inReturnWindow: 0, returns: 0, returns30: 0, problems: 0, problems30: 0, openRequests: 0 });
    const out = { live: empty(), demo: empty() };
    for (const o of orders) {
        const s = out[o.demo ? 'demo' : 'live'];
        s.delivered++;
        if (o.deliveredAt && new Date(o.deliveredAt) >= since) s.delivered30++;
        if (o.status === 'completed') s.completed++; else s.inReturnWindow++;
        for (const r of o.requests || []) {
            const key = r.type === 'return' ? 'returns' : 'problems';
            s[key]++;
            if (new Date(r.createdAt) >= since) s[key + '30']++;
            if (!r.handledAt) s.openRequests++;
        }
    }
    out.live.publicCount = await completedDeliveries();
    return out;
}

module.exports = {
    REVIEW_DAYS, deliveredFields, ensureOrderCodes, orderCodes, voidOrderCodes, ticketWindow,
    completeDueOrders, completedDeliveries, publicDeliveries, orderStats
};
