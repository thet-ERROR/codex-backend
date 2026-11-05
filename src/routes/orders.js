// Orders: placing one (guests too), the customer's own order page and cancellation, and the admin's
// list, status changes and cancellations.
const crypto = require('crypto');
const { ORDERS_LIVE } = require('../config');
const { orderLimiter, requestLimiter } = require('../security/rate-limits');
const { auth, authUser, requireVerified, optionalSessionUser } = require('../security/auth');
const { asString } = require('../lib/validation');
const PC = require('../models/pc');
const User = require('../models/user');
const { Order, nextOrderNumber } = require('../models/order');
const { getSiteConfig, orderSettings } = require('../models/site-config');
const { sendOrderPlaced, sendOrderCancelled, sendRequestReceived } = require('../lib/order-emails');
const {
    canCustomerCancel, adminCancellable, checkAdminTransition,
    validateCheckout, priceLine, orderableProblem, publicView, requestProblem, isOpen
} = require('../lib/orders');
const { deliveredFields, ensureOrderCodes, orderCodes, voidOrderCodes, completeDueOrders, orderStats } = require('../lib/order-lifecycle');

const router = require('express').Router();

const hashToken = (t) => crypto.createHash('sha256').update(t).digest('hex');
// Constant-time, so a wrong token takes as long to refuse as a nearly-right one
function tokenMatches(order, token) {
    if (!order || !order.accessTokenHash || !/^[a-f0-9]{48}$/.test(token)) return false;
    const a = Buffer.from(order.accessTokenHash, 'hex'), b = Buffer.from(hashToken(token), 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const unitsPerPc = (items) => items.reduce((m, i) => m.set(String(i.pcId), (m.get(String(i.pcId)) || 0) + 1), new Map());

// A cancelled order gives back what it held: the stock, and the coupon (if it hasn't expired since,
// it can be used again). Each write is on its own, so one failing doesn't stop the others.
async function releaseOrder(order) {
    for (const [pcId, units] of unitsPerPc(order.items)) {
        try { await PC.updateOne({ _id: pcId }, { $inc: { stock: units } }); }
        catch (e) { console.error(`Order ${order.number}: returning stock for ${pcId} failed:`, e); }
    }
    if (order.coupon?.code && order.userId) {
        try {
            await User.updateOne(
                { _id: order.userId, coupons: { $elemMatch: { code: order.coupon.code, orderNumber: order.number } } },
                { $set: { 'coupons.$.usedAt': null, 'coupons.$.orderNumber': null } }
            );
        } catch (e) { console.error(`Order ${order.number}: giving the coupon back failed:`, e); }
    }
}

// --- placing an order ---
router.post('/api/orders', orderLimiter, async (req, res) => {
    try {
        const config = await getSiteConfig();
        const v = validateCheckout(req.body, orderSettings(config));
        if (v.error) return res.status(400).json({ error: v.error, field: v.field });
        const input = v.value;
        const user = await optionalSessionUser(req);
        const now = new Date();

        // Every line is priced from the database, never from what the browser says it costs
        const ids = [...new Set(input.items.map(i => i.pcId))];
        const pcs = new Map((await PC.find({ _id: { $in: ids } })).map(p => [String(p._id), p]));
        const lines = [];
        for (const choice of input.items) {
            const pc = pcs.get(choice.pcId);
            const problem = orderableProblem(pc, user);
            if (problem) return res.status(409).json({ error: problem, code: 'NOT_ORDERABLE' });
            const priced = priceLine(pc, choice, config?.proConfigPrice ?? 30);
            if (priced.error) return res.status(400).json({ error: priced.error, field: 'items' });
            lines.push(priced.line);
        }
        const subtotalCents = lines.reduce((sum, l) => sum + l.totalCents, 0);

        // A coupon belongs to an account, so only a verified member can spend one
        let coupon = null, discountCents = 0;
        if (input.couponCode) {
            if (!user || !user.emailVerified) return res.status(403).json({ error: 'Sign in to use a coupon', code: 'COUPON_NEEDS_ACCOUNT' });
            const c = (user.coupons || []).find(x => x.code === input.couponCode && !x.usedAt && x.expiresAt > now);
            if (!c) return res.status(400).json({ error: 'That coupon is not valid on this account', field: 'coupon' });
            coupon = { code: c.code, percent: c.percent };
            discountCents = Math.round(subtotalCents * c.percent / 100);
        }

        // From here on every step changes something, and each one is undone if a later one fails
        const undo = [];
        const rollback = async () => {
            for (const step of undo.reverse()) {
                try { await step(); } catch (e) { console.error('Order rollback step failed:', e); }
            }
        };
        try {
            // Hold the stock. The check and the decrement are one update, so two customers can never
            // both get the last unit.
            for (const [pcId, units] of unitsPerPc(lines)) {
                const held = await PC.findOneAndUpdate(
                    { _id: pcId, stock: { $gte: units }, status: { $ne: 'coming' } },
                    { $inc: { stock: -units } }
                );
                if (!held) {
                    await rollback();
                    return res.status(409).json({ error: `${pcs.get(pcId).name} just sold out`, code: 'SOLD_OUT', pcId });
                }
                undo.push(() => PC.updateOne({ _id: pcId }, { $inc: { stock: units } }));
            }

            const number = await nextOrderNumber(!ORDERS_LIVE);
            if (coupon) {
                const claimed = await User.findOneAndUpdate(
                    { _id: user._id, coupons: { $elemMatch: { code: coupon.code, usedAt: null, expiresAt: { $gt: now } } } },
                    { $set: { 'coupons.$.usedAt': now, 'coupons.$.orderNumber': number } }
                );
                if (!claimed) {
                    await rollback();
                    return res.status(409).json({ error: 'That coupon was just used', code: 'COUPON_USED' });
                }
                undo.push(() => User.updateOne(
                    { _id: user._id, 'coupons.code': coupon.code },
                    { $set: { 'coupons.$.usedAt': null, 'coupons.$.orderNumber': null } }
                ));
            }

            const accessToken = crypto.randomBytes(24).toString('hex');
            const order = await Order.create({
                number, demo: !ORDERS_LIVE, status: 'new',
                history: [{ status: 'new', at: now, by: 'customer' }],
                userId: user ? user._id : undefined,
                customer: input.customer, delivery: input.delivery, invoice: input.invoice,
                items: lines, subtotalCents, discountCents, coupon: coupon || undefined,
                totalCents: subtotalCents - discountCents, notes: input.notes, lang: input.lang,
                consent: { termsVersion: input.termsVersion, acceptedAt: now, adultOrGuardian: true },
                accessTokenHash: hashToken(accessToken)
            });
            // The token is shown once, here (and in the confirmation email): the order page's link
            res.json({ success: true, number, demo: order.demo, accessToken, order: publicView(order) });
            // After answering: the shop's notice warns if this phone or email didn't turn up before
            Order.countDocuments({ noShow: true, $or: [{ 'customer.phone': order.customer.phone }, { 'customer.email': order.customer.email }] })
                .catch(() => 0)
                .then(priorNoShows => sendOrderPlaced(order, accessToken, { priorNoShows }));
        } catch (e) {
            await rollback();
            throw e;
        }
    } catch (e) {
        console.error('Place order failed:', e);
        res.status(500).json({ error: 'Server Error' });
    }
});

// --- the customer's side ---
// The private link (?order=…&t=…) — no account needed. An unknown number and a wrong token give the
// same answer, so the link can't be used to find out which order numbers exist.
router.get('/api/orders/:number', async (req, res) => {
    try {
        await completeDueOrders();
        const order = await Order.findOne({ number: asString(req.params.number).toUpperCase() });
        if (!tokenMatches(order, asString(req.query.t))) return res.status(404).json({ error: 'Order not found' });
        res.json(publicView(order));
    } catch (e) { console.error('Read order failed:', e); res.status(500).json({ error: 'Server Error' }); }
});

// A member's own orders, newest first
router.get('/api/my-orders', authUser, requireVerified, async (req, res) => {
    try {
        await completeDueOrders();
        const orders = await Order.find({ userId: req.userId }).sort({ createdAt: -1 }).limit(50);
        res.json(orders.map(publicView));
    } catch (e) { console.error('My orders failed:', e); res.status(500).json({ error: 'Server Error' }); }
});

// Cancelling: with the link's token, or as the signed-in member who placed it
router.post('/api/orders/:number/cancel', async (req, res) => {
    try {
        const order = await Order.findOne({ number: asString(req.params.number).toUpperCase() });
        let allowed = tokenMatches(order, asString(req.body?.t));
        if (!allowed && order?.userId) {
            const user = await optionalSessionUser(req);
            allowed = !!user && String(user._id) === String(order.userId);
        }
        if (!allowed) return res.status(404).json({ error: 'Order not found' });
        if (!canCustomerCancel(order)) {
            return res.status(409).json({ error: 'This order can no longer be cancelled here — contact us', code: 'NOT_CANCELLABLE', status: order.status });
        }
        const now = new Date();
        // Conditional on the status read above: if the admin moved it on meanwhile, nothing changes
        const cancelled = await Order.findOneAndUpdate(
            { _id: order._id, status: order.status },
            {
                $set: { status: 'cancelled', cancelledAt: now, cancelReason: 'customer', refundDue: !!order.payment?.paidAt },
                $push: { history: { status: 'cancelled', at: now, by: 'customer' } }
            },
            { new: true }
        );
        if (!cancelled) return res.status(409).json({ error: 'The order changed just now — reload and try again', code: 'CHANGED' });
        await releaseOrder(cancelled);
        await voidOrderCodes(cancelled);
        res.json({ success: true, order: publicView(cancelled) });
        sendOrderCancelled(cancelled, { byCustomer: true });
    } catch (e) { console.error('Cancel order failed:', e); res.status(500).json({ error: 'Server Error' }); }
});

// After delivery: a return (inside the return window) or a problem under the guarantee. Same access
// as cancelling — the link's token, or the member who placed it. Recorded on the order so it can't be
// lost in an inbox; the shop is emailed too.
router.post('/api/orders/:number/request', requestLimiter, async (req, res) => {
    try {
        const order = await Order.findOne({ number: asString(req.params.number).toUpperCase() });
        let allowed = tokenMatches(order, asString(req.body?.t));
        if (!allowed && order?.userId) {
            const user = await optionalSessionUser(req);
            allowed = !!user && String(user._id) === String(order.userId);
        }
        if (!allowed) return res.status(404).json({ error: 'Order not found' });

        const type = asString(req.body?.type);
        const message = asString(req.body?.message).trim().slice(0, 1000);
        if (message.length < 5) return res.status(400).json({ error: 'Tell us briefly what is wrong', field: 'message' });
        const problem = requestProblem(order, type);
        if (problem) return res.status(409).json({ error: problem, code: 'NOT_ALLOWED' });

        // Conditional on there being no open request of this type: two taps at once make one
        const updated = await Order.findOneAndUpdate(
            { _id: order._id, requests: { $not: { $elemMatch: { type, handledAt: { $exists: false } } } } },
            { $push: { requests: { type, message, createdAt: new Date() } } },
            { new: true }
        );
        if (!updated) return res.status(409).json({ error: 'You already have an open request of this kind', code: 'NOT_ALLOWED' });
        sendRequestReceived(updated, updated.requests.at(-1));
        res.json({ success: true, order: publicView(updated) });
    } catch (e) { console.error('Order request failed:', e); res.status(500).json({ error: 'Server Error' }); }
});

// --- the admin's side ---
// Everything but the customer's link token
const ADMIN_PROJECTION = '-accessTokenHash';

// How many earlier orders from the same phone or email ended in a no-show, per order
async function noShowCounts(orders) {
    const phones = [...new Set(orders.map(o => o.customer?.phone).filter(Boolean))];
    const emails = [...new Set(orders.map(o => o.customer?.email).filter(Boolean))];
    const flagged = await Order.find({ noShow: true, $or: [{ 'customer.phone': { $in: phones } }, { 'customer.email': { $in: emails } }] })
        .select('number customer.phone customer.email').lean();
    return (o) => flagged.filter(f => f.number !== o.number && (f.customer?.phone === o.customer?.phone || f.customer?.email === o.customer?.email)).length;
}

// The admin's own figures: deliveries, returns and problems (all time and the last 30 days), real
// orders and DEMO ones apart. Never public.
router.get('/api/admin/order-stats', auth, async (req, res) => {
    try {
        await completeDueOrders();
        res.json(await orderStats());
    } catch (e) { console.error('Order stats failed:', e); res.status(500).json({ error: 'Server Error' }); }
});

router.get('/api/admin/orders', auth, async (req, res) => {
    try {
        await completeDueOrders();
        const q = {};
        const status = asString(req.query.status);
        if (status) q.status = status;
        if (req.query.demo === 'true') q.demo = true;
        if (req.query.demo === 'false') q.demo = false;
        const orders = await Order.find(q).select(ADMIN_PROJECTION).sort({ createdAt: -1 }).limit(200);
        const noShows = await noShowCounts(orders);
        res.json(orders.map(o => ({ ...o.toObject(), priorNoShows: noShows(o), openRequests: (o.requests || []).filter(isOpen).length })));
    } catch (e) { console.error('List orders failed:', e); res.status(500).json({ error: 'Server Error' }); }
});

router.get('/api/admin/orders/:number', auth, async (req, res) => {
    try {
        await completeDueOrders();
        const order = await Order.findOne({ number: asString(req.params.number).toUpperCase() }).select(ADMIN_PROJECTION);
        if (!order) return res.status(404).json({ error: 'Order not found' });
        const noShows = await noShowCounts([order]);
        res.json({ ...order.toObject(), priorNoShows: noShows(order), openRequests: (order.requests || []).filter(isOpen).length, reviewCodes: await orderCodes(order) });
    } catch (e) { console.error('Read order (admin) failed:', e); res.status(500).json({ error: 'Server Error' }); }
});

// Moves an order forward: paid, building, packed, shipped (with the courier's tracking number),
// delivered (starts the return window). Sending an unpaid order needs force: true.
router.post('/api/admin/orders/:number/status', auth, async (req, res) => {
    try {
        const order = await Order.findOne({ number: asString(req.params.number).toUpperCase() });
        if (!order) return res.status(404).json({ error: 'Order not found' });
        const next = asString(req.body?.status);
        const problem = checkAdminTransition(order, next, { force: req.body?.force === true });
        if (problem === 'NOT_PAID') {
            return res.status(409).json({ error: 'This order is not marked paid. Send it anyway with force.', code: 'NOT_PAID' });
        }
        if (problem) return res.status(400).json({ error: problem });

        const now = new Date();
        const set = { status: next };
        if (next === 'paid') set['payment.paidAt'] = now;
        const tracking = asString(req.body?.trackingNumber).trim().slice(0, 60);
        if (tracking) set['delivery.trackingNumber'] = tracking;
        if (next === 'delivered') Object.assign(set, await deliveredFields(now));
        const note = asString(req.body?.note).trim().slice(0, 300);
        const updated = await Order.findOneAndUpdate(
            { _id: order._id, status: order.status },
            { $set: set, $push: { history: { status: next, at: now, by: 'admin', ...(note ? { note } : {}) } } },
            { new: true, projection: ADMIN_PROJECTION }
        );
        if (!updated) return res.status(409).json({ error: 'The order changed just now — reload', code: 'CHANGED' });
        // From "packed" on, the box's review codes exist (made once), ready to print
        const reviewCodes = await ensureOrderCodes(updated);
        res.json({ ...updated.toObject(), reviewCodes });
    } catch (e) { console.error('Update order status failed:', e); res.status(500).json({ error: 'Server Error' }); }
});

// Cancels on the shop's side; reason 'no_show' also flags the customer for next time
router.post('/api/admin/orders/:number/cancel', auth, async (req, res) => {
    try {
        const order = await Order.findOne({ number: asString(req.params.number).toUpperCase() });
        if (!order) return res.status(404).json({ error: 'Order not found' });
        if (!adminCancellable(order)) return res.status(409).json({ error: `A ${order.status} order can't be cancelled`, code: 'NOT_CANCELLABLE' });
        const reason = req.body?.reason === 'no_show' ? 'no_show' : 'admin';
        const note = asString(req.body?.note).trim().slice(0, 300);
        const now = new Date();
        const cancelled = await Order.findOneAndUpdate(
            { _id: order._id, status: order.status },
            {
                $set: { status: 'cancelled', cancelledAt: now, cancelReason: reason, noShow: reason === 'no_show', refundDue: !!order.payment?.paidAt },
                $push: { history: { status: 'cancelled', at: now, by: 'admin', ...(note ? { note } : {}) } }
            },
            { new: true, projection: ADMIN_PROJECTION }
        );
        if (!cancelled) return res.status(409).json({ error: 'The order changed just now — reload', code: 'CHANGED' });
        await releaseOrder(cancelled);
        await voidOrderCodes(cancelled);
        res.json(cancelled);
        sendOrderCancelled(cancelled, { byCustomer: false });
    } catch (e) { console.error('Cancel order (admin) failed:', e); res.status(500).json({ error: 'Server Error' }); }
});

// Marks a customer's request as handled (with an optional note for the record)
router.post('/api/admin/orders/:number/requests/:id/handle', auth, async (req, res) => {
    try {
        const id = asString(req.params.id);
        if (!/^[a-f0-9]{24}$/i.test(id)) return res.status(400).json({ error: 'Invalid request id' });
        const note = asString(req.body?.note).trim().slice(0, 300);
        const updated = await Order.findOneAndUpdate(
            { number: asString(req.params.number).toUpperCase(), requests: { $elemMatch: { _id: id, handledAt: { $exists: false } } } },
            { $set: { 'requests.$.handledAt': new Date(), 'requests.$.handledNote': note } },
            { new: true, projection: ADMIN_PROJECTION }
        );
        if (!updated) return res.status(404).json({ error: 'Request not found or already handled' });
        res.json({ ...updated.toObject(), openRequests: (updated.requests || []).filter(isOpen).length });
    } catch (e) { console.error('Handle request failed:', e); res.status(500).json({ error: 'Server Error' }); }
});

module.exports = router;
