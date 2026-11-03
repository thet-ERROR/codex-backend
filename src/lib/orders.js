// Checkout rules: what a valid order form looks like, what each line costs (worked out here from the
// database — the prices in the browser's cart are never trusted), and which status may follow which.
const { asString, isValidEmail } = require('./validation');

// A community drop unlocked early is for verified members until membersOnlyUntil (lib/vote.js sets it).
// The storefront only shows this; checkout is where it is enforced.
const membersOnlyActive = (pc, now = new Date()) => !!pc.membersOnlyUntil && new Date(pc.membersOnlyUntil) > now;

// --- statuses ---
// The normal path, in order. 'cancelled' can branch off it (see canCustomerCancel / adminCancellable).
const STATUS_FLOW = ['new', 'paid', 'building', 'packed', 'shipped', 'delivered', 'completed'];
// The customer may cancel on their own until the order is packed — except a painted build, which is
// made to order: once building has started it stays.
function canCustomerCancel(order) {
    if (order.status === 'new' || order.status === 'paid') return true;
    if (order.status === 'building') return !order.items.some(i => i.paint);
    return false;
}
// The admin can cancel anything not yet delivered (and mark a no-show)
const adminCancellable = (order) => STATUS_FLOW.indexOf(order.status) >= 0 && STATUS_FLOW.indexOf(order.status) < STATUS_FLOW.indexOf('delivered');

// Admin moves an order one step forward along STATUS_FLOW. Skipping ahead is allowed (a build that's
// packed the day it's paid), going back is not. Sending before payment is refused unless the admin says
// so explicitly — the guard against a "customer" who orders, never pays and never turns up.
function checkAdminTransition(order, next, { force = false } = {}) {
    const from = STATUS_FLOW.indexOf(order.status);
    const to = STATUS_FLOW.indexOf(next);
    if (from < 0) return `This order is ${order.status} and can't move on`;
    if (to < 0 || next === 'completed') return `Unknown or automatic status: ${next}`;
    if (to <= from) return `An order can only move forward (it is ${order.status})`;
    if (to >= STATUS_FLOW.indexOf('shipped') && !order.payment?.paidAt && !force) {
        return 'NOT_PAID';
    }
    return null;
}

// --- the form ---
const NAME_RE = /^[^<>]{1,60}$/;
// Greek mobile or landline, optionally with +30 / 0030 in front; spaces and dashes allowed
const normalisePhone = (v) => asString(v).replace(/[\s\-().]/g, '').replace(/^(\+30|0030)/, '');
const isGreekPhone = (digits) => /^(69\d{8}|2\d{9})$/.test(digits);

// Returns { error } or { value } with every field trimmed, checked and normalised.
function validateCheckout(body, { handDeliveryAreas }) {
    const b = body && typeof body === 'object' ? body : {};
    const c = b.customer && typeof b.customer === 'object' ? b.customer : {};
    const d = b.delivery && typeof b.delivery === 'object' ? b.delivery : {};
    const inv = b.invoice && typeof b.invoice === 'object' ? b.invoice : {};
    const t = (v, max) => asString(v).trim().slice(0, max);

    const customer = {
        firstName: t(c.firstName, 60), lastName: t(c.lastName, 60),
        phone: normalisePhone(c.phone), email: t(c.email, 254).toLowerCase()
    };
    if (!NAME_RE.test(customer.firstName) || !NAME_RE.test(customer.lastName)) return { error: 'First and last name are required', field: 'name' };
    if (!isGreekPhone(customer.phone)) return { error: 'A Greek phone number is required (10 digits)', field: 'phone' };
    if (!isValidEmail(customer.email)) return { error: 'A valid email address is required', field: 'email' };

    const method = asString(d.method);
    const delivery = { method };
    if (method === 'courier') {
        delivery.address = t(d.address, 120); delivery.postcode = asString(d.postcode).replace(/\s/g, ''); delivery.city = t(d.city, 60);
        if (!delivery.address || /[<>]/.test(delivery.address)) return { error: 'Delivery address is required', field: 'address' };
        if (!/^\d{5}$/.test(delivery.postcode)) return { error: 'Postcode must be 5 digits', field: 'postcode' };
        if (!delivery.city || /[<>]/.test(delivery.city)) return { error: 'City is required', field: 'city' };
    } else if (method === 'hand') {
        delivery.area = t(d.area, 60);
        delivery.address = t(d.address, 120);
        if (!handDeliveryAreas.includes(delivery.area)) return { error: 'Hand delivery is only available in the listed areas', field: 'area' };
        if (!delivery.address || /[<>]/.test(delivery.address)) return { error: 'Delivery address is required', field: 'address' };
    } else if (method === 'boxnow') {
        delivery.locker = t(d.locker, 120);
        if (!delivery.locker || /[<>]/.test(delivery.locker)) return { error: 'Pick a BOX NOW locker', field: 'locker' };
    } else {
        return { error: 'Choose a delivery method', field: 'method' };
    }

    const invoice = { type: inv.type === 'invoice' ? 'invoice' : 'receipt' };
    if (invoice.type === 'invoice') {
        invoice.vatNumber = asString(inv.vatNumber).replace(/\s/g, '').replace(/^EL/i, '');
        invoice.taxOffice = t(inv.taxOffice, 60);
        invoice.companyName = t(inv.companyName, 120);
        if (!/^\d{9}$/.test(invoice.vatNumber)) return { error: 'VAT number (ΑΦΜ) must be 9 digits', field: 'vatNumber' };
        if (!invoice.taxOffice || !invoice.companyName || /[<>]/.test(invoice.taxOffice + invoice.companyName)) {
            return { error: 'Tax office and company name are required for an invoice', field: 'invoice' };
        }
    }

    if (b.acceptTerms !== true) return { error: 'The terms must be accepted', field: 'terms' };
    if (b.adultOrGuardian !== true) return { error: 'Confirm you are 18 or older, or have a parent or guardian\'s consent', field: 'adult' };
    const termsVersion = t(b.termsVersion, 40);
    if (!termsVersion) return { error: 'Terms version missing', field: 'terms' };

    if (!Array.isArray(b.items) || !b.items.length) return { error: 'The cart is empty', field: 'items' };
    if (b.items.length > 10) return { error: 'At most 10 systems per order', field: 'items' };
    const items = [];
    for (const raw of b.items) {
        const it = raw && typeof raw === 'object' ? raw : {};
        const pcId = asString(it.pcId);
        if (!/^[a-f0-9]{24}$/i.test(pcId)) return { error: 'Unknown system in the cart', field: 'items' };
        const storage = it.storage === 'hdd' || it.storage === 'ssd' ? it.storage : '';
        if (it.storage && !storage) return { error: 'Unknown storage option', field: 'items' };
        items.push({ pcId, storage, proConfig: it.proConfig === true, paint: it.paint === true, paintAck: it.paintAck === true });
    }

    return {
        value: {
            customer, delivery, invoice, items, termsVersion,
            couponCode: t(b.couponCode, 20).toUpperCase(),
            lang: b.lang === 'en' ? 'en' : 'el',
            notes: t(b.notes, 500).replace(/[<>]/g, '')
        }
    };
}

// --- prices ---
const eurosToCents = (euros) => Math.round((Number(euros) || 0) * 100);

// The same arithmetic as the storefront's getBreakdown (js/modules/gallery.js): base price plus each
// chosen extra, every extra only if this PC offers it. Returns { error } for an option it doesn't offer.
function priceLine(pc, choice, proConfigPrice) {
    const o = pc.options || {};
    const storage = o.storage || {}, pro = o.proConfig || {}, paint = o.paint || {};
    const base = Number.isFinite(pc.priceCents) ? pc.priceCents : null;
    if (base === null || base <= 0) return { error: `${pc.name} has no price yet` };

    const extras = [];
    if (choice.storage) {
        const euros = storage[choice.storage];
        if (!storage.enabled || !(euros > 0)) return { error: `${pc.name}: that storage option isn't offered` };
        extras.push({ key: 'storage', choice: choice.storage, priceCents: eurosToCents(euros) });
    }
    if (choice.proConfig) {
        if (!pro.enabled) return { error: `${pc.name}: Pro Configuration isn't offered` };
        extras.push({ key: 'proConfig', priceCents: eurosToCents(proConfigPrice) });
    }
    if (choice.paint) {
        if (!paint.enabled) return { error: `${pc.name}: custom paint isn't offered` };
        // Paint is made to order and can't be returned — the customer must have accepted that
        if (!choice.paintAck) return { error: `${pc.name}: the custom paint terms must be accepted` };
        extras.push({ key: 'paint', colorName: paint.colorName || '', colorNameEl: paint.colorNameEl || '', priceCents: eurosToCents(paint.price) });
    }
    const totalCents = extras.reduce((sum, e) => sum + e.priceCents, base);
    return { line: { pcId: pc._id, name: pc.name, basePriceCents: base, extras, totalCents, paint: !!choice.paint } };
}

// Whether a PC can be ordered at all right now, by this customer
function orderableProblem(pc, user) {
    if (!pc) return 'One of the systems in the cart no longer exists';
    if (pc.status === 'coming') return `${pc.name} is coming soon and can't be ordered yet`;
    if (membersOnlyActive(pc) && !(user && user.emailVerified)) return `${pc.name} is for signed-in members first — sign in to order it`;
    return null;
}

// --- what the customer's own order page shows ---
function publicView(order) {
    return {
        number: order.number, demo: order.demo, status: order.status,
        history: (order.history || []).map(h => ({ status: h.status, at: h.at })),
        customer: { firstName: order.customer?.firstName, lastName: order.customer?.lastName },
        delivery: { method: order.delivery?.method, area: order.delivery?.area, city: order.delivery?.city, locker: order.delivery?.locker, trackingNumber: order.delivery?.trackingNumber || null },
        items: order.items.map(i => ({ name: i.name, basePriceCents: i.basePriceCents, extras: i.extras, totalCents: i.totalCents, paint: i.paint })),
        subtotalCents: order.subtotalCents, discountCents: order.discountCents, coupon: order.coupon?.code ? order.coupon : null, totalCents: order.totalCents,
        createdAt: order.createdAt, deliveredAt: order.deliveredAt || null, returnDeadline: order.returnDeadline || null,
        canCancel: canCustomerCancel(order)
    };
}

module.exports = {
    STATUS_FLOW, canCustomerCancel, adminCancellable, checkAdminTransition,
    validateCheckout, normalisePhone, priceLine, orderableProblem, publicView
};
