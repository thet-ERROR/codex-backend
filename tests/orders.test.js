// Orders: placing one (prices worked out by the server, stock held atomically, coupons), the
// customer's order page and cancellation, the admin's status changes, no-shows, and DEMO vs live.
// Run: npm test
//
// Placing orders is limited to 20 an hour per address, so each group has a server of its own.

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startBackend } from './harness.js';

const DAY = 86400e3;

// A full, valid checkout form; tests override the part they're about
const form = (items, over = {}) => ({
    customer: { firstName: 'Nikos', lastName: 'Papadopoulos', phone: '691 234 5678', email: 'nikos@gmail.com' },
    delivery: { method: 'courier', address: 'Egnatias 1', postcode: '546 30', city: 'Thessaloniki' },
    invoice: { type: 'receipt' },
    items, acceptTerms: true, adultOrGuardian: true, termsVersion: '2026-11',
    ...over
});

async function shop(api, admin) {
    const make = async (body) => (await api.post('/drops', body, { token: admin })).body._id;
    return {
        rig: await make({ name: 'FULL RIG', priceCents: 100000, stock: 3, options: {
            storage: { enabled: true, hdd: 50, ssd: 80 }, proConfig: { enabled: true },
            paint: { enabled: true, price: 40, colorName: 'Matte Black', colorNameEl: 'Ματ μαύρο' } } }),
        last: await make({ name: 'LAST ONE', priceCents: 200000, stock: 1 }),
        // Plenty of stock: each group places many orders of this one
        plain: await make({ name: 'PLAIN', priceCents: 50000, stock: 30, options: { storage: { enabled: false }, proConfig: { enabled: false }, paint: { enabled: false } } }),
        soon: await make({ name: 'SOON', priceCents: 90000, stock: 2, status: 'coming' }),
        members: await make({ name: 'MEMBERS FIRST', priceCents: 120000, stock: 2, membersOnlyUntil: new Date(Date.now() + 3 * DAY) })
    };
}
const stockOf = async (api, id) => (await api.get('/drops')).body.find(p => p._id === id).stock;

describe('placing an order', () => {
    let api, admin, pc;
    before(async () => { api = await startBackend(); admin = await api.adminToken(); pc = await shop(api, admin); });
    after(async () => { await api.stop(); });

    it('/status tells the checkout that orders are a demo, and the delivery settings', async () => {
        const o = (await api.get('/status')).body.orders;
        assert.equal(o.live, false);
        assert.equal(o.returnDays, 14);
        assert.ok(o.handDeliveryAreas.includes('Καλαμαριά'));
        assert.deepEqual(o.handDeliveryCenter, { lat: 40.6401, lng: 22.9444 });
        assert.equal(o.handDeliveryRadiusKm, 10);
    });

    it('a guest orders; the server prices it from the database, whatever the cart says', async () => {
        const r = await api.post('/orders', form([{ pcId: pc.rig, storage: 'ssd', proConfig: true, priceCents: 1, totalCents: 1 }], { totalCents: 1 }));
        assert.equal(r.status, 200);
        assert.equal(r.body.number, 'DEMO-0001');
        assert.equal(r.body.demo, true);
        assert.match(r.body.accessToken, /^[a-f0-9]{48}$/);
        const o = r.body.order;
        assert.equal(o.subtotalCents, 100000 + 8000 + 3000);
        assert.equal(o.totalCents, 111000);
        assert.deepEqual(o.items[0].extras.map(e => [e.key, e.priceCents]), [['storage', 8000], ['proConfig', 3000]]);
        assert.equal(o.status, 'new');
        assert.equal(o.canCancel, true);
        assert.equal(await stockOf(api, pc.rig), 2, 'the order must hold the unit');
    });

    it('stores what was agreed: frozen prices, consent with the terms version, normalised phone and postcode', async () => {
        const doc = await api.col('orders').findOne({ number: 'DEMO-0001' });
        assert.equal(doc.customer.phone, '6912345678');
        assert.equal(doc.delivery.postcode, '54630');
        assert.equal(doc.consent.termsVersion, '2026-11');
        assert.equal(doc.consent.adultOrGuardian, true);
        assert.ok(doc.consent.acceptedAt);
        assert.equal(doc.items[0].basePriceCents, 100000);
        assert.notEqual(doc.accessTokenHash, undefined);
        assert.equal(doc.payment.method, 'agreed');
    });

    it('custom paint needs its terms accepted, and is priced from the PC', async () => {
        assert.equal((await api.post('/orders', form([{ pcId: pc.rig, paint: true }]))).status, 400);
        const r = await api.post('/orders', form([{ pcId: pc.rig, paint: true, paintAck: true }]));
        assert.equal(r.status, 200);
        const line = r.body.order.items[0];
        assert.equal(line.paint, true);
        assert.deepEqual(line.extras, [{ key: 'paint', colorName: 'Matte Black', colorNameEl: 'Ματ μαύρο', priceCents: 4000 }]);
        assert.equal(r.body.number, 'DEMO-0002');
    });

    it('an extra the PC does not offer is refused', async () => {
        for (const extra of [{ storage: 'hdd' }, { proConfig: true }, { paint: true, paintAck: true }]) {
            const r = await api.post('/orders', form([{ pcId: pc.plain, ...extra }]));
            assert.equal(r.status, 400, JSON.stringify(extra));
        }
    });

    it('coming-soon and members-first PCs are refused to a guest', async () => {
        const soon = await api.post('/orders', form([{ pcId: pc.soon }]));
        assert.equal(soon.status, 409);
        assert.equal(soon.body.code, 'NOT_ORDERABLE');
        const members = await api.post('/orders', form([{ pcId: pc.members }]));
        assert.equal(members.status, 409);
        assert.match(members.body.error, /members first/);
    });

    it('two customers after the last unit: one gets it, the other is told it sold out', async () => {
        const [a, b] = await Promise.all([
            api.post('/orders', form([{ pcId: pc.last }])),
            api.post('/orders', form([{ pcId: pc.last }], { customer: { firstName: 'Maria', lastName: 'K', phone: '6987654321', email: 'maria@gmail.com' } }))
        ]);
        assert.deepEqual([a.status, b.status].sort(), [200, 409]);
        assert.equal((a.status === 409 ? a : b).body.code, 'SOLD_OUT');
        assert.equal(await stockOf(api, pc.last), 0);
    });

    it('if one PC in the cart is sold out, nothing is held for the others', async () => {
        const before = await stockOf(api, pc.plain);
        const r = await api.post('/orders', form([{ pcId: pc.plain }, { pcId: pc.last }]));
        assert.equal(r.status, 409);
        assert.equal(await stockOf(api, pc.plain), before, 'the first PC\'s unit was not given back');
    });

    it('the same PC twice in the cart holds two units', async () => {
        const before = await stockOf(api, pc.plain);
        const r = await api.post('/orders', form([{ pcId: pc.plain }, { pcId: pc.plain }]));
        assert.equal(r.status, 200);
        assert.equal(r.body.order.totalCents, 100000);
        assert.equal(await stockOf(api, pc.plain), before - 2);
    });

    it('coupons: members only, their own, once; the discount comes off the subtotal', async () => {
        const member = await api.signUp('Buyer');
        await api.col('users').updateOne({ username: 'Buyer' }, { $push: { coupons: { $each: [
            { code: 'CDX-SAVE55', percent: 5, issuedAt: new Date(), expiresAt: new Date(Date.now() + DAY) },
            { code: 'CDX-OLDOLD', percent: 5, issuedAt: new Date(Date.now() - 40 * DAY), expiresAt: new Date(Date.now() - DAY) }
        ] } } });

        const guest = await api.post('/orders', form([{ pcId: pc.plain }], { couponCode: 'CDX-SAVE55' }));
        assert.equal(guest.status, 403);
        assert.equal(guest.body.code, 'COUPON_NEEDS_ACCOUNT');

        const expired = await api.post('/orders', form([{ pcId: pc.plain }], { couponCode: 'CDX-OLDOLD' }), { token: member.token });
        assert.equal(expired.status, 400);

        const ok = await api.post('/orders', form([{ pcId: pc.plain }], { couponCode: 'cdx-save55' }), { token: member.token });
        assert.equal(ok.status, 200);
        assert.equal(ok.body.order.subtotalCents, 50000);
        assert.equal(ok.body.order.discountCents, 2500);
        assert.equal(ok.body.order.totalCents, 47500);
        const coupon = (await api.col('users').findOne({ username: 'Buyer' })).coupons.find(c => c.code === 'CDX-SAVE55');
        assert.ok(coupon.usedAt);
        assert.equal(coupon.orderNumber, ok.body.number);

        const again = await api.post('/orders', form([{ pcId: pc.plain }], { couponCode: 'CDX-SAVE55' }), { token: member.token });
        assert.equal(again.status, 400, 'a coupon must work once');
    });

    it('a verified member may order a members-first PC, and the order is on their account', async () => {
        const member = await api.signUp('Insider');
        const r = await api.post('/orders', form([{ pcId: pc.members }]), { token: member.token });
        assert.equal(r.status, 200);
        const doc = await api.col('orders').findOne({ number: r.body.number });
        assert.ok(doc.userId);
    });
});

describe('the checkout form', () => {
    let api, pcId;
    before(async () => {
        api = await startBackend();
        const admin = await api.adminToken();
        pcId = (await api.post('/drops', { name: 'FORM RIG', priceCents: 100000, stock: 10 }, { token: admin })).body._id;
    });
    after(async () => { await api.stop(); });

    const refused = [
        ['no first name', { customer: { firstName: '', lastName: 'P', phone: '6912345678', email: 'a@gmail.com' } }, 'name'],
        ['a phone that is not Greek', { customer: { firstName: 'A', lastName: 'P', phone: '12345', email: 'a@gmail.com' } }, 'phone'],
        ['a bad email', { customer: { firstName: 'A', lastName: 'P', phone: '6912345678', email: 'nope' } }, 'email'],
        ['courier without a postcode', { delivery: { method: 'courier', address: 'X 1', city: 'Thessaloniki' } }, 'postcode'],
        ['hand delivery outside the areas', { delivery: { method: 'hand', area: 'Athens', address: 'X 1' } }, 'area'],
        ['BOX NOW without a locker', { delivery: { method: 'boxnow' } }, 'locker'],
        ['no delivery method', { delivery: {} }, 'method'],
        ['an invoice without a VAT number', { invoice: { type: 'invoice', taxOffice: 'A', companyName: 'B' } }, 'vatNumber'],
        ['terms not accepted', { acceptTerms: false }, 'terms'],
        ['no 18+ / guardian confirmation', { adultOrGuardian: false }, 'adult'],
    ];
    for (const [name, over, field] of refused) {
        it(`refuses ${name}`, async () => {
            const r = await api.post('/orders', form([{ pcId }], over));
            assert.equal(r.status, 400);
            assert.equal(r.body.field, field);
        });
    }

    it('refuses an empty cart, more than ten systems, and an id that is not one', async () => {
        assert.equal((await api.post('/orders', form([]))).status, 400);
        assert.equal((await api.post('/orders', form(Array(11).fill({ pcId })))).status, 400);
        assert.equal((await api.post('/orders', form([{ pcId: { $ne: null } }]))).status, 400);
    });

    it('accepts hand delivery inside the areas, and an invoice with its details', async () => {
        const r = await api.post('/orders', form([{ pcId }], {
            delivery: { method: 'hand', area: 'Καλαμαριά', address: 'Pontou 5' },
            invoice: { type: 'invoice', vatNumber: 'EL 123456789', taxOffice: 'Kalamarias', companyName: 'Test IKE' }
        }));
        assert.equal(r.status, 200);
        const doc = await api.col('orders').findOne({ number: r.body.number });
        assert.equal(doc.invoice.vatNumber, '123456789');
        assert.equal(doc.delivery.area, 'Καλαμαριά');
    });

    it('the placing of orders is rate limited per address', async () => {
        let blocked = 0;
        for (let i = 0; i < 12; i++) if ((await api.post('/orders', form([]))).status === 429) blocked++;
        assert.ok(blocked > 0, 'twenty orders an hour from one address is the limit');
    });
});

describe('the customer\'s order page and cancelling', () => {
    let api, admin, pc;
    before(async () => { api = await startBackend(); admin = await api.adminToken(); pc = await shop(api, admin); });
    after(async () => { await api.stop(); });
    const place = async (items, over, opts) => (await api.post('/orders', form(items, over), opts)).body;
    const toStatus = (number, status, extra = {}) => api.post(`/admin/orders/${number}/status`, { status, ...extra }, { token: admin });

    it('the private link shows the order; a wrong token or an unknown number look the same', async () => {
        const placed = await place([{ pcId: pc.plain }]);
        const ok = await api.get(`/orders/${placed.number}?t=${placed.accessToken}`);
        assert.equal(ok.status, 200);
        assert.equal(ok.body.number, placed.number);
        assert.equal(ok.body.customer.firstName, 'Nikos');
        assert.equal('accessTokenHash' in ok.body, false);
        assert.equal('phone' in ok.body.customer, false, 'the page shows no more contact details than needed');
        const wrong = await api.get(`/orders/${placed.number}?t=${'0'.repeat(48)}`);
        const unknown = await api.get(`/orders/DEMO-9999?t=${placed.accessToken}`);
        assert.equal(wrong.status, 404);
        assert.deepEqual(wrong.body, unknown.body);
    });

    it('cancelling a new order gives the stock and the coupon back', async () => {
        const member = await api.signUp('Changer');
        await api.col('users').updateOne({ username: 'Changer' }, { $push: { coupons: { code: 'CDX-BACK22', percent: 5, issuedAt: new Date(), expiresAt: new Date(Date.now() + DAY) } } });
        const before = await stockOf(api, pc.plain);
        const placed = await place([{ pcId: pc.plain }], { couponCode: 'CDX-BACK22' }, { token: member.token });
        assert.equal(await stockOf(api, pc.plain), before - 1);

        const r = await api.post(`/orders/${placed.number}/cancel`, { t: placed.accessToken });
        assert.equal(r.status, 200);
        assert.equal(r.body.order.status, 'cancelled');
        assert.equal(r.body.order.canCancel, false);
        assert.equal(await stockOf(api, pc.plain), before);
        const coupon = (await api.col('users').findOne({ username: 'Changer' })).coupons.find(c => c.code === 'CDX-BACK22');
        assert.equal(coupon.usedAt, null, 'the coupon was not given back');

        const twice = await api.post(`/orders/${placed.number}/cancel`, { t: placed.accessToken });
        assert.equal(twice.status, 409);
        assert.equal(twice.body.code, 'NOT_CANCELLABLE');
    });

    it('cancelling after payment flags the refund', async () => {
        const placed = await place([{ pcId: pc.plain }]);
        await toStatus(placed.number, 'paid');
        const r = await api.post(`/orders/${placed.number}/cancel`, { t: placed.accessToken });
        assert.equal(r.status, 200);
        const doc = await api.col('orders').findOne({ number: placed.number });
        assert.equal(doc.refundDue, true);
        assert.equal(doc.cancelReason, 'customer');
    });

    it('a build being made can still be cancelled — unless it is painted', async () => {
        const plain = await place([{ pcId: pc.rig }]);
        await toStatus(plain.number, 'building');
        assert.equal((await api.post(`/orders/${plain.number}/cancel`, { t: plain.accessToken })).status, 200);

        const painted = await place([{ pcId: pc.rig, paint: true, paintAck: true }]);
        assert.equal((await api.get(`/orders/${painted.number}?t=${painted.accessToken}`)).body.canCancel, true);
        await toStatus(painted.number, 'building');
        const r = await api.post(`/orders/${painted.number}/cancel`, { t: painted.accessToken });
        assert.equal(r.status, 409);
        assert.equal((await api.get(`/orders/${painted.number}?t=${painted.accessToken}`)).body.canCancel, false);
    });

    it('once packed it can no longer be cancelled by the customer', async () => {
        const placed = await place([{ pcId: pc.plain }]);
        await toStatus(placed.number, 'packed');
        assert.equal((await api.post(`/orders/${placed.number}/cancel`, { t: placed.accessToken })).status, 409);
    });

    it('a member sees their orders and can cancel without the link; another member cannot', async () => {
        const owner = await api.signUp('Owner');
        const other = await api.signUp('Other');
        const placed = await place([{ pcId: pc.plain }], {}, { token: owner.token });
        const mine = await api.get('/my-orders', { token: owner.token });
        assert.deepEqual(mine.body.map(o => o.number), [placed.number]);
        assert.deepEqual((await api.get('/my-orders', { token: other.token })).body, []);
        assert.equal((await api.post(`/orders/${placed.number}/cancel`, {}, { token: other.token })).status, 404);
        assert.equal((await api.post(`/orders/${placed.number}/cancel`, {}, { token: owner.token })).status, 200);
    });
});

describe('the admin\'s side', () => {
    let api, admin, pc;
    before(async () => { api = await startBackend(); admin = await api.adminToken(); pc = await shop(api, admin); });
    after(async () => { await api.stop(); });
    const place = async (over = {}) => (await api.post('/orders', form([{ pcId: pc.plain }], over))).body;
    const toStatus = (number, status, extra = {}) => api.post(`/admin/orders/${number}/status`, { status, ...extra }, { token: admin });

    it('only the admin can see or change orders', async () => {
        const placed = await place();
        assert.equal((await api.get('/admin/orders')).status, 401);
        assert.equal((await api.get(`/admin/orders/${placed.number}`)).status, 401);
        assert.equal((await api.post(`/admin/orders/${placed.number}/status`, { status: 'paid' })).status, 401);
        const member = await api.signUp('Snooper');
        assert.equal((await api.get('/admin/orders', { token: member.token })).status, 403);
    });

    it('the list has every detail but the link token, newest first, and filters by status', async () => {
        const second = await place({ customer: { firstName: 'Eleni', lastName: 'M', phone: '6900000001', email: 'eleni@gmail.com' } });
        const list = await api.get('/admin/orders', { token: admin });
        assert.equal(list.status, 200);
        assert.equal(list.body[0].number, second.number);
        assert.equal(list.body[0].customer.phone, '6900000001');
        assert.ok(list.body.every(o => !('accessTokenHash' in o)));
        await toStatus(second.number, 'paid');
        const paid = await api.get('/admin/orders?status=paid', { token: admin });
        assert.deepEqual(paid.body.map(o => o.number), [second.number]);
    });

    it('statuses only move forward; payment is stamped; sending unpaid needs force', async () => {
        const o = await place();
        assert.equal((await toStatus(o.number, 'nonsense')).status, 400);
        assert.equal((await toStatus(o.number, 'completed')).status, 400, 'completed is automatic');
        const shipUnpaid = await toStatus(o.number, 'shipped');
        assert.equal(shipUnpaid.status, 409);
        assert.equal(shipUnpaid.body.code, 'NOT_PAID');
        const paid = await toStatus(o.number, 'paid');
        assert.ok(paid.body.payment.paidAt);
        assert.equal((await toStatus(o.number, 'new')).status, 400, 'going back is refused');
        const shipped = await toStatus(o.number, 'shipped', { trackingNumber: 'ACS 123 456' });
        assert.equal(shipped.status, 200);
        assert.equal(shipped.body.delivery.trackingNumber, 'ACS 123 456');
        assert.deepEqual(shipped.body.history.map(h => h.status), ['new', 'paid', 'shipped']);

        const forced = await place();
        assert.equal((await toStatus(forced.number, 'shipped', { force: true })).status, 200);
    });

    it('delivery starts the return window; the window follows the setting, never under 14 days', async () => {
        const o = await place();
        await toStatus(o.number, 'paid');
        const d = await toStatus(o.number, 'delivered', { note: 'handed over' });
        const days = (new Date(d.body.returnDeadline) - new Date(d.body.deliveredAt)) / DAY;
        assert.equal(days, 14);
        assert.equal(d.body.history.at(-1).note, 'handed over');

        assert.equal((await api.post('/site-config', { returnDays: 7 }, { token: admin })).status, 400);
        assert.equal((await api.post('/site-config', { returnDays: 30 }, { token: admin })).status, 200);
        assert.equal((await api.get('/status')).body.orders.returnDays, 30);
        const o2 = await place();
        await toStatus(o2.number, 'paid');
        const d2 = await toStatus(o2.number, 'delivered');
        assert.equal((new Date(d2.body.returnDeadline) - new Date(d2.body.deliveredAt)) / DAY, 30);

        assert.equal((await api.post(`/admin/orders/${o.number}/cancel`, {}, { token: admin })).status, 409, 'a delivered order is not cancelled — it is returned');
    });

    it('a no-show cancels the order, gives the unit back, and warns on the next order from that phone', async () => {
        const before = await stockOf(api, pc.plain);
        const o = await place({ customer: { firstName: 'Ghost', lastName: 'X', phone: '6955555555', email: 'ghost@gmail.com' } });
        const r = await api.post(`/admin/orders/${o.number}/cancel`, { reason: 'no_show', note: 'never came' }, { token: admin });
        assert.equal(r.status, 200);
        assert.equal(r.body.noShow, true);
        assert.equal(r.body.cancelReason, 'no_show');
        assert.equal(await stockOf(api, pc.plain), before);

        const next = await place({ customer: { firstName: 'Ghost', lastName: 'X', phone: '6955555555', email: 'new-address@gmail.com' } });
        const detail = await api.get(`/admin/orders/${next.number}`, { token: admin });
        assert.equal(detail.body.priorNoShows, 1);
        const clean = await place();
        assert.equal((await api.get(`/admin/orders/${clean.number}`, { token: admin })).body.priorNoShows, 0);
    });

    it('the admin can change the hand-delivery areas; the checkout follows', async () => {
        assert.equal((await api.post('/site-config', { handDeliveryAreas: [] }, { token: admin })).status, 400);
        assert.equal((await api.post('/site-config', { handDeliveryAreas: ['Καλαμαριά', ' Θέρμη ', 'Θέρμη'], handDeliveryRadiusKm: 15 }, { token: admin })).status, 200);
        const o = (await api.get('/status')).body.orders;
        assert.deepEqual(o.handDeliveryAreas, ['Καλαμαριά', 'Θέρμη']);
        assert.equal(o.handDeliveryRadiusKm, 15);
        const outside = await api.post('/orders', form([{ pcId: pc.plain }], { delivery: { method: 'hand', area: 'Θεσσαλονίκη', address: 'A 1' } }));
        assert.equal(outside.status, 400);
    });
});

describe('live orders', () => {
    it('with ORDERS_LIVE on, orders are real and numbered PX-0001', async () => {
        const api = await startBackend({ env: { ORDERS_LIVE: 'true' } });
        try {
            const admin = await api.adminToken();
            const pcId = (await api.post('/drops', { name: 'REAL RIG', priceCents: 100000, stock: 1 }, { token: admin })).body._id;
            assert.equal((await api.get('/status')).body.orders.live, true);
            const r = await api.post('/orders', form([{ pcId }]));
            assert.equal(r.body.number, 'PX-0001');
            assert.equal(r.body.demo, false);
        } finally { await api.stop(); }
    });
});

describe('order emails', () => {
    const SHOP = 'shop@test.invalid';
    let api, admin, pc;
    before(async () => {
        api = await startBackend({ env: { ORDERS_NOTIFY_EMAIL: SHOP } });
        admin = await api.adminToken();
        pc = await shop(api, admin);
    });
    after(async () => { await api.stop(); });

    // Emails go out after the answer, so wait for the one wanted
    const waitForMail = async (match) => {
        for (let i = 0; i < 60; i++) {
            const m = api.mails().filter(match);
            if (m.length) return m.at(-1);
            await new Promise(r => setTimeout(r, 50));
        }
        throw new Error('expected email never arrived');
    };
    const count = (match) => api.mails().filter(match).length;

    it('a new order emails the customer, in Greek, with the private link that opens it', async () => {
        const r = await api.post('/orders', form([{ pcId: pc.rig, storage: 'ssd' }], { notes: 'Ring before, A & B' }));
        const mail = await waitForMail(m => m.to === 'nikos@gmail.com' && m.subject.includes(r.body.number));
        assert.equal(mail.subject, `[DEMO] Η παραγγελία ${r.body.number} καταχωρήθηκε`);
        assert.match(mail.text, /Δοκιμαστική παραγγελία/);
        assert.match(mail.text, /\+ 1TB SSD/);
        assert.match(mail.text, /1\.080,00 €/);
        assert.equal(mail.replyTo, SHOP, 'a reply from the customer must reach the shop');
        const link = mail.text.match(/\?order=([A-Z0-9-]+)&t=([a-f0-9]{48})/);
        assert.ok(link, 'the email carries the order page link');
        assert.equal((await api.get(`/orders/${link[1]}?t=${link[2]}`)).status, 200);
        assert.match(mail.html, /DEMO/);
    });

    it('the shop is told everything it needs, and nothing the customer typed can inject markup', async () => {
        const r = await api.post('/orders', form([{ pcId: pc.plain }], { notes: 'Gate code 1 & 2' }));
        const notice = await waitForMail(m => m.to === SHOP && m.subject.includes(r.body.number));
        assert.match(notice.subject, /^\[DEMO\] Νέα παραγγελία DEMO-\d{4} — 500,00 €$/);
        for (const piece of ['Nikos Papadopoulos', '6912345678', 'nikos@gmail.com', 'Egnatias 1, 54630 Thessaloniki', 'επισκέπτης', 'Απόδειξη', 'Gate code 1 & 2', 'PLAIN']) {
            assert.ok(notice.text.includes(piece), `missing from the shop notice: ${piece}`);
        }
        assert.equal(notice.replyTo, 'nikos@gmail.com', 'the shop can reply straight to the customer');
        assert.ok(notice.html.includes('Gate code 1 &amp; 2'), 'customer text must be escaped in the HTML');
    });

    it('an order placed in English is emailed in English', async () => {
        const r = await api.post('/orders', form([{ pcId: pc.plain }], { lang: 'en', customer: { firstName: 'Anna', lastName: 'Smith', phone: '6900000002', email: 'anna@gmail.com' } }));
        const mail = await waitForMail(m => m.to === 'anna@gmail.com');
        assert.equal(mail.subject, `[DEMO] Order ${r.body.number} placed`);
        assert.match(mail.text, /VIEW YOUR ORDER/);
    });

    it('a customer\'s cancellation emails them and the shop; the shop\'s own cancellation only the customer', async () => {
        const mine = (await api.post('/orders', form([{ pcId: pc.plain }]))).body;
        await waitForMail(m => m.to === SHOP && m.subject.includes(mine.number));
        await api.post(`/orders/${mine.number}/cancel`, { t: mine.accessToken });
        const toCustomer = await waitForMail(m => m.to === 'nikos@gmail.com' && m.subject === `Η παραγγελία ${mine.number} ακυρώθηκε`);
        assert.match(toCustomer.text, /δεν χρειάζεται να κάνεις τίποτα/);
        const toShop = await waitForMail(m => m.to === SHOP && m.subject.startsWith('[DEMO] Ακύρωση') && m.subject.includes(mine.number));
        assert.match(toShop.text, /Ο πελάτης ακύρωσε/);

        const theirs = (await api.post('/orders', form([{ pcId: pc.plain }]))).body;
        await waitForMail(m => m.to === SHOP && m.subject.includes(theirs.number));
        await api.post(`/admin/orders/${theirs.number}/cancel`, {}, { token: admin });
        await waitForMail(m => m.to === 'nikos@gmail.com' && m.subject === `Η παραγγελία ${theirs.number} ακυρώθηκε`);
        await new Promise(r => setTimeout(r, 300));
        assert.equal(count(m => m.to === SHOP && m.subject.startsWith('[DEMO] Ακύρωση') && m.subject.includes(theirs.number)), 0);
    });

    it('a paid order that is cancelled tells the customer the money comes back', async () => {
        const o = (await api.post('/orders', form([{ pcId: pc.plain }]))).body;
        await api.post(`/admin/orders/${o.number}/status`, { status: 'paid' }, { token: admin });
        await api.post(`/orders/${o.number}/cancel`, { t: o.accessToken });
        const mail = await waitForMail(m => m.to === 'nikos@gmail.com' && m.subject.includes(o.number) && m.subject.includes('ακυρώθηκε'));
        assert.match(mail.text, /επιστροφή των χρημάτων/);
        const shopMail = await waitForMail(m => m.to === SHOP && m.subject.includes('Ακύρωση') && m.subject.includes(o.number));
        assert.match(shopMail.text, /ΕΧΕΙ ΠΛΗΡΩΘΕΙ/);
    });

    it('the shop\'s notice warns when the phone has not turned up before', async () => {
        const ghost = { firstName: 'Ghost', lastName: 'X', phone: '6977777777', email: 'ghost@gmail.com' };
        const first = (await api.post('/orders', form([{ pcId: pc.plain }], { customer: ghost }))).body;
        await api.post(`/admin/orders/${first.number}/cancel`, { reason: 'no_show' }, { token: admin });
        const again = (await api.post('/orders', form([{ pcId: pc.plain }], { customer: { ...ghost, email: 'other@gmail.com' } }))).body;
        const notice = await waitForMail(m => m.to === SHOP && m.subject.includes(again.number));
        assert.match(notice.subject, /⚠$/);
        assert.match(notice.text, /ΠΡΟΣΟΧΗ: 1 προηγούμενη/);
    });
});
