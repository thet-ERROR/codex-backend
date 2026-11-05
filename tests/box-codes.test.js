// The review code in the box, closing an order once its return window is over, the "N deliveries"
// figure by the reviews, and the admin's own figures. Run: npm test
//
// Its own server with ORDERS_LIVE on: only real orders count as deliveries.

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startBackend } from './harness.js';

const DAY = 86400e3;

const form = (items, over = {}) => ({
    customer: { firstName: 'Nikos', lastName: 'Papadopoulos', phone: '6912345678', email: 'nikos@gmail.com' },
    delivery: { method: 'courier', address: 'Egnatias 1', postcode: '54630', city: 'Thessaloniki' },
    invoice: { type: 'receipt' },
    items, acceptTerms: true, adultOrGuardian: true, termsVersion: '2026-11',
    ...over
});

let api, admin, pcId, pc2Id;
before(async () => {
    api = await startBackend({ env: { ORDERS_LIVE: 'true' } });
    admin = await api.adminToken();
    pcId = (await api.post('/drops', { name: 'BOX RIG', priceCents: 50000, stock: 40 }, { token: admin })).body._id;
    pc2Id = (await api.post('/drops', { name: 'SECOND RIG', priceCents: 70000, stock: 10 }, { token: admin })).body._id;
});
after(async () => { await api.stop(); });

const place = async (items = [{ pcId }]) => (await api.post('/orders', form(items))).body;
const step = (o, status, extra = {}) => api.post(`/admin/orders/${o.number}/status`, { status, ...extra }, { token: admin });
const codesOf = async (o) => (await api.get(`/admin/orders/${o.number}`, { token: admin })).body.reviewCodes;
const view = async (o) => (await api.get(`/orders/${o.number}?t=${o.accessToken}`)).body;
const enter = (code) => api.post(`/check-code/${code}/activate`);
const review = (code, over = {}) => api.post('/submit-review', { code, user: 'Nikos', rating: 5, text: 'Runs great', ...over });
const packed = async (items) => {
    const o = await place(items);
    await step(o, 'paid');
    await step(o, 'packed');
    return o;
};

describe('the review code in the box', () => {
    it('is made when the order is packed — one per PC, never before, never twice', async () => {
        const o = await place([{ pcId }, { pcId: pc2Id }]);
        await step(o, 'paid');
        assert.deepEqual(await codesOf(o), [], 'no code before packing');
        const r = await step(o, 'packed');
        assert.equal(r.status, 200);
        assert.equal(r.body.reviewCodes.length, 2, 'the answer carries them, ready to print');
        assert.deepEqual(r.body.reviewCodes.map(c => c.pcName), ['BOX RIG', 'SECOND RIG']);
        assert.match(r.body.reviewCodes[0].code, /^CDX-[0-9A-F]{10}$/);
        await step(o, 'shipped');
        assert.deepEqual((await codesOf(o)).map(c => c.code), r.body.reviewCodes.map(c => c.code), 'the same codes after the next step');
        assert.equal((await view(o)).reviewCodes, undefined, "the customer's page never shows them — they are in the box");
    });

    it('skipping straight past packed still makes them', async () => {
        const o = await place();
        await step(o, 'paid');
        await step(o, 'delivered');
        assert.equal((await codesOf(o)).length, 1);
    });

    it('a code waiting in the box has no clock running; entering it marks the order delivered', async () => {
        const o = await packed();
        await step(o, 'shipped');
        const [{ code }] = await codesOf(o);
        const before = (await api.get(`/check-code/${code}`)).body;
        assert.equal(before.valid, true);
        assert.equal(before.activated, false, 'nothing starts until the customer enters it');
        assert.equal((await view(o)).status, 'shipped', 'checking the code changes nothing');

        const a = await enter(code);
        assert.equal(a.status, 200);
        assert.equal(a.body.expired, false);
        const days = a.body.timeLeft / DAY;
        assert.ok(days > 13.9 && days <= 14, `two weeks to write the review, got ${days}`);
        const v = await view(o);
        assert.equal(v.status, 'delivered');
        assert.ok(v.deliveredAt);
        assert.equal(v.canReturn, true, 'the return window runs from that moment');
        const order = await api.col('orders').findOne({ number: o.number });
        assert.equal(order.history.at(-1).by, 'customer');

        const again = await enter(code);
        assert.ok(Math.abs(again.body.timeLeft - a.body.timeLeft) < 5000, 'entering it again never resets the clock');
    });

    it('when the admin marked it delivered, the two weeks run from that day', async () => {
        const o = await packed();
        await step(o, 'delivered');
        const [{ code }] = await codesOf(o);
        await api.col('orders').updateOne({ number: o.number }, { $set: { deliveredAt: new Date(Date.now() - 10 * DAY) } });
        const left = (await enter(code)).body.timeLeft / DAY;
        assert.ok(left > 3.9 && left < 4.1, `4 days left, got ${left}`);

        await api.col('orders').updateOne({ number: o.number }, { $set: { deliveredAt: new Date(Date.now() - 15 * DAY) } });
        assert.equal((await api.get(`/check-code/${code}`)).body.expired, true);
        const r = await review(code);
        assert.equal(r.status, 403, 'no review after the two weeks');
    });

    it('a review with it is a verified purchase, and the code works once', async () => {
        const o = await packed();
        await step(o, 'delivered');
        const [{ code }] = await codesOf(o);
        assert.equal((await review(code, { text: 'Silent and fast' })).status, 200);
        assert.equal((await review(code)).status, 409);
        const pc = (await api.get('/drops')).body.find(p => p._id === pcId);
        const mine = pc.reviews.find(r => r.text === 'Silent and fast');
        assert.equal(mine.verified, true);
        assert.equal((await codesOf(o))[0].status, 'used');
    });

    it("writing the review straight away counts as entering the code", async () => {
        const o = await packed();
        await step(o, 'shipped');
        const [{ code }] = await codesOf(o);
        assert.equal((await review(code)).status, 200);
        assert.equal((await view(o)).status, 'delivered');
    });

    it("a review the admin types in by hand is not marked verified", async () => {
        await api.post(`/drops/${pcId}/reviews`, { user: 'Shop', text: 'Typed by hand', rating: 5 }, { token: admin });
        const pc = (await api.get('/drops')).body.find(p => p._id === pcId);
        assert.notEqual(pc.reviews.find(r => r.text === 'Typed by hand').verified, true);
    });

    it("a cancelled order's codes stop working", async () => {
        const o = await packed();
        const [{ code }] = await codesOf(o);
        await api.post(`/admin/orders/${o.number}/cancel`, { reason: 'admin' }, { token: admin });
        assert.equal((await api.get(`/check-code/${code}`)).body.valid, false);
        assert.equal((await enter(code)).status, 404);
        assert.equal((await review(code)).status, 400);
    });

    it('a code made by hand in the panel keeps its 48 hours from first entry', async () => {
        const t = (await api.post('/generate-code', { pcId, pcName: 'BOX RIG' }, { token: admin })).body;
        const left = (await enter(t.code)).body.timeLeft / 3600e3;
        assert.ok(left > 47.9 && left <= 48, `48 hours, got ${left}`);
    });
});

describe('closing an order after the return window', () => {
    const deliveredAgo = async (days) => {
        const o = await packed();
        await step(o, 'delivered');
        const at = new Date(Date.now() - days * DAY);
        await api.col('orders').updateOne({ number: o.number }, { $set: { deliveredAt: at, returnDeadline: new Date(at.getTime() + 14 * DAY) } });
        return o;
    };

    it('completes on its own once the window is over, dated at the deadline', async () => {
        const o = await deliveredAgo(15);
        const v = await view(o);
        assert.equal(v.status, 'completed');
        const order = await api.col('orders').findOne({ number: o.number });
        const last = order.history.at(-1);
        assert.equal(last.by, 'auto');
        assert.equal(new Date(last.at).getTime(), new Date(order.returnDeadline).getTime());
        assert.equal(v.canReportProblem, true, 'the guarantee goes on after completion');
    });

    it('stays delivered while inside the window', async () => {
        const o = await deliveredAgo(5);
        assert.equal((await view(o)).status, 'delivered');
    });

    it('an open return holds it until the admin has handled it', async () => {
        const o = await deliveredAgo(10);
        await api.post(`/orders/${o.number}/request`, { t: o.accessToken, type: 'return', message: 'Sending it back' });
        await api.col('orders').updateOne({ number: o.number }, { $set: { returnDeadline: new Date(Date.now() - DAY) } });
        assert.equal((await view(o)).status, 'delivered');
        const detail = (await api.get(`/admin/orders/${o.number}`, { token: admin })).body;
        await api.post(`/admin/orders/${o.number}/requests/${detail.requests[0]._id}/handle`, { note: 'refused' }, { token: admin });
        assert.equal((await view(o)).status, 'completed');
    });

    it('the admin can never set completed by hand', async () => {
        const o = await deliveredAgo(1);
        assert.equal((await step(o, 'completed')).status, 400);
    });
});

describe('"N deliveries" and the admin figures', () => {
    it('counts only real, completed orders with no return, and only from the threshold up', async () => {
        await api.post('/site-config', { deliveriesBadgeMin: 1 }, { token: admin });
        // Clear out what the tests above completed, so the count starts from zero here
        await api.col('orders').deleteMany({});
        await api.get('/admin/orders', { token: admin });
        const now = Date.now();
        const past = { deliveredAt: new Date(now - 20 * DAY), returnDeadline: new Date(now - 6 * DAY) };
        const base = { items: [], requests: [], history: [], customer: {} };
        await api.col('orders').insertMany([
            { ...base, number: 'PX-9001', demo: false, status: 'delivered', ...past },
            { ...base, number: 'PX-9002', demo: false, status: 'delivered', ...past },
            { ...base, number: 'PX-9003', demo: false, status: 'delivered', ...past, requests: [{ type: 'return', message: 'x', createdAt: new Date(), handledAt: new Date() }] },
            { ...base, number: 'PX-9004', demo: false, status: 'delivered', deliveredAt: new Date(), returnDeadline: new Date(now + 14 * DAY), requests: [{ type: 'problem', message: 'fan', createdAt: new Date() }] },
            { ...base, number: 'DEMO-9001', demo: true, status: 'completed', ...past }
        ]);
        const stats = (await api.get('/admin/order-stats', { token: admin })).body;   // completes the due ones
        assert.equal(stats.live.publicCount, 2, 'a returned PC and a DEMO order are not counted');
        assert.equal(stats.live.delivered, 4);
        assert.equal(stats.live.completed, 3);
        assert.equal(stats.live.inReturnWindow, 1);
        assert.equal(stats.live.returns, 1);
        assert.equal(stats.live.problems, 1);
        assert.equal(stats.live.openRequests, 1);
        assert.equal(stats.demo.completed, 1);
        assert.equal((await api.get('/admin/order-stats')).status, 401, 'never public');

        assert.equal((await api.get('/status')).body.deliveries, 2);
        await api.post('/site-config', { deliveriesBadgeMin: 3 }, { token: admin });
        assert.equal((await api.get('/status')).body.deliveries, null, 'under the threshold nothing is shown');
        await api.post('/site-config', { deliveriesBadgeMin: 2, deliveriesBadgeOn: false }, { token: admin });
        assert.equal((await api.get('/status')).body.deliveries, null, 'switched off');
        const s = (await api.get('/status')).body;
        assert.equal(JSON.stringify(s).includes('problem'), false, 'the public answer says nothing about problems');
    });

    it('the switch and threshold are checked', async () => {
        assert.equal((await api.post('/site-config', { deliveriesBadgeMin: 0 }, { token: admin })).status, 400);
        assert.equal((await api.post('/site-config', { deliveriesBadgeMin: 2.5 }, { token: admin })).status, 400);
        assert.equal((await api.post('/site-config', { deliveriesBadgeOn: 'yes' }, { token: admin })).status, 400);
    });
});
