// After delivery: a return (inside the return window) and a problem under the 2-year guarantee,
// recorded on the order, emailed to both sides, and closed by the admin. Run: npm test
//
// Placing orders is limited to 20 an hour per address, so this file has a server of its own.

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startBackend } from './harness.js';

const DAY = 86400e3;
const SHOP = 'shop@test.invalid';

const form = (items, over = {}) => ({
    customer: { firstName: 'Nikos', lastName: 'Papadopoulos', phone: '6912345678', email: 'nikos@gmail.com' },
    delivery: { method: 'courier', address: 'Egnatias 1', postcode: '54630', city: 'Thessaloniki' },
    invoice: { type: 'receipt' },
    items, acceptTerms: true, adultOrGuardian: true, termsVersion: '2026-11',
    ...over
});

let api, admin, pcId;
before(async () => {
    api = await startBackend({ env: { ORDERS_NOTIFY_EMAIL: SHOP } });
    admin = await api.adminToken();
    pcId = (await api.post('/drops', { name: 'RETURN RIG', priceCents: 50000, stock: 30 }, { token: admin })).body._id;
});
after(async () => { await api.stop(); });

// An order taken to "delivered" by the admin, as it would be in the shop
const delivered = async (over = {}) => {
    const placed = (await api.post('/orders', form([{ pcId }], over))).body;
    await api.post(`/admin/orders/${placed.number}/status`, { status: 'paid' }, { token: admin });
    await api.post(`/admin/orders/${placed.number}/status`, { status: 'delivered' }, { token: admin });
    return placed;
};
const ask = (o, type, message = 'It does not turn on at all', opts) => api.post(`/orders/${o.number}/request`, { t: o.accessToken, type, message }, opts);
const view = async (o) => (await api.get(`/orders/${o.number}?t=${o.accessToken}`)).body;
const waitForMail = async (match) => {
    for (let i = 0; i < 60; i++) { const m = api.mails().filter(match); if (m.length) return m.at(-1); await new Promise(r => setTimeout(r, 50)); }
    throw new Error('expected email never arrived');
};

describe('returns and guarantee problems', () => {
    it('nothing can be asked before the order is delivered', async () => {
        const o = (await api.post('/orders', form([{ pcId }]))).body;
        const v = await view(o);
        assert.equal(v.canReturn, false);
        assert.equal(v.canReportProblem, false);
        const r = await ask(o, 'return');
        assert.equal(r.status, 409);
        assert.match(r.body.error, /delivered/);
    });

    it('once delivered, the page offers both, with the guarantee running two years', async () => {
        const o = await delivered();
        const v = await view(o);
        assert.equal(v.canReturn, true);
        assert.equal(v.canReportProblem, true);
        const years = (new Date(v.warrantyUntil) - new Date(v.deliveredAt)) / (365 * DAY);
        assert.ok(years > 1.99 && years < 2.01);
    });

    it('a return is recorded on the order and both sides are emailed', async () => {
        const o = await delivered({ customer: { firstName: 'Rita', lastName: 'Return', phone: '6911111111', email: 'rita@gmail.com' } });
        const r = await ask(o, 'return', 'Changed my mind <b>sorry</b>');
        assert.equal(r.status, 200);
        assert.deepEqual(r.body.order.requests.map(x => [x.type, x.handled]), [['return', false]]);
        assert.equal(r.body.order.canReturn, false, 'one open request of a kind at a time');
        assert.equal(r.body.order.canReportProblem, true);

        const shopMail = await waitForMail(m => m.to === SHOP && m.subject.includes('Αίτημα επιστροφής') && m.subject.includes(o.number));
        assert.match(shopMail.text, /Rita Return/);
        assert.match(shopMail.text, /6911111111/);
        assert.match(shopMail.text, /Changed my mind <b>sorry<\/b>/);
        assert.ok(shopMail.html.includes('&lt;b&gt;sorry&lt;/b&gt;'), "the customer's words are escaped in the HTML");
        assert.equal(shopMail.replyTo, 'rita@gmail.com');
        const ack = await waitForMail(m => m.to === 'rita@gmail.com' && m.subject.includes('Αίτημα επιστροφής'));
        assert.match(ack.text, /Λάβαμε το αίτημά σου/);
    });

    it('a second open request of the same kind is refused, even two at once; the other kind is fine', async () => {
        const o = await delivered();
        const [a, b] = await Promise.all([ask(o, 'problem', 'No picture on the screen'), ask(o, 'problem', 'No picture on the screen')]);
        assert.deepEqual([a.status, b.status].sort(), [200, 409]);
        assert.equal((await ask(o, 'return')).status, 200);
        assert.equal((await api.col('orders').findOne({ number: o.number })).requests.length, 2);
    });

    it('a request needs words, and only of a known kind', async () => {
        const o = await delivered();
        assert.equal((await ask(o, 'return', '  ')).status, 400);
        assert.equal((await ask(o, 'return', 'ok')).status, 400);
        assert.equal((await ask(o, 'refund')).status, 409);
        const long = await ask(o, 'problem', 'x'.repeat(5000));
        assert.equal(long.status, 200);
        assert.equal((await api.col('orders').findOne({ number: o.number })).requests[0].message.length, 1000);
    });

    it('a return after the return window is refused; a problem still goes through', async () => {
        const o = await delivered();
        await api.col('orders').updateOne({ number: o.number }, { $set: { returnDeadline: new Date(Date.now() - DAY) } });
        const ret = await ask(o, 'return');
        assert.equal(ret.status, 409);
        assert.match(ret.body.error, /return window/);
        assert.equal((await view(o)).canReturn, false);
        assert.equal((await ask(o, 'problem')).status, 200);
    });

    it('after two years the guarantee has ended too', async () => {
        const o = await delivered();
        await api.col('orders').updateOne({ number: o.number }, { $set: { deliveredAt: new Date(Date.now() - 731 * DAY) } });
        const r = await ask(o, 'problem');
        assert.equal(r.status, 409);
        assert.match(r.body.error, /guarantee/);
    });

    it("only the link's token or the member who ordered can ask", async () => {
        const owner = await api.signUp('Buyer2');
        const stranger = await api.signUp('Stranger2');
        const placed = (await api.post('/orders', form([{ pcId }]), { token: owner.token })).body;
        await api.post(`/admin/orders/${placed.number}/status`, { status: 'delivered', force: true }, { token: admin });
        const body = { type: 'problem', message: 'It makes a noise' };
        assert.equal((await api.post(`/orders/${placed.number}/request`, body)).status, 404);
        assert.equal((await api.post(`/orders/${placed.number}/request`, { ...body, t: '0'.repeat(48) })).status, 404);
        assert.equal((await api.post(`/orders/${placed.number}/request`, body, { token: stranger.token })).status, 404);
        assert.equal((await api.post(`/orders/${placed.number}/request`, body, { token: owner.token })).status, 200);
    });

    it('the admin sees open requests and closes them with a note; a closed kind can be asked again', async () => {
        const o = await delivered();
        await ask(o, 'problem', 'Fan rattles');
        const detail = (await api.get(`/admin/orders/${o.number}`, { token: admin })).body;
        assert.equal(detail.openRequests, 1);
        const id = detail.requests[0]._id;
        const list = (await api.get('/admin/orders', { token: admin })).body;
        assert.equal(list.find(x => x.number === o.number).openRequests, 1);

        assert.equal((await api.post(`/admin/orders/${o.number}/requests/${id}/handle`, {})).status, 401);
        const done = await api.post(`/admin/orders/${o.number}/requests/${id}/handle`, { note: 'sent a new fan' }, { token: admin });
        assert.equal(done.status, 200);
        assert.equal(done.body.openRequests, 0);
        assert.equal(done.body.requests[0].handledNote, 'sent a new fan');
        assert.equal((await api.post(`/admin/orders/${o.number}/requests/${id}/handle`, {}, { token: admin })).status, 404, 'handled once');
        assert.equal((await view(o)).requests[0].handled, true);
        assert.equal((await ask(o, 'problem', 'Rattles again')).status, 200);
        assert.equal((await api.post(`/admin/orders/${o.number}/requests/not-an-id/handle`, {}, { token: admin })).status, 400);
    });
});
