// The admin side: sign-in, the PC catalogue (create / read / edit / delete, prices, reviews) and the
// read cache that must never serve a stale catalogue. Run from this folder: npm test

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startBackend, ADMIN_PASSWORD } from './harness.js';

let api, admin;
before(async () => { api = await startBackend(); admin = await api.adminToken(); });
after(async () => { await api.stop(); });

const ids = {};

describe('admin PCs', () => {
    it('create: a PC is saved with its price in cents, and the old text price mirrored', async () => {
        const r = await api.post('/drops', { name: 'RIG ONE', priceCents: 129900, stock: 2, category: 'drop' }, { token: admin });
        assert.equal(r.status, 200);
        assert.equal(r.body.priceCents, 129900);
        assert.equal(r.body.price, '1299');
        assert.equal(r.body.stock, 2);
        assert.equal(r.body.status, 'available');
        ids.one = r.body._id;
    });

    it('create: a legacy text price is turned into cents', async () => {
        const r = await api.post('/drops', { name: 'RIG TWO', price: '€1.200', category: 'drop' }, { token: admin });
        assert.equal(r.status, 200);
        assert.equal(r.body.priceCents, 120000);
        ids.two = r.body._id;
    });

    it('create: a nonsense price is refused', async () => {
        const r = await api.post('/drops', { name: 'BAD', priceCents: -5 }, { token: admin });
        assert.equal(r.status, 400);
    });

    it('the public list shows a new PC at once (the read cache is cleared by writes)', async () => {
        const warm = await api.get('/drops');                 // fills the cache
        assert.equal(warm.body.length, 2);
        const made = await api.post('/drops', { name: 'RIG THREE', priceCents: 50000 }, { token: admin });
        const after = await api.get('/drops');
        assert.equal(after.body.length, 3, 'a stale cached list was served after a write');
        assert.ok(after.body.some(p => p._id === made.body._id));
        ids.three = made.body._id;
    });

    it('edit: changes the PC and shows up in the list at once', async () => {
        const r = await api.put(`/drops/${ids.one}`, { name: 'RIG ONE MK2', stock: 5 }, { token: admin });
        assert.equal(r.status, 200);
        assert.equal(r.body.name, 'RIG ONE MK2');
        const list = await api.get('/drops');
        assert.equal(list.body.find(p => p._id === ids.one).stock, 5);
    });

    it('edit: an unknown or malformed id is a clean error', async () => {
        assert.equal((await api.put('/drops/000000000000000000000000', { name: 'x' }, { token: admin })).status, 404);
        assert.equal((await api.put('/drops/not-an-id', { name: 'x' }, { token: admin })).status, 400);
    });

    it('edit: the admin panel can never overwrite customer reviews with a stale copy', async () => {
        await api.post(`/drops/${ids.one}/reviews`, { user: 'Nikos', text: 'Great', rating: 5 }, { token: admin });
        // The panel saves the PC with the (old, empty) review list it loaded
        await api.put(`/drops/${ids.one}`, { name: 'RIG ONE MK3', reviews: [] }, { token: admin });
        const pc = (await api.get('/drops')).body.find(p => p._id === ids.one);
        assert.equal(pc.name, 'RIG ONE MK3');
        assert.equal(pc.reviews.length, 1, 'the review was wiped by an admin save');
    });

    it('reviews: added one at a time, validated, and removable', async () => {
        const bad = await api.post(`/drops/${ids.one}/reviews`, { user: 'x', text: 'y', rating: 9 }, { token: admin });
        assert.equal(bad.status, 400);
        const none = await api.post(`/drops/${ids.one}/reviews`, { user: '', text: 'y', rating: 3 }, { token: admin });
        assert.equal(none.status, 400);
        const ok = await api.post(`/drops/${ids.one}/reviews`, { user: 'Maria', text: 'Fast', rating: 4 }, { token: admin });
        assert.equal(ok.status, 200);
        assert.equal(ok.body.reviews.length, 2);
        const reviewId = ok.body.reviews[1]._id;
        const del = await api.del(`/drops/${ids.one}/reviews/${reviewId}`, { token: admin });
        assert.equal(del.status, 200);
        assert.equal(del.body.reviews.length, 1);
    });

    it('delete: removes the PC', async () => {
        const r = await api.del(`/drops/${ids.three}`, { token: admin });
        assert.equal(r.status, 200);
        const list = await api.get('/drops');
        assert.ok(!list.body.some(p => p._id === ids.three));
    });
});

describe('admin sign-in', () => {
    it('a user session is not an admin session', async () => {
        const user = await api.signUp('Plainuser');
        const r = await api.get('/users', { token: user.token });
        assert.equal(r.status, 403);
    });

    it('a garbage token is refused', async () => {
        assert.equal((await api.get('/users', { token: 'nonsense' })).status, 401);
    });

    it('admin can list users and count them', async () => {
        const list = await api.get('/users', { token: admin });
        assert.equal(list.status, 200);
        assert.ok(list.body.some(u => u.username === 'Plainuser'));
        assert.equal((await api.get('/users/count', { token: admin })).body.count, 1);
    });

    it('site config: read and saved by the admin, and public through /status', async () => {
        const read = await api.get('/site-config', { token: admin });
        assert.equal(read.status, 200);
        const save = await api.post('/site-config', { proConfigPrice: 45 }, { token: admin });
        assert.equal(save.status, 200);
        assert.equal((await api.get('/status')).body.proConfigPrice, 45);
    });

    it('maintenance mode: visitors get a 503 everywhere but /status, the admin carries on', async () => {
        await api.post('/site-config', { maintenanceMode: true, maintenanceMessage: 'BACK SOON' }, { token: admin });
        const s = await api.get('/status');
        assert.equal(s.body.maintenance, true);
        assert.equal(s.body.message, 'BACK SOON');
        const visitor = await api.get('/drops');
        assert.equal(visitor.status, 503);
        assert.deepEqual(visitor.body, { maintenance: true, message: 'BACK SOON' });
        assert.equal((await api.get('/drops', { token: admin })).status, 200);
        await api.post('/site-config', { maintenanceMode: false }, { token: admin });
        assert.equal((await api.get('/status')).body.maintenance, false);
        assert.equal((await api.get('/drops')).status, 200);
    });

    // Last on purpose: five wrong passwords lock the admin out for 15 minutes.
    it('wrong password is refused, and repeated failures lock the account — even for the right password', async () => {
        const fresh = await startBackend();
        try {
            for (let i = 0; i < 5; i++) {
                const bad = await fresh.post('/login', { password: 'wrong' });
                assert.equal(bad.status, 403, `attempt ${i + 1}`);
            }
            const locked = await fresh.post('/login', { password: ADMIN_PASSWORD });
            assert.equal(locked.status, 429);
            assert.match(locked.body.error, /Too many failed attempts/);
        } finally { await fresh.stop(); }
    });
});
