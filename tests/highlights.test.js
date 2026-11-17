// A PC's "strong points": up to three short lines per language that the admin writes ("Έξι πυρήνες: παίζει
// άνετα σε υψηλά γραφικά", "Αναβαθμίζεται εύκολα"). The storefront's assistant shows them when it recommends
// a PC. The shop's own words, so they are checked here: never more than three, never long, never markup.
// Run from this folder: npm test

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startBackend } from './harness.js';

let api, admin;
before(async () => { api = await startBackend(); admin = await api.adminToken(); });
after(async () => { await api.stop(); });

const make = (highlights) => api.post('/drops', { name: 'HL RIG', priceCents: 40000, ...(highlights !== undefined ? { highlights } : {}) }, { token: admin });
const fromList = async (id) => (await api.get('/drops')).body.find(p => p._id === id);

describe('a PC\'s strong points', () => {
    it('are saved in both languages, trimmed, empty lines dropped, and come back in the public list', async () => {
        const r = await make({ el: ['  Έξι πυρήνες: παίζει άνετα σε υψηλά γραφικά ', '', 'Αναβαθμίζεται εύκολα'], en: ['Six cores: plays smoothly on high settings'] });
        assert.equal(r.status, 200);
        const pc = await fromList(r.body._id);
        assert.deepEqual(pc.highlights, { el: ['Έξι πυρήνες: παίζει άνετα σε υψηλά γραφικά', 'Αναβαθμίζεται εύκολα'], en: ['Six cores: plays smoothly on high settings'] });
    });

    it('a PC saved without any has two empty lists, not nothing', async () => {
        const r = await make();
        assert.deepEqual((await fromList(r.body._id)).highlights, { el: [], en: [] });
    });

    it('an edit can change them, and an edit that doesn\'t mention them leaves them alone', async () => {
        const id = (await make({ el: ['Ένα'], en: ['One'] })).body._id;
        await api.put(`/drops/${id}`, { name: 'HL RIG MK2' }, { token: admin });
        assert.deepEqual((await fromList(id)).highlights, { el: ['Ένα'], en: ['One'] });
        const r = await api.put(`/drops/${id}`, { highlights: { el: ['Δύο', 'Τρία'], en: [] } }, { token: admin });
        assert.equal(r.status, 200);
        assert.deepEqual((await fromList(id)).highlights, { el: ['Δύο', 'Τρία'], en: [] });
    });

    it('refuses more than three in a language', async () => {
        const r = await make({ el: ['1', '2', '3', '4'], en: [] });
        assert.equal(r.status, 400);
        assert.match(r.body.error, /3/);
    });

    it('refuses a line over 90 characters', async () => {
        assert.equal((await make({ el: ['x'.repeat(91)], en: [] })).status, 400);
        assert.equal((await make({ el: ['x'.repeat(90)], en: [] })).status, 200);
    });

    it('refuses markup', async () => {
        assert.equal((await make({ el: ['<b>Γρήγορο</b>'], en: [] })).status, 400);
    });

    it('refuses anything that isn\'t two lists of text', async () => {
        assert.equal((await make('Γρήγορο')).status, 400);
        assert.equal((await make({ el: 'Γρήγορο', en: [] })).status, 400);
        assert.equal((await make({ el: [5], en: [] })).status, 400);
        const id = (await make({ el: ['Ένα'], en: [] })).body._id;
        assert.equal((await api.put(`/drops/${id}`, { highlights: ['x'] }, { token: admin })).status, 400);
        assert.deepEqual((await fromList(id)).highlights, { el: ['Ένα'], en: [] }, 'a refused edit changes nothing');
    });

    it('only the admin can set them', async () => {
        assert.equal((await api.post('/drops', { name: 'X', highlights: { el: ['a'], en: [] } })).status, 401);
    });
});
