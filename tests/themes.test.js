// The five themes that replaced the thirteen accent colours (Nov 2026): what an account can wear, and that
// nobody who won a colour before loses it. Run from this folder: npm test

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { startBackend } from './harness.js';

const require = createRequire(import.meta.url);
const { themesFor, grantTheme, THEME_OF_COLOR } = require('../src/lib/themes');
const { WHEEL_SLICES } = require('../src/lib/wheel');
const { grantRankRewards } = require('../src/lib/achievements');

const ALL = ['graphite', 'phoenix', 'nebula', 'inferno', 'arctic', 'phantom'];
const OLD_COLORS = ['cyberGold', 'toxicOrange', 'neonPink', 'matrixGreen', 'ultraviolet', 'arctic', 'phantom', 'cheatCode'];

describe('themes: who can wear what', () => {
    it('a new account has the two free themes and nothing else', () => {
        assert.deepEqual(themesFor({}), ['graphite', 'phoenix', 'nebula']);
    });

    it('every colour that could be won before opens a theme (nobody loses a win)', () => {
        for (const c of OLD_COLORS) assert.ok(ALL.includes(THEME_OF_COLOR[c]), `${c} opens nothing`);
        assert.deepEqual(themesFor({ unlockedColors: OLD_COLORS }), ALL);
    });

    it('the old rank colour "phantom" opens Arctic, not the Konami theme of the same name', () => {
        assert.deepEqual(themesFor({ unlockedColors: ['phantom'] }), ['graphite', 'phoenix', 'nebula', 'arctic']);
        assert.deepEqual(themesFor({ unlockedColors: ['cheatCode'] }), ['graphite', 'phoenix', 'nebula', 'phantom']);
        assert.deepEqual(themesFor({ unlockedColors: ['neonPink'] }), ['graphite', 'phoenix', 'nebula', 'inferno']);
    });

    it('unknown names in either list are ignored, and the order is always the same', () => {
        assert.deepEqual(themesFor({ unlockedThemes: ['phantom', 'made-up', 'inferno'], unlockedColors: ['nope'] }), ['graphite', 'phoenix', 'nebula', 'inferno', 'phantom']);
    });

    it('granting a theme the account already has (from an old colour) stores nothing and says so', () => {
        const u = { unlockedColors: ['toxicOrange'], unlockedThemes: [] };
        assert.equal(grantTheme(u, 'inferno'), false);
        assert.deepEqual(u.unlockedThemes, []);
        assert.equal(grantTheme(u, 'arctic'), true);
        assert.equal(grantTheme(u, 'arctic'), false);
        assert.deepEqual(u.unlockedThemes, ['arctic']);
        assert.deepEqual(u.unlockedColors, ['toxicOrange'], 'the old list is never touched');
    });
});

describe('themes: where they come from', () => {
    it('the wheel: one Inferno slice, four coupons, three blanks', () => {
        const count = (t) => WHEEL_SLICES.filter(s => s.type === t).length;
        assert.equal(WHEEL_SLICES.length, 8);
        assert.deepEqual([count('theme'), count('coupon'), count('blank')], [1, 4, 3]);
        assert.equal(WHEEL_SLICES.find(s => s.type === 'theme').id, 'inferno');
        assert.equal(count('color'), 0);
    });

    it('the ranks: Arctic at Elite Agent, and every rank on the way still pays', () => {
        const u = { unlockedColors: [], unlockedThemes: [], rankRewardsClaimed: [], bonusSpins: 0 };
        grantRankRewards(u, 699);
        assert.ok(!themesFor(u).includes('arctic'), 'not before 700 XP');
        assert.equal(u.bonusSpins, 4, 'operative 1 + field agent 1 + specialist 2');
        const g = grantRankRewards(u, 700);
        assert.deepEqual(g, [{ rank: 'eliteAgent', theme: 'arctic', spins: 1 }]);
        assert.ok(themesFor(u).includes('arctic'));
        assert.deepEqual(grantRankRewards(u, 700), [], 'paid once');
    });

    it('an account that was paid its rank colours before is not paid again, and keeps Arctic', () => {
        const u = { unlockedColors: ['ultraviolet', 'arctic'], unlockedThemes: [], rankRewardsClaimed: ['recruit', 'operative', 'fieldAgent', 'specialist', 'eliteAgent'], bonusSpins: 0 };
        assert.deepEqual(grantRankRewards(u, 800), []);
        assert.equal(u.bonusSpins, 0);
        assert.deepEqual(u.unlockedThemes, [], 'Arctic comes from the old colours, nothing new is stored');
        assert.ok(themesFor(u).includes('arctic'));
    });
});

describe('themes: through the API', () => {
    let api;
    before(async () => { api = await startBackend(); });
    after(async () => { await api.stop(); });

    it('/me and /wheel list the themes; an account with old colours sees their themes and keeps the colours', async () => {
        const me = await api.signUp('OldTimer');
        const fresh = (await api.get('/me', { token: me.token })).body;
        assert.deepEqual(fresh.unlockedThemes, ['graphite', 'phoenix', 'nebula']);

        await api.col('users').updateOne({ username: 'OldTimer' }, { $set: { unlockedColors: ['matrixGreen', 'phantom'] } });
        const r = await api.get('/me', { token: me.token });
        assert.deepEqual(r.body.unlockedThemes, ['graphite', 'phoenix', 'nebula', 'inferno', 'arctic']);
        assert.deepEqual(r.body.unlockedColors, ['matrixGreen', 'phantom'], 'still sent, for a frontend from before the themes');
        assert.deepEqual((await api.get('/wheel', { token: me.token })).body.unlockedThemes, ['graphite', 'phoenix', 'nebula', 'inferno', 'arctic']);

        const stored = await api.col('users').findOne({ username: 'OldTimer' });
        assert.deepEqual(stored.unlockedColors, ['matrixGreen', 'phantom'], 'the stored colours are not rewritten');
    });

    it('a spin answers with the themes too, and a theme win on an account that has it is "already yours"', async () => {
        const me = await api.signUp('ThemeSpinner');
        // Inferno already open (an old wheel colour), so whatever the spin lands on, nothing is stored twice
        await api.col('users').updateOne({ username: 'ThemeSpinner' }, { $set: { unlockedColors: ['cyberGold'] } });
        const r = await api.post('/wheel/spin', undefined, { token: me.token });
        assert.equal(r.status, 200);
        assert.ok(r.body.unlockedThemes.includes('inferno'));
        if (r.body.reward.type === 'theme') assert.equal(r.body.reward.alreadyUnlocked, true);
        const stored = await api.col('users').findOne({ username: 'ThemeSpinner' });
        assert.ok(!(stored.unlockedThemes || []).includes('inferno'));
    });
});
