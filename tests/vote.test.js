// The community vote: the admin starts an event, verified members vote once, and a drop that reaches
// its target (or whose timer runs out) turns into a regular PC in LIVE DROPS. Run: npm test

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startBackend } from './harness.js';

let api, admin;
let ann, ben, cleo;
before(async () => {
    api = await startBackend();
    admin = await api.adminToken();
    [ann, ben, cleo] = [await api.signUp('Annie'), await api.signUp('Benny'), await api.signUp('Cleo')];
});
after(async () => { await api.stop(); });

const startEvent = (over = {}) => api.post('/vote-event', {
    title: 'COMMUNITY RIG', image: 'https://img.example/rig.png', targetVotes: 2, priceCents: 250000,
    description: 'Voted in', lore: 'Born from the crowd', loreEl: 'Γεννήθηκε από το πλήθος',
    specs: { cpu: 'CPU X', gpu: 'GPU Y' }, fps: [{ game: 'Game', score: 144 }], ...over
}, { token: admin });

describe('vote event basics', () => {
    it('the admin starts an event; it always begins open, whatever status the request says', async () => {
        const r = await startEvent({ status: 'unlocked', pcId: '000000000000000000000000' });
        assert.equal(r.status, 200);
        assert.equal(r.body.status, 'open');
        assert.equal(r.body.currentVotes, 0);
        assert.equal(r.body.pcId, undefined);
    });

    // Pinned as it is today: the starting count comes from the admin's form (only status, pcId and
    // resolvedAt are reset), so an event can be seeded with votes.
    it('the admin can seed the starting vote count', async () => {
        assert.equal((await startEvent({ title: 'SEEDED', currentVotes: 1, targetVotes: 5 })).body.currentVotes, 1);
        assert.equal((await api.get('/vote-event')).body.currentVotes, 1);
        await startEvent();   // back to the event the rest of this file uses
    });

    it('visitors see it, without the list of who voted', async () => {
        const r = await api.get('/vote-event');
        assert.equal(r.body.title, 'COMMUNITY RIG');
        assert.equal(r.body.phase, 'open');
        assert.equal(r.body.hasVoted, false);
        assert.equal('votedBy' in r.body, false);
        assert.ok(r.body.serverNow);
    });

    it('a bad event is refused and the running one is left alone', async () => {
        const r = await startEvent({ priceCents: -1 });
        assert.equal(r.status, 400);
        assert.equal((await api.get('/vote-event')).body.title, 'COMMUNITY RIG');
    });

    it('only the admin can start or clear an event', async () => {
        assert.equal((await api.post('/vote-event', { title: 'x' })).status, 401);
        assert.equal((await api.post('/vote-event', { title: 'x' }, { token: ann.token })).status, 403);
        assert.equal((await api.del('/vote-event')).status, 401);
    });
});

describe('casting votes', () => {
    it('a vote needs a verified member', async () => {
        assert.equal((await api.post('/cast-vote')).status, 401);
        const unverified = await api.signUp('Unverified', { verify: false });
        assert.equal((await api.post('/cast-vote', undefined, { token: unverified.token })).status, 403);
    });

    it('counts a vote, earns the badge, and remembers who voted', async () => {
        const r = await api.post('/cast-vote', undefined, { token: ann.token });
        assert.equal(r.status, 200);
        assert.equal(r.body.votes, 1);
        assert.equal(r.body.hasVoted, true);
        assert.equal(r.body.phase, 'open');
        assert.ok(r.body.profile.achievements.includes('vote_caster'));
        assert.equal((await api.get('/vote-event', { token: ann.token })).body.hasVoted, true);
        assert.equal((await api.get('/vote-event', { token: ben.token })).body.hasVoted, false);
    });

    it('one vote per account', async () => {
        const r = await api.post('/cast-vote', undefined, { token: ann.token });
        assert.equal(r.status, 409);
        assert.equal(r.body.error, 'ALREADY VOTED');
        assert.equal(r.body.votes, 1);
    });

    it('two votes at the same instant from one account count once', async () => {
        const [a, b] = await Promise.all([
            api.post('/cast-vote', undefined, { token: ben.token }),
            api.post('/cast-vote', undefined, { token: ben.token })
        ]);
        // Ben's vote is the second one, which reaches the target of 2 and unlocks the drop
        assert.deepEqual([a.status, b.status].sort(), [200, 409]);
        const winner = a.status === 200 ? a : b;
        assert.equal(winner.body.votes, 2);
    });

    it('reaching the target turns the drop into a regular PC in LIVE DROPS', async () => {
        const ev = (await api.get('/vote-event')).body;
        assert.equal(ev.status, 'unlocked');
        assert.equal(ev.phase, 'unlocked');
        assert.ok(ev.pcId);
        const pc = (await api.get('/drops')).body.find(p => p._id === ev.pcId);
        assert.ok(pc, 'the unlocked drop is not in the catalogue');
        assert.equal(pc.name, 'COMMUNITY RIG');
        assert.equal(pc.priceCents, 250000);
        assert.equal(pc.status, 'available');
        assert.equal(pc.category, 'drop');
        assert.equal(pc.stock, 1);
        assert.equal(pc.communityDrop, true);
        assert.equal(pc.lore, 'Born from the crowd');
        assert.equal(pc.loreEl, 'Γεννήθηκε από το πλήθος');
        assert.deepEqual(pc.images, ['https://img.example/rig.png']);
        assert.equal(pc.fps[0].score, 144);
    });

    it('nobody can vote once the drop is unlocked', async () => {
        const r = await api.post('/cast-vote', undefined, { token: cleo.token });
        assert.equal(r.status, 409);
        assert.equal(r.body.code, 'VOTE_CLOSED');
    });

    it('with no event at all there is nothing to vote on', async () => {
        await api.del('/vote-event', { token: admin });
        assert.deepEqual((await api.get('/vote-event')).body, {});
        assert.equal((await api.post('/cast-vote', undefined, { token: cleo.token })).status, 404);
    });
});

describe('vote windows', () => {
    const day = 86400e3;

    it('before the start date voting is not open', async () => {
        await startEvent({ startDate: new Date(Date.now() + day), durationDays: 2 });
        const r = await api.post('/cast-vote', undefined, { token: cleo.token });
        assert.equal(r.status, 403);
        assert.equal(r.body.code, 'VOTE_NOT_OPEN');
    });

    it('an unlock inside the window gives members the drop first, until the vote would have ended', async () => {
        const start = new Date(Date.now() - 3600e3);
        await startEvent({ title: 'EARLY ACCESS RIG', targetVotes: 1, startDate: start, durationDays: 3 });
        const r = await api.post('/cast-vote', undefined, { token: cleo.token });
        assert.equal(r.body.phase, 'unlocked');
        const pc = (await api.get('/drops')).body.find(p => p._id === r.body.pcId);
        assert.equal(new Date(pc.membersOnlyUntil).getTime(), start.getTime() + 3 * day);
    });

    it('an expired vote closes on the next read, and a drop without a price is COMING SOON', async () => {
        await startEvent({ title: 'EXPIRED RIG', targetVotes: 50, priceCents: undefined, startDate: new Date(Date.now() - 3 * day), durationDays: 1 });
        const ev = (await api.get('/vote-event')).body;
        assert.equal(ev.status, 'closed');
        assert.equal(ev.phase, 'closed');
        const pc = (await api.get('/drops')).body.find(p => p._id === ev.pcId);
        assert.equal(pc.status, 'coming');
        assert.equal(pc.communityDrop, true);
        assert.equal(pc.membersOnlyUntil, undefined, 'a vote that timed out gives nobody early access');
        assert.equal((await api.post('/cast-vote', undefined, { token: ben.token })).status, 409);
    });

    it('opening the next event replaces the finished one', async () => {
        await startEvent({ title: 'NEXT RIG' });
        const ev = (await api.get('/vote-event')).body;
        assert.equal(ev.title, 'NEXT RIG');
        assert.equal(ev.status, 'open');
        assert.equal(await api.col('voteevents').countDocuments(), 1);
    });
});
