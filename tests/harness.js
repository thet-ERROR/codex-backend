// Starts the real server.js as a child process against a throw-away in-memory MongoDB, and gives
// the tests a small client for it. server.js itself is not touched or imported: the tests talk to it
// over HTTP exactly as the browser does, which is also what makes them survive splitting it up.
//
// SAFETY: the backend's own .env holds the production DB_URI. The environment given to the child
// always sets its own DB_URI, and this file refuses to start the server unless it is a local one.

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BACKEND_ROOT = path.resolve(HERE, '..');

export const ADMIN_PASSWORD = 'test-admin-password';
export const FRONTEND_ORIGIN = 'http://localhost:3000';

const freePort = () => new Promise((resolve, reject) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
    s.on('error', reject);
});

export async function startBackend() {
    const mongod = await MongoMemoryServer.create();
    const dbUri = mongod.getUri('codex-test');
    if (!/^mongodb:\/\/127\.0\.0\.1:\d+\//.test(dbUri)) {
        await mongod.stop();
        throw new Error(`refusing to start: test database is not local (${dbUri})`);
    }

    const port = await freePort();
    const mailFile = path.join(os.tmpdir(), `codex-test-mail-${process.pid}-${port}.jsonl`);
    fs.rmSync(mailFile, { force: true });

    const child = spawn(process.execPath, ['server.js'], {
        cwd: BACKEND_ROOT,
        env: {
            PATH: process.env.PATH, SystemRoot: process.env.SystemRoot,
            DB_URI: dbUri,
            JWT_SECRET: 'test-jwt-secret-not-used-anywhere-else',
            ADMIN_PASSWORD,
            FRONTEND_URL: FRONTEND_ORIGIN,
            MAILJET_API_KEY: 'test', MAILJET_SECRET_KEY: 'test', EMAIL_FROM: 'noreply@test.invalid',
            PORT: String(port), NODE_ENV: 'test',
            MAIL_CAPTURE_FILE: mailFile,
            NODE_OPTIONS: `--require ${path.join(HERE, 'mail-capture.cjs').replace(/\\/g, '/')}`
        },
        stdio: ['ignore', 'pipe', 'pipe']
    });

    let log = '';
    child.stdout.on('data', d => { log += d; });
    child.stderr.on('data', d => { log += d; });

    // Ready when the port answers AND the database is connected
    const base = `http://127.0.0.1:${port}/api`;
    const deadline = Date.now() + 60000;
    for (;;) {
        if (child.exitCode !== null) throw new Error(`server exited early:\n${log}`);
        if (log.includes('DATABASE CONNECTED')) {
            try { await fetch(`${base}/status`); break; } catch (e) { /* not listening yet */ }
        }
        if (Date.now() > deadline) { child.kill(); throw new Error(`server did not start in time:\n${log}`); }
        await new Promise(r => setTimeout(r, 150));
    }

    // A side door to the same database, for the things only the database can answer
    const conn = await mongoose.createConnection(dbUri).asPromise();
    const col = (name) => conn.db.collection(name);

    // The client: JSON in, { status, body, headers } out. Never throws on a 4xx/5xx — those are
    // exactly what many tests assert.
    const call = async (method, route, { body, token, headers = {} } = {}) => {
        const res = await fetch(base + route, {
            method,
            headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}), ...headers },
            body: body !== undefined ? JSON.stringify(body) : undefined
        });
        const text = await res.text();
        let json = null;
        try { json = text ? JSON.parse(text) : null; } catch (e) { /* not JSON */ }
        return { status: res.status, body: json, headers: res.headers, text };
    };

    const mails = () => (fs.existsSync(mailFile) ? fs.readFileSync(mailFile, 'utf8').trim().split('\n').filter(Boolean).map(l => JSON.parse(l)) : []);

    const backend = {
        url: base, call, col, mails,
        get: (r, o) => call('GET', r, o), post: (r, b, o) => call('POST', r, { ...o, body: b }),
        put: (r, b, o) => call('PUT', r, { ...o, body: b }), del: (r, o) => call('DELETE', r, o),
        async stop() {
            await conn.close();
            child.kill();
            await new Promise(r => child.once('exit', r));
            await mongod.stop();
            fs.rmSync(mailFile, { force: true });
        }
    };

    // --- shortcuts the tests share ---
    backend.adminToken = async () => {
        const r = await call('POST', '/login', { body: { password: ADMIN_PASSWORD } });
        if (!r.body || !r.body.token) throw new Error(`admin login failed: ${r.status} ${r.text}`);
        return r.body.token;
    };

    // The newest mail sent to an address, and the token inside it
    backend.lastMailTo = (email) => mails().filter(m => m.to === email).pop();
    backend.tokenFromMail = (mail, pattern) => (mail.text.match(pattern) || [])[1];

    // Registers through the API and follows the emailed link, like a real visitor. Returns the
    // session token and the credentials.
    backend.signUp = async (name, { verify = true } = {}) => {
        const email = `${name.toLowerCase()}@gmail.com`;
        const password = 'correct-horse-9';
        const reg = await call('POST', '/register', { body: { username: name, email, password, subscribed: false } });
        if (reg.status !== 200) throw new Error(`register failed: ${reg.status} ${reg.text}`);
        if (verify) {
            // The mail goes out in the background; wait for it to land
            for (let i = 0; i < 40 && !backend.lastMailTo(email); i++) await new Promise(r => setTimeout(r, 50));
            const token = backend.tokenFromMail(backend.lastMailTo(email), /\?verify=([a-f0-9]+)/);
            const ok = await call('POST', '/verify-email', { body: { token } });
            if (ok.status !== 200) throw new Error(`verify failed: ${ok.status} ${ok.text}`);
        }
        return { token: reg.body.token, username: name, email, password };
    };

    return backend;
}
