// Time-based one-time passwords (RFC 6238 over RFC 4226 HOTP) — what Google Authenticator and every
// other authenticator app computes: HMAC-SHA1 of the 30-second step counter, truncated to 6 digits.
// Written here on Node's crypto rather than pulled in as a package: it is a few lines, fully
// specified, and checked against the RFC's own test vectors (tests/totp.test.js).
const crypto = require('crypto');

const STEP_SECONDS = 30;
const DIGITS = 6;
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buf) {
    let bits = 0, value = 0, out = '';
    for (const byte of buf) {
        value = (value << 8) | byte;
        bits += 8;
        while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
    }
    if (bits > 0) out += B32[(value << (5 - bits)) & 31];
    return out;
}

function base32Decode(str) {
    const clean = String(str).toUpperCase().replace(/[\s=-]/g, '');
    let bits = 0, value = 0;
    const out = [];
    for (const ch of clean) {
        const idx = B32.indexOf(ch);
        if (idx < 0) throw new Error('not base32');
        value = (value << 5) | idx;
        bits += 5;
        if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
    }
    return Buffer.from(out);
}

// 20 random bytes = 160 bits, the size RFC 4226 recommends for HMAC-SHA1
const generateSecret = () => crypto.randomBytes(20);

const stepAt = (ms = Date.now()) => Math.floor(ms / 1000 / STEP_SECONDS);

function hotp(secret, counter, digits = DIGITS) {
    const msg = Buffer.alloc(8);
    msg.writeBigUInt64BE(BigInt(counter));
    const mac = crypto.createHmac('sha1', secret).update(msg).digest();
    const offset = mac[mac.length - 1] & 0x0f;
    const bin = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
    return String(bin % 10 ** digits).padStart(digits, '0');
}

// The step a code belongs to, or null. One step either side is accepted, for a phone clock a little
// off or a code typed just as it changed. Codes are compared in constant time.
function verify(secret, code, { now = Date.now(), window = 1 } = {}) {
    const c = String(code || '').replace(/\s/g, '');
    if (!/^\d{6}$/.test(c)) return null;
    const current = stepAt(now);
    for (let s = current - window; s <= current + window; s++) {
        const expected = Buffer.from(hotp(secret, s));
        if (crypto.timingSafeEqual(expected, Buffer.from(c))) return s;
    }
    return null;
}

// What the QR code holds; the authenticator app reads the account name, issuer and secret from it
function otpauthUrl(secret, { issuer = 'PHOENIX CODEX', account = 'admin' } = {}) {
    const label = encodeURIComponent(`${issuer}:${account}`);
    return `otpauth://totp/${label}?secret=${base32Encode(secret)}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=${DIGITS}&period=${STEP_SECONDS}`;
}

module.exports = { base32Encode, base32Decode, generateSecret, hotp, verify, stepAt, otpauthUrl, STEP_SECONDS };
