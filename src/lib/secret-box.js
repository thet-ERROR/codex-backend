// Encrypts the admin's authenticator secret before it is stored, so a copy of the database alone is
// not enough to generate the admin's codes. AES-256-GCM (authenticated: a tampered value fails to
// decrypt instead of decrypting to garbage) with the key from ADMIN_2FA_KEY — a Render setting, never
// in the database or the code. Generate one with:
//   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
const crypto = require('crypto');

const KEY_HEX = (process.env.ADMIN_2FA_KEY || '').trim();
const KEY = /^[0-9a-f]{64}$/i.test(KEY_HEX) ? Buffer.from(KEY_HEX, 'hex') : null;
if (KEY_HEX && !KEY) console.error('🚨 ADMIN_2FA_KEY must be 64 hex characters (32 bytes). Two-factor sign-in cannot be set up until it is.');

const keyConfigured = () => !!KEY;

// "iv.tag.ciphertext", each base64
function seal(plain) {
    if (!KEY) throw new Error('ADMIN_2FA_KEY not configured');
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
    const data = Buffer.concat([c.update(plain), c.final()]);
    return [iv, c.getAuthTag(), data].map(b => b.toString('base64')).join('.');
}

function open(sealed) {
    if (!KEY) throw new Error('ADMIN_2FA_KEY not configured');
    const [iv, tag, data] = String(sealed).split('.').map(s => Buffer.from(s, 'base64'));
    const d = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(data), d.final()]);
}

module.exports = { keyConfigured, seal, open };
