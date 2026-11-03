const mongoose = require('mongoose');
const { CACHE_TTL_MS, WRITE_HOOKS } = require('./cache');

// The admin's two-factor sign-in. One document (_id 'admin') — there is one admin account.
//   totpSecret / totpPending: the authenticator secret, sealed with ADMIN_2FA_KEY (lib/secret-box.js).
//     A new secret waits in totpPending until a code from the app proves it was scanned.
//   recoveryHashes: sha256 of the one-time recovery codes, for a lost phone; each works once.
//   lastStep: the 30-second step of the last code accepted — the same code can't be used twice.
//   securityVersion: in every admin token; bumped when 2FA is turned on or off, which ends every
//     session signed in before.
const adminSecuritySchema = new mongoose.Schema({
    _id: { type: String, default: 'admin' },
    totpEnabled: { type: Boolean, default: false },
    totpSecret: String,
    totpPending: String,
    recoveryHashes: { type: [String], default: [] },
    lastStep: { type: Number, default: 0 },
    securityVersion: { type: Number, default: 0 },
    enabledAt: Date
});

// Every admin request reads this (the session check), so it comes from memory, cleared by the
// model's own writes like the other read caches
let cached = null; // { doc, at }
adminSecuritySchema.post(WRITE_HOOKS, () => { cached = null; });
const AdminSecurity = mongoose.model('AdminSecurity', adminSecuritySchema);

async function getAdminSecurity() {
    if (cached && Date.now() - cached.at < CACHE_TTL_MS) return cached.doc;
    const doc = (await AdminSecurity.findById('admin').lean()) || { _id: 'admin', totpEnabled: false, recoveryHashes: [], lastStep: 0, securityVersion: 0 };
    cached = { doc, at: Date.now() };
    return doc;
}

module.exports = { AdminSecurity, getAdminSecurity };
