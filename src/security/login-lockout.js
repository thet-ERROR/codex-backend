// Per-ACCOUNT lockout, independent of the IP-based limiters above. Those stop one IP from
// hammering the API; this stops credential stuffing against one specific account from many
// rotating IPs, which the IP limiter alone can't see. In-memory, so it resets on a redeploy or
// when the free-tier dyno sleeps — an acceptable trade for this site's scale. A periodic sweep
// keeps the map from growing unbounded if someone tries thousands of fake usernames.
const failedLogins = new Map(); // key (e.g. "user:bob" or "admin") -> { count, windowStart, lockedUntil }
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_LOCKOUT_MS = 15 * 60 * 1000;

function accountLockMinutesLeft(key) {
    const entry = failedLogins.get(key);
    if (!entry || !entry.lockedUntil || Date.now() >= entry.lockedUntil) return 0;
    return Math.ceil((entry.lockedUntil - Date.now()) / 60000);
}
function recordFailedLogin(key) {
    const now = Date.now();
    const entry = failedLogins.get(key);
    const fresh = !entry || (now - entry.windowStart) > LOGIN_LOCKOUT_MS;
    const next = fresh ? { count: 1, windowStart: now, lockedUntil: 0 } : { ...entry, count: entry.count + 1 };
    if (next.count >= LOGIN_MAX_ATTEMPTS) next.lockedUntil = now + LOGIN_LOCKOUT_MS;
    failedLogins.set(key, next);
}
function clearFailedLogins(key) { failedLogins.delete(key); }

setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of failedLogins) {
        if (now >= entry.lockedUntil && (now - entry.windowStart) > LOGIN_LOCKOUT_MS) failedLogins.delete(key);
    }
}, 10 * 60 * 1000).unref();

module.exports = { accountLockMinutesLeft, recordFailedLogin, clearFailedLogins };
