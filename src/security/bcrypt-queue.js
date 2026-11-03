// Password hashing brake. A bcrypt round at cost 12 is deliberately slow — on this dyno's small
// CPU share likely around a second. A burst of logins/sign-ups (or someone scripting them from many
// IPs, which the per-IP limiters above can't see) would run several at once and starve every other
// request of CPU, so the whole site would crawl. At most BCRYPT_MAX_CONCURRENT run together, the
// rest wait their turn; with too many already waiting the request is turned away at once with a
// "busy" answer instead of joining a queue it would time out in.
const BCRYPT_MAX_CONCURRENT = 2;
const BCRYPT_MAX_WAITING = 20;
let bcryptRunning = 0;
const bcryptWaiting = [];
class BcryptBusyError extends Error {}
async function withBcrypt(fn) {
    if (bcryptRunning >= BCRYPT_MAX_CONCURRENT) {
        if (bcryptWaiting.length >= BCRYPT_MAX_WAITING) throw new BcryptBusyError();
        await new Promise(resolve => bcryptWaiting.push(resolve));
    } else {
        bcryptRunning++;
    }
    try { return await fn(); }
    finally {
        // Hand the slot straight to the next in line (the count stays), or free it
        const next = bcryptWaiting.shift();
        if (next) next(); else bcryptRunning--;
    }
}
const BUSY_ERROR = { error: "⚠️ SYSTEM BUSY: Too many sign-ins right now. Try again in a few seconds." };

module.exports = { BcryptBusyError, withBcrypt, BUSY_ERROR };
