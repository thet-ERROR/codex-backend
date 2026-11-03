// Input checks shared by the routes.

// Rejects strings that aren't strings — a JSON body can smuggle {"$ne": null} into a query and
// turn findOne() into "match any user". Everything that reaches a query goes through here.
const asString = v => (typeof v === 'string' ? v : '');

// --- EMAIL ADDRESS SANITY CHECKS ---
// The previous pattern was /^[^\s@]+@[^\s@]+\.[^\s@]+$/ — "anything without spaces, with an @".
// That accepts "<svg/onload=fetch(...)>@gmail.com": it has no space, exactly one @, and the domain
// half is a real domain, so it also passed the MX check below. The address was then stored and
// rendered by the admin panel, which is how a public, unauthenticated signup form became a way to
// run script in an authenticated admin's browser.
//
// This pattern allows only characters that appear in addresses people actually use, which happens
// to exclude every HTML metacharacter (< > " ' / & =). RFC 5321 technically permits more in the
// local part, but no mainstream provider issues such addresses, and letting them through here is
// how the injection above became possible in the first place.
const EMAIL_PATTERN = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$/;
const isValidEmail = (email) => email.length <= 254 && EMAIL_PATTERN.test(email);

// A format regex alone accepts anything shaped like an address, so "asdf@asdf.com" sails through.
// These two checks raise the bar cheaply; the verification link remains the real proof of
// ownership, since only a mailbox that actually receives it can complete signup.
const DISPOSABLE_EMAIL_DOMAINS = new Set([
    'mailinator.com', '10minutemail.com', 'guerrillamail.com', 'guerrillamail.net',
    'tempmail.com', 'temp-mail.org', 'throwawaymail.com', 'yopmail.com', 'trashmail.com',
    'sharklasers.com', 'getnada.com', 'maildrop.cc', 'fakeinbox.com', 'dispostable.com',
    'mailnesia.com', 'mintemail.com', 'spamgourmet.com', 'mytemp.email', 'moakt.com',
    'emailondeck.com', 'burnermail.io', 'tempr.email', 'discard.email', 'mailcatch.com'
]);

const isDisposableEmail = (email) => DISPOSABLE_EMAIL_DOMAINS.has(email.split('@')[1] || '');

// Confirms the domain actually publishes mail servers — catches invented domains and typos like
// "gmial.com". Deliberately fails OPEN: a DNS hiccup must never block a legitimate signup.
async function domainAcceptsMail(email) {
    const domain = email.split('@')[1];
    if (!domain) return false;
    try {
        const records = await require('dns').promises.resolveMx(domain);
        return Array.isArray(records) && records.length > 0;
    } catch (e) {
        if (e.code === 'ENOTFOUND' || e.code === 'NODATA') return false; // domain has no mail
        console.error(`MX lookup failed for "${domain}", allowing through:`, e.code);
        return true;
    }
}

module.exports = { asString, isValidEmail, isDisposableEmail, domainAcceptsMail };
