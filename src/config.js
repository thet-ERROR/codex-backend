// Settings read from the environment (Render's Environment tab, or .env locally).
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const JWT_SECRET = process.env.JWT_SECRET;
const dbURI = process.env.DB_URI;

if (!JWT_SECRET) {
    console.error("🚨 JWT_SECRET is not set. Every authenticated route (login, register, admin, vote) will refuse to work until it is. Generate one with: node -e \"console.log(require('crypto').randomBytes(48).toString('hex'))\"");
}
if (!ADMIN_PASSWORD) {
    console.error("🚨 ADMIN_PASSWORD is not set. The admin panel cannot be used until it is.");
}

// Orders are a DEMO until the business is registered: they are saved and work end to end, but are
// marked demo, numbered DEMO-0001…, and the site says no real order is placed. Set ORDERS_LIVE=true
// on Render the day real orders start — nothing else changes.
const ORDERS_LIVE = process.env.ORDERS_LIVE === 'true';

// Where the shop is told about new and cancelled orders, and the address customers' replies go to
// (defaults to the same one). Set on Render, never in the code: the repository is public.
const ORDERS_NOTIFY_EMAIL = (process.env.ORDERS_NOTIFY_EMAIL || '').trim();
const ORDERS_CONTACT_EMAIL = (process.env.ORDERS_CONTACT_EMAIL || ORDERS_NOTIFY_EMAIL).trim();
if (!ORDERS_NOTIFY_EMAIL) {
    console.error("⚠️ ORDERS_NOTIFY_EMAIL is not set — orders still work, but nobody is emailed about a new one.");
}

module.exports = { ADMIN_PASSWORD, JWT_SECRET, dbURI, ORDERS_LIVE, ORDERS_NOTIFY_EMAIL, ORDERS_CONTACT_EMAIL };
