const crypto = require('crypto');
const { ALLOWED_ORIGINS } = require('../security/cors');

// --- 📧 EMAIL DELIVERY (Mailjet Send API v3.1) ---
// Render's free tier blocks outbound SMTP (ports 25/465/587) since Sept 2025, so nodemailer over
// Gmail could never connect from here — every send died with ETIMEDOUT. This goes out over plain
// HTTPS instead, which is never blocked. It's also the right tool regardless: Gmail caps at
// ~500/day, has poor deliverability to strangers, and eventually flags automated sending.
const MAILJET_API_KEY = process.env.MAILJET_API_KEY;        // "API Key" (public) in Mailjet
const MAILJET_SECRET_KEY = process.env.MAILJET_SECRET_KEY;  // "Secret Key" (private) in Mailjet
const EMAIL_FROM = process.env.EMAIL_FROM || process.env.EMAIL_USER;
const EMAIL_FROM_NAME = process.env.EMAIL_FROM_NAME || 'CODEX SYSTEMS';

if (!MAILJET_API_KEY || !MAILJET_SECRET_KEY) {
    console.error("🚨 MAILJET_API_KEY / MAILJET_SECRET_KEY not set — no verification or password-reset email can be sent.");
}
if (!EMAIL_FROM) {
    console.error("🚨 EMAIL_FROM is not set — set it to the sender address you validated in Mailjet.");
}

// `html` is optional — every existing call site (forgot-password, reset-password) keeps sending
// text-only exactly as before. TextPart is still sent alongside HTMLPart even when html is given:
// Mailjet's spam scoring and any client that can't render HTML both fall back to it.
// Throws on failure; callers already log and carry on without failing the request.
async function sendMail({ to, subject, text, html }) {
    if (!MAILJET_API_KEY || !MAILJET_SECRET_KEY || !EMAIL_FROM) {
        throw new Error('Email is not configured (MAILJET_API_KEY / MAILJET_SECRET_KEY / EMAIL_FROM missing)');
    }

    // Mailjet authenticates with HTTP Basic: "apiKey:secretKey" base64-encoded
    const credentials = Buffer.from(`${MAILJET_API_KEY}:${MAILJET_SECRET_KEY}`).toString('base64');

    const res = await fetch('https://api.mailjet.com/v3.1/send', {
        method: 'POST',
        headers: {
            'Authorization': `Basic ${credentials}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            Messages: [{
                From: { Email: EMAIL_FROM, Name: EMAIL_FROM_NAME },
                To: [{ Email: to }],
                Subject: subject,
                TextPart: text,
                ...(html ? { HTMLPart: html } : {})
            }]
        })
    });

    if (!res.ok) {
        // Mailjet returns a JSON body explaining the rejection (unvalidated sender, bad key, quota)
        const detail = await res.text().catch(() => '');
        throw new Error(`Mailjet API ${res.status}: ${detail}`);
    }
    return res.json().catch(() => ({}));
}

// Shared by /api/register and /api/resend-verification. Stores only the hash (same reasoning as
// the password-reset token) and returns the raw value, which is what actually goes in the email.
function issueEmailVerification(user) {
    const rawToken = crypto.randomBytes(32).toString('hex');
    user.emailVerifyTokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    user.emailVerifyExpiry = Date.now() + 24 * 60 * 60 * 1000; // 24h
    return rawToken;
}

// The "wasn't you?" token. Re-issued (rotated) alongside the verify token on every send, same as
// issueEmailVerification — but on its own 7-day clock rather than 24h. See the schema comment on
// securityReportTokenHash for why the two can't share a lifetime.
function issueSecurityReportToken(user) {
    const rawToken = crypto.randomBytes(32).toString('hex');
    user.securityReportTokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    user.securityReportTokenExpiry = Date.now() + 7 * 24 * 60 * 60 * 1000; // 7 days
    return rawToken;
}

// Minimal HTML-escaping for the one piece of user data that reaches the email template. The
// username is already restricted to [a-zA-Z0-9_.-] at registration so this can never actually
// fire — kept anyway because "the input is validated elsewhere" is exactly the assumption that
// broke on the admin panel (see the newsletter-email XSS fix), and an email template is not a
// context worth trusting twice.
const escHtml = (v) => String(v ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));

// Table-based layout with every style inline: Outlook's rendering engine is Word, not a browser,
// and most clients strip <style> blocks outright, so anything depending on external CSS or flex/
// grid silently collapses. This is the plainest layout that still looks like a real product email
// rather than the raw-URL plaintext it replaces.
function buildVerificationEmailHtml({ username, confirmLink, reportLink }) {
    const font = "font-family:Arial,Helvetica,sans-serif;";
    return `
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0a0a0a;padding:32px 16px;">
<tr><td align="center">
<table role="presentation" width="480" cellpadding="0" cellspacing="0" style="max-width:480px;background:#141414;border:1px solid #262626;border-radius:12px;">
<tr><td style="padding:32px 32px 8px 32px;text-align:center;">
<span style="${font}font-size:12px;letter-spacing:3px;color:#ccff00;font-weight:bold;">PHOENIX CODEX</span>
</td></tr>
<tr><td style="padding:8px 32px 24px 32px;text-align:center;">
<div style="${font}font-size:20px;color:#ffffff;font-weight:bold;margin-bottom:12px;">Confirm your identity, Agent ${escHtml(username)}</div>
<div style="${font}font-size:14px;color:#999999;line-height:1.6;">One more step unlocks your dossier, wishlist and voting rights. This link is valid for 24 hours.</div>
</td></tr>
<tr><td style="padding:8px 32px 32px 32px;text-align:center;">
<a href="${confirmLink}" style="display:inline-block;background:#ccff00;color:#0a0a0a;${font}font-size:14px;font-weight:bold;text-decoration:none;padding:14px 32px;border-radius:8px;">CONFIRM MY EMAIL</a>
</td></tr>
<tr><td style="padding:20px 32px 32px 32px;border-top:1px solid #262626;">
<div style="${font}font-size:12px;color:#666666;line-height:1.6;text-align:center;">Didn't create this account? <a href="${reportLink}" style="color:#ff6666;">Secure it now</a> — this locks it for 5 days.</div>
</td></tr>
</table>
<div style="${font}font-size:11px;color:#444444;margin-top:16px;">CODEX HQ</div>
</td></tr>
</table>`.trim();
}

async function sendVerificationEmail(user, rawVerifyToken, rawReportToken) {
    // Points at the frontend, not the API — verification is done by that page's own POST call
    // once it loads (js/main.js), never by whatever GETs the link itself (a mail client's link
    // scanner never runs the page's JavaScript). Falls back to the API URL only if no frontend
    // origin is configured, so verification is never completely undeliverable. The report link
    // uses the identical reasoning and the identical protection.
    const base = ALLOWED_ORIGINS[0] || `https://codex-backend-9kij.onrender.com`;
    const confirmLink = `${base}/?verify=${rawVerifyToken}`;
    const reportLink = `${base}/?report=${rawReportToken}`;
    await sendMail({
        to: user.email,
        subject: '✅ CONFIRM YOUR AGENT IDENTITY',
        text: `AGENT ${user.username},\n\nConfirm your email to unlock your dossier, wishlist and voting rights:\n${confirmLink}\n\nThis link is valid for 24 hours.\n\nDidn't create this account? Secure it now (locks it for 5 days):\n${reportLink}\n\n- CODEX HQ`,
        html: buildVerificationEmailHtml({ username: user.username, confirmLink, reportLink })
    });
}

module.exports = { MAILJET_API_KEY, MAILJET_SECRET_KEY, EMAIL_FROM, sendMail, issueEmailVerification, issueSecurityReportToken, sendVerificationEmail };
