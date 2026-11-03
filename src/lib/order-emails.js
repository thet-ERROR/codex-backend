// The emails an order sends: to the customer (in the language they ordered in) when it is placed and
// when it is cancelled, and to the shop (ORDERS_NOTIFY_EMAIL) for a new order and for a cancellation
// by the customer. Sent in the background: a slow or failed email never holds up or fails the order.
const { ORDERS_NOTIFY_EMAIL, ORDERS_CONTACT_EMAIL } = require('../config');
const { PRIMARY_ORIGIN } = require('../security/cors');
const { sendMail, escHtml } = require('./email');

const font = 'font-family:Arial,Helvetica,sans-serif;';
const euros = (cents) => `${(Number(cents || 0) / 100).toLocaleString('el-GR', { minimumFractionDigits: 2, maximumFractionDigits: 2 })} €`;
const siteBase = () => PRIMARY_ORIGIN || 'https://codex-iota-nine.vercel.app';
// The customer's own order page (the storefront reads ?order= and ?t=)
const orderLink = (order, token) => `${siteBase()}/?order=${encodeURIComponent(order.number)}&t=${encodeURIComponent(token)}`;

const COPY = {
    el: {
        placedSubject: (n, demo) => `${demo ? '[DEMO] ' : ''}Η παραγγελία ${n} καταχωρήθηκε`,
        placedTitle: 'Η παραγγελία σου καταχωρήθηκε',
        demo: 'Δοκιμαστική παραγγελία: δεν γίνεται πραγματική αγορά, χρέωση ή αποστολή.',
        number: 'Αριθμός παραγγελίας',
        // Written out: toUpperCase() keeps the Greek accents, which capitals don't carry
        numberCaps: 'ΑΡΙΘΜΟΣ ΠΑΡΑΓΓΕΛΙΑΣ',
        total: 'Σύνολο',
        discount: 'Κουπόνι',
        next: 'Θα επικοινωνήσουμε μαζί σου για την πληρωμή και τα μεταφορικά. Μπορείς να απαντήσεις σε αυτό το email για οτιδήποτε.',
        view: 'ΔΕΣ ΤΗΝ ΠΑΡΑΓΓΕΛΙΑ',
        viewNote: 'Από τη σελίδα της παραγγελίας μπορείς και να την ακυρώσεις, όσο δεν έχει πακεταριστεί.',
        delivery: { courier: 'Courier', hand: 'Χέρι με χέρι', boxnow: 'BOX NOW' },
        extras: { hdd: '+ 1TB HDD', ssd: '+ 1TB SSD', proConfig: 'Pro Configuration', paint: 'Custom βαφή' },
        cancelSubject: (n) => `Η παραγγελία ${n} ακυρώθηκε`,
        cancelTitle: 'Η παραγγελία σου ακυρώθηκε',
        cancelText: 'Η παραγγελία ακυρώθηκε και δεν χρειάζεται να κάνεις τίποτα άλλο.',
        refund: 'Επειδή είχε πληρωθεί, θα επικοινωνήσουμε μαζί σου για την επιστροφή των χρημάτων.',
        sign: 'PHOENIX CODEX'
    },
    en: {
        placedSubject: (n, demo) => `${demo ? '[DEMO] ' : ''}Order ${n} placed`,
        placedTitle: 'Your order is placed',
        demo: 'Demo order: no real purchase, charge or shipment happens.',
        number: 'Order number',
        numberCaps: 'ORDER NUMBER',
        total: 'Total',
        discount: 'Coupon',
        next: 'We will be in touch about payment and shipping. You can reply to this email about anything.',
        view: 'VIEW YOUR ORDER',
        viewNote: 'From the order page you can also cancel it, until it is packed.',
        delivery: { courier: 'Courier', hand: 'In person', boxnow: 'BOX NOW' },
        extras: { hdd: '+ 1TB HDD', ssd: '+ 1TB SSD', proConfig: 'Pro Configuration', paint: 'Custom Paint' },
        cancelSubject: (n) => `Order ${n} cancelled`,
        cancelTitle: 'Your order is cancelled',
        cancelText: 'The order is cancelled and there is nothing else you need to do.',
        refund: 'As it had been paid, we will be in touch about the refund.',
        sign: 'PHOENIX CODEX'
    }
};
const copyFor = (order) => COPY[order.lang === 'en' ? 'en' : 'el'];

function extraLabel(e, c, lang) {
    if (e.key === 'storage') return c.extras[e.choice] || e.choice;
    if (e.key === 'paint') {
        const colour = lang === 'en' ? e.colorName : (e.colorNameEl || e.colorName);
        return colour ? `${c.extras.paint} — ${colour}` : c.extras.paint;
    }
    return c.extras[e.key] || e.key;
}

// The lines, total and delivery as text (for the plain part, and for the shop's notice)
function linesText(order, c) {
    const out = [];
    order.items.forEach((i, n) => {
        out.push(`${n + 1}. ${i.name} — ${euros(i.totalCents)}`);
        (i.extras || []).forEach(e => out.push(`   ${extraLabel(e, c, order.lang)} (+${euros(e.priceCents)})`));
    });
    if (order.discountCents) out.push(`${c.discount} ${order.coupon?.code || ''}: -${euros(order.discountCents)}`);
    out.push(`${c.total}: ${euros(order.totalCents)}`);
    return out.join('\n');
}

function linesHtml(order, c) {
    const row = (left, right, style = '') => `<tr><td style="${font}font-size:14px;color:#dddddd;padding:6px 0;${style}">${left}</td><td style="${font}font-size:14px;color:#ffffff;padding:6px 0;text-align:right;white-space:nowrap;${style}">${right}</td></tr>`;
    const items = order.items.map(i => row(
        `${escHtml(i.name)}${(i.extras || []).map(e => `<br><span style="color:#999999;font-size:12px;">${escHtml(extraLabel(e, c, order.lang))}</span>`).join('')}`,
        euros(i.totalCents)
    )).join('');
    const discount = order.discountCents ? row(`${c.discount} ${escHtml(order.coupon?.code || '')}`, `-${euros(order.discountCents)}`, 'color:#ffb800;') : '';
    return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0">${items}${discount}${row(`<b>${c.total}</b>`, `<b>${euros(order.totalCents)}</b>`, 'border-top:1px solid #262626;padding-top:10px;')}</table>`;
}

// The same dark card as the verification email
function shell(inner) {
    return `
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0a0a0a;padding:32px 16px;">
<tr><td align="center">
<table role="presentation" width="480" cellpadding="0" cellspacing="0" style="max-width:480px;background:#141414;border:1px solid #262626;border-radius:12px;">
<tr><td style="padding:32px 32px 8px 32px;text-align:center;">
<span style="${font}font-size:12px;letter-spacing:3px;color:#ccff00;font-weight:bold;">PHOENIX CODEX</span>
</td></tr>
${inner}
</table>
</td></tr>
</table>`.trim();
}
const demoBanner = (order, c) => order.demo
    ? `<tr><td style="padding:0 32px 16px 32px;"><div style="${font}font-size:13px;color:#ffd56b;background:#2a2108;border:1px solid #6b5410;border-radius:8px;padding:10px 12px;text-align:center;">${c.demo}</div></td></tr>`
    : '';

function placedEmail(order, token) {
    const c = copyFor(order);
    const link = orderLink(order, token);
    const delivery = c.delivery[order.delivery?.method] || '';
    const text = [
        c.placedTitle, order.demo ? c.demo : '', '',
        `${c.number}: ${order.number}`, '', linesText(order, c), '',
        delivery, '', c.next, '', `${c.view}: ${link}`, c.viewNote, '', `- ${c.sign}`
    ].filter((l, i, a) => l !== '' || a[i - 1] !== '').join('\n');
    const html = shell(`
${demoBanner(order, c)}
<tr><td style="padding:8px 32px 8px 32px;text-align:center;">
<div style="${font}font-size:20px;color:#ffffff;font-weight:bold;margin-bottom:6px;">${c.placedTitle}</div>
<div style="${font}font-size:12px;letter-spacing:2px;color:#999999;">${c.numberCaps}</div>
<div style="${font}font-size:28px;letter-spacing:3px;color:#ffffff;font-weight:bold;margin:4px 0 8px;">${escHtml(order.number)}</div>
</td></tr>
<tr><td style="padding:8px 32px 8px 32px;">${linesHtml(order, c)}</td></tr>
<tr><td style="padding:8px 32px 16px 32px;${font}font-size:13px;color:#999999;line-height:1.6;">${escHtml(delivery)}<br>${c.next}</td></tr>
<tr><td style="padding:8px 32px 8px 32px;text-align:center;">
<a href="${escHtml(link)}" style="display:inline-block;background:#ccff00;color:#0a0a0a;${font}font-size:14px;font-weight:bold;text-decoration:none;padding:14px 32px;border-radius:8px;">${c.view}</a>
</td></tr>
<tr><td style="padding:8px 32px 28px 32px;${font}font-size:12px;color:#666666;text-align:center;line-height:1.6;">${c.viewNote}</td></tr>`);
    return { subject: c.placedSubject(order.number, order.demo), text, html };
}

function cancelledEmail(order) {
    const c = copyFor(order);
    const text = [c.cancelTitle, '', `${c.number}: ${order.number}`, '', c.cancelText, order.refundDue ? c.refund : '', '', linesText(order, c), '', `- ${c.sign}`]
        .filter((l, i, a) => l !== '' || a[i - 1] !== '').join('\n');
    const html = shell(`
${demoBanner(order, c)}
<tr><td style="padding:8px 32px 8px 32px;text-align:center;">
<div style="${font}font-size:20px;color:#ffffff;font-weight:bold;margin-bottom:6px;">${c.cancelTitle}</div>
<div style="${font}font-size:22px;letter-spacing:3px;color:#ffffff;font-weight:bold;margin:4px 0 8px;">${escHtml(order.number)}</div>
<div style="${font}font-size:14px;color:#999999;line-height:1.6;">${c.cancelText}${order.refundDue ? `<br><span style="color:#ffd56b;">${c.refund}</span>` : ''}</div>
</td></tr>
<tr><td style="padding:16px 32px 28px 32px;">${linesHtml(order, c)}</td></tr>`);
    return { subject: c.cancelSubject(order.number), text, html };
}

// The shop's notice: everything needed to act on it, in Greek, plain text (it is read, not designed)
function shopNotice(order, { event, priorNoShows = 0 }) {
    const c = COPY.el;
    const d = order.delivery || {};
    const where = d.method === 'courier' ? `${d.address}, ${d.postcode} ${d.city}`
        : d.method === 'hand' ? `${d.area} — ${d.address}`
        : d.method === 'boxnow' ? `Locker: ${d.locker}` : '';
    const inv = order.invoice?.type === 'invoice'
        ? `Τιμολόγιο: ${order.invoice.companyName}, ΑΦΜ ${order.invoice.vatNumber}, ΔΟΥ ${order.invoice.taxOffice}` : 'Απόδειξη';
    const head = event === 'cancelled'
        ? `Ο πελάτης ακύρωσε την παραγγελία ${order.number}.${order.refundDue ? ' ΕΧΕΙ ΠΛΗΡΩΘΕΙ: χρειάζεται επιστροφή χρημάτων.' : ''}`
        : `Νέα παραγγελία ${order.number}.`;
    const text = [
        order.demo ? '[DEMO — δοκιμαστική, όχι πραγματική]' : '',
        head,
        priorNoShows ? `⚠ ΠΡΟΣΟΧΗ: ${priorNoShows} προηγούμενη/ες μη εμφάνιση/εις από αυτό το τηλέφωνο ή email.` : '',
        '',
        `Πελάτης: ${order.customer?.firstName} ${order.customer?.lastName}`,
        `Τηλέφωνο: ${order.customer?.phone}`,
        `Email: ${order.customer?.email}`,
        `Λογαριασμός: ${order.userId ? 'μέλος' : 'επισκέπτης'}`,
        `Παράδοση: ${c.delivery[d.method] || d.method} — ${where}`,
        inv,
        order.notes ? `Σημειώσεις: ${order.notes}` : '',
        '',
        linesText(order, c)
    ].filter((l, i, a) => l !== '' || a[i - 1] !== '').join('\n').trim();
    const subject = `${order.demo ? '[DEMO] ' : ''}${event === 'cancelled' ? 'Ακύρωση' : 'Νέα παραγγελία'} ${order.number} — ${euros(order.totalCents)}${priorNoShows ? ' ⚠' : ''}`;
    // Text in a <pre>-like block so the shop's mail app shows it as it is, every value escaped
    const html = `<div style="${font}font-size:14px;line-height:1.6;white-space:pre-wrap;color:#111111;">${escHtml(text)}</div>`;
    return { subject, text, html };
}

// --- sending (never awaited by the routes) ---
const quietly = (label, p) => p.catch(e => console.error(`${label} email failed:`, e.message || e));

function sendOrderPlaced(order, accessToken, { priorNoShows = 0 } = {}) {
    const mail = placedEmail(order, accessToken);
    quietly(`Order ${order.number} confirmation`, sendMail({ to: order.customer.email, replyTo: ORDERS_CONTACT_EMAIL || undefined, ...mail }));
    if (ORDERS_NOTIFY_EMAIL) {
        quietly(`Order ${order.number} shop notice`, sendMail({ to: ORDERS_NOTIFY_EMAIL, replyTo: order.customer.email, ...shopNotice(order, { event: 'placed', priorNoShows }) }));
    }
}

function sendOrderCancelled(order, { byCustomer }) {
    quietly(`Order ${order.number} cancellation`, sendMail({ to: order.customer.email, replyTo: ORDERS_CONTACT_EMAIL || undefined, ...cancelledEmail(order) }));
    // The shop cancelled it itself, so it only needs telling when the customer did
    if (byCustomer && ORDERS_NOTIFY_EMAIL) {
        quietly(`Order ${order.number} cancel notice`, sendMail({ to: ORDERS_NOTIFY_EMAIL, replyTo: order.customer.email, ...shopNotice(order, { event: 'cancelled' }) }));
    }
}

module.exports = { sendOrderPlaced, sendOrderCancelled, orderLink };
