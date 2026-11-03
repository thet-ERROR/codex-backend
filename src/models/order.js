const mongoose = require('mongoose');

// Everything about an order is copied into it at the moment it is placed — names, prices, extras,
// the coupon — so later edits to a PC or a price never change what a customer agreed to pay.
const orderItemSchema = new mongoose.Schema({
    pcId: { type: mongoose.Schema.Types.ObjectId, ref: 'PC' },
    name: String,
    basePriceCents: Number,
    // key: 'storage' (choice 'hdd' | 'ssd'), 'proConfig', or 'paint' (with the colour's names). The
    // storefront turns the key into a label in the visitor's language.
    extras: [{ _id: false, key: String, choice: String, colorName: String, colorNameEl: String, priceCents: Number }],
    totalCents: Number,
    // A painted build is made to order: once building starts it can no longer be cancelled
    paint: { type: Boolean, default: false }
}, { _id: false });

const orderSchema = new mongoose.Schema({
    // DEMO-0001 while orders are a demo, PX-0001 once ORDERS_LIVE is on (two separate sequences)
    number: { type: String, required: true, unique: true },
    demo: { type: Boolean, default: true },
    status: { type: String, enum: ['new', 'paid', 'building', 'packed', 'shipped', 'delivered', 'completed', 'cancelled'], default: 'new', index: true },
    history: [{ _id: false, status: String, at: { type: Date, default: Date.now }, by: String, note: String }],

    // The account it was placed from, if any — guests can order too
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
    customer: {
        firstName: String, lastName: String,
        phone: { type: String, index: true },
        email: { type: String, index: true }
    },
    delivery: {
        method: { type: String, enum: ['courier', 'hand', 'boxnow'] },
        address: String, postcode: String, city: String,
        area: String,       // hand delivery: one of the admin's areas
        locker: String,     // BOX NOW: the locker the customer picked
        trackingNumber: String
    },
    invoice: {
        type: { type: String, enum: ['receipt', 'invoice'], default: 'receipt' },
        vatNumber: String, taxOffice: String, companyName: String
    },
    items: [orderItemSchema],
    subtotalCents: Number,
    discountCents: { type: Number, default: 0 },
    coupon: { code: String, percent: Number },
    totalCents: Number,
    notes: String,

    // What the customer agreed to, and when. termsVersion says which wording, if the terms change later.
    consent: { termsVersion: String, acceptedAt: Date, adultOrGuardian: Boolean },
    // Until the payment methods are decided this is 'agreed' — settled over WhatsApp
    payment: { method: { type: String, default: 'agreed' }, paidAt: Date, depositCents: Number },

    // The private link sent to the customer (the order page) carries a token; only its hash is kept
    accessTokenHash: String,

    deliveredAt: Date,
    returnDeadline: Date,
    cancelledAt: Date,
    cancelReason: { type: String, enum: ['customer', 'admin', 'no_show'] },
    // Cancelled after it was paid: the money has to go back
    refundDue: { type: Boolean, default: false },
    // The customer never turned up or refused it. Later orders from the same phone or email say so.
    noShow: { type: Boolean, default: false }
}, { timestamps: true });

const Order = mongoose.model('Order', orderSchema);

// One counter per sequence ('order' / 'demo-order'), bumped atomically — two orders placed at the same
// instant can never get the same number
const counterSchema = new mongoose.Schema({ _id: String, seq: { type: Number, default: 0 } });
const Counter = mongoose.model('Counter', counterSchema);

async function nextOrderNumber(demo) {
    const c = await Counter.findOneAndUpdate(
        { _id: demo ? 'demo-order' : 'order' },
        { $inc: { seq: 1 } },
        { new: true, upsert: true }
    );
    return `${demo ? 'DEMO' : 'PX'}-${String(c.seq).padStart(4, '0')}`;
}

module.exports = { Order, nextOrderNumber };
