const mongoose = require('mongoose');

// A review code. Either made by hand in the admin panel for a PC (48 hours from the first time it is
// entered), or made for an order when it is packed — one per PC in the box, open for reviews from
// delivery (lib/order-lifecycle.js). status: pending → active (entered) → used (review written);
// 'void' when its order was cancelled.
const reviewTicketSchema = new mongoose.Schema({
    code: { type: String, index: true }, pcId: String, pcName: String,
    status: { type: String, default: 'pending' },
    generatedAt: { type: Date, default: Date.now },
    firstScan: { type: Date, default: null },
    orderId: { type: mongoose.Schema.Types.ObjectId, ref: 'Order' },
    orderNumber: String,
    itemIndex: Number
});
// One code per PC line of an order, however many times the order passes "packed"
reviewTicketSchema.index({ orderId: 1, itemIndex: 1 }, { unique: true, partialFilterExpression: { orderId: { $exists: true } } });
const ReviewTicket = mongoose.model('ReviewTicket', reviewTicketSchema);

module.exports = ReviewTicket;
