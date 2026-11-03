const mongoose = require('mongoose');

const reviewTicketSchema = new mongoose.Schema({
    code: { type: String, index: true }, pcId: String, pcName: String,
    status: { type: String, default: 'pending' }, 
    generatedAt: { type: Date, default: Date.now }, 
    firstScan: { type: Date, default: null } 
});
const ReviewTicket = mongoose.model('ReviewTicket', reviewTicketSchema);

module.exports = ReviewTicket;
