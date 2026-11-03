const mongoose = require('mongoose');

// Indexed: the signup route looks up by email to avoid duplicates, and the achievement sync
// checks it once per unearned "signal_intercepted" — both are exact-match reads on every call.
const newsletterSchema = new mongoose.Schema({ email: { type: String, index: true }, date: { type: Date, default: Date.now } });
const Newsletter = mongoose.model('Newsletter', newsletterSchema);

module.exports = Newsletter;
