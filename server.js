require('dotenv').config(); // ΝΕΟ: Φορτώνει τα μυστικά από το .env
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt'); // ΝΕΟ: Για κρυπτογράφηση κωδικών

const app = express();
const PORT = 5000;

// Τραβάμε τους κωδικούς από το .env
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD; 
const dbURI = process.env.DB_URI;

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

console.log("⏳ Connecting to MongoDB...");
mongoose.connect(dbURI, { serverSelectionTimeoutMS: 30000, socketTimeoutMS: 45000 })
.then(() => console.log("✅ SERVER ONLINE: DATABASE CONNECTED (SECURE MODE)"))
.catch((err) => console.error("❌ DB CONNECTION ERROR:", err.message));

// --- SCHEMAS ---
const pcSchema = new mongoose.Schema({
    name: String, price: String, description: String, stock: { type: Number, default: 1 }, 
    images: [String], status: { type: String, default: 'available' }, category: { type: String, default: 'drop' },    
    multitasking: { type: Number, default: 0 },
    specs: { cpu: String, gpu: String, ram: String, ssd: String, mobo: String, psu: String, case: String },
    fps: [{ game: String, score: Number }],
    reviews: [{ user: String, text: String, rating: Number, date: { type: Date, default: Date.now } }],
    votes: { type: Number, default: 0 }
});
const PC = mongoose.model('PC', pcSchema);

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }, // Θα αποθηκεύεται κρυπτογραφημένο
    joined: { type: Date, default: Date.now },
    resetToken: String,
    resetTokenExpiry: Date
});
const User = mongoose.model('User', userSchema);

const voteEventSchema = new mongoose.Schema({ title: String, image: String, targetVotes: Number, currentVotes: { type: Number, default: 0 }, startDate: Date, durationDays: Number });
const VoteEvent = mongoose.model('VoteEvent', voteEventSchema);

const reviewTicketSchema = new mongoose.Schema({ 
    code: String, pcId: String, pcName: String, 
    status: { type: String, default: 'pending' }, 
    generatedAt: { type: Date, default: Date.now }, 
    firstScan: { type: Date, default: null } 
});
const ReviewTicket = mongoose.model('ReviewTicket', reviewTicketSchema);

const newsletterSchema = new mongoose.Schema({ email: String, date: { type: Date, default: Date.now } });
const Newsletter = mongoose.model('Newsletter', newsletterSchema);

// --- EMAIL CONFIG ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER, // Από το .env
        pass: process.env.EMAIL_PASS  // Από το .env
    }
});

// --- CONFIG ---
const storage = multer.diskStorage({ destination: (req, file, cb) => cb(null, 'uploads/'), filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname)) });
const upload = multer({ storage: storage });
const auth = (req, res, next) => { if (req.headers['x-admin-auth'] === ADMIN_PASSWORD) next(); else res.status(403).json({ error: "⛔ WRONG PASSWORD" }); };

// --- ROUTES ---

// 1. REGISTER (ΜΕ BCRYPT)
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (await User.findOne({ email })) return res.status(400).json({ error: "Email exists" });
        
        // Κρυπτογράφηση κωδικού
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({ username, email, password: hashedPassword }); 
        await newUser.save();
        res.json({ success: true, username: newUser.username });
    } catch (e) { res.status(500).json({ error: "Error" }); }
});

// 2. LOGIN (ΜΕ BCRYPT)
app.post('/api/user-login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ error: "Invalid Credentials" });

        // Σύγκριση κωδικών
        const isMatch = await bcrypt.compare(password, user.password);
        if (isMatch) res.json({ success: true, username: user.username }); 
        else res.status(400).json({ error: "Invalid Credentials" });
    } catch (e) {
        res.status(500).json({ error: "Server Error" });
    }
});

app.post('/api/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: "Email not found" });
        const token = crypto.randomBytes(20).toString('hex');
        user.resetToken = token;
        user.resetTokenExpiry = Date.now() + 3600000;
        await user.save();
        const mailOptions = {
            from: 'CODEX SYSTEMS',
            to: user.email,
            subject: '🔐 PASSWORD RECOVERY',
            text: `AGENT ${user.username},\n\nYOUR RESET TOKEN:\n${token}\n\nValid for 60 minutes.\n- CODEX HQ`
        };
        await transporter.sendMail(mailOptions);
        res.json({ success: true });
    } catch (e) { console.error(e); res.status(500).json({ error: "Email Failed" }); }
});

// 3. RESET PASSWORD (ΜΕ BCRYPT)
app.post('/api/reset-password', async (req, res) => {
    const { token, newPass } = req.body;
    try {
        const user = await User.findOne({ resetToken: token, resetTokenExpiry: { $gt: Date.now() } });
        if (!user) return res.status(400).json({ error: "Invalid Token" });
        
        // Κρυπτογράφηση του ΝΕΟΥ κωδικού
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPass, salt);
        
        user.resetToken = undefined;
        user.resetTokenExpiry = undefined;
        await user.save();
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: "Error" }); }
});

app.get('/api/users/count', auth, async (req, res) => { const count = await User.countDocuments(); res.json({ count }); });
app.post('/api/login', (req, res) => { if (req.body.password === ADMIN_PASSWORD) res.json({ success: true }); else res.status(403).json({ success: false }); });

// DROPS
app.get('/api/drops', async (req, res) => { const all = await PC.find(); res.json(all); });
app.post('/api/drops', auth, async (req, res) => { const n = new PC(req.body); await n.save(); res.json(n); });
app.put('/api/drops/:id', auth, async (req, res) => { const u = await PC.findByIdAndUpdate(req.params.id, req.body, {new:true}); res.json(u); });
app.delete('/api/drops/:id', auth, async (req, res) => { await PC.findByIdAndDelete(req.params.id); res.json({msg:"Deleted"}); });
app.post('/api/upload', auth, upload.array('photos', 5), (req, res) => { const u = req.files.map(f => `http://localhost:${PORT}/uploads/${f.filename}`); res.json({imageUrls: u}); });

// VOTE
app.get('/api/vote-event', async (req, res) => { const event = await VoteEvent.findOne(); res.json(event || {}); });
app.post('/api/vote-event', auth, async (req, res) => { await VoteEvent.deleteMany({}); const n = new VoteEvent(req.body); await n.save(); res.json(n); });
app.post('/api/cast-vote', async (req, res) => { const event = await VoteEvent.findOne(); if(event) { event.currentVotes += 1; await event.save(); res.json({ votes: event.currentVotes }); } else { res.status(404).json({ error: "No active vote" }); } });

// MISSION / VALIDATION
app.post('/api/generate-code', auth, async (req, res) => { const { pcId, pcName } = req.body; const code = 'CDX-' + crypto.randomBytes(3).toString('hex').toUpperCase(); const ticket = new ReviewTicket({ code, pcId, pcName }); await ticket.save(); res.json(ticket); });
app.get('/api/tickets', auth, async (req, res) => { const tickets = await ReviewTicket.find().sort({ generatedAt: -1 }); res.json(tickets); });

app.post('/api/activate-ticket/:id', auth, async (req, res) => {
    try {
        const ticket = await ReviewTicket.findById(req.params.id);
        if(ticket) {
            ticket.status = 'active';
            await ticket.save();
            res.json({ success: true });
        } else { res.status(404).json({ error: "Ticket not found" }); }
    } catch(e) { res.status(500).json({ error: "Server error" }); }
});

app.get('/api/check-code/:code', async (req, res) => {
    try {
        const ticket = await ReviewTicket.findOne({ code: req.params.code });
        if (!ticket) return res.json({ valid: false, msg: "❌ INVALID CODE" });
        if (ticket.status === 'used') return res.json({ valid: false, msg: "⚠️ ALREADY REDEEMED" });
        if (!ticket.firstScan) { ticket.firstScan = new Date(); ticket.status = 'active'; await ticket.save(); }
        const now = new Date(); const expiry = new Date(ticket.firstScan); expiry.setHours(expiry.getHours() + 48);
        if (now > expiry) { return res.json({ valid: true, expired: true, pcName: ticket.pcName }); }
        res.json({ valid: true, expired: false, pcName: ticket.pcName, timeLeft: expiry - now });
    } catch(e) { console.error(e); res.status(500).json({ valid: false, msg: "SERVER ERROR" }); }
});

app.post('/api/submit-review', async (req, res) => {
    const { code, user, rating, text } = req.body;
    const ticket = await ReviewTicket.findOne({ code });
    if (!ticket) return res.status(400).json({ error: "Invalid Ticket" });
    const pc = await PC.findById(ticket.pcId);
    if (pc) {
        pc.reviews.push({ user, rating, text, date: new Date() }); await pc.save();
        ticket.status = 'used'; await ticket.save();
        res.json({ success: true });
    } else { res.status(404).json({ error: "PC not found" }); }
});

app.post('/api/newsletter', async (req, res) => { const { email } = req.body; if(!email) return res.status(400).json({error:"Email required"}); const sub = new Newsletter({ email }); await sub.save(); res.json({ success: true }); });
app.get('/api/newsletter', auth, async (req, res) => { const subs = await Newsletter.find().sort({ date: -1 }); res.json(subs); });

app.listen(PORT, '0.0.0.0', () => { console.log(`🚀 Server running on port ${PORT}`); });