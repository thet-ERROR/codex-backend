require('dotenv').config(); 
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit'); 

const app = express();
const PORT = process.env.PORT || 5000;

// --- 🛡️ SECURITY LAYER 1: HTTP HEADERS ---
app.use(helmet());
app.use(helmet.crossOriginResourcePolicy({ policy: "cross-origin" })); 

// --- 🛡️ SECURITY LAYER 2: CORS ---
const corsOptions = {
    origin: process.env.FRONTEND_URL || '*', 
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'x-admin-auth']
};
app.use(cors(corsOptions));
app.use(express.json());

// --- 🛡️ SECURITY LAYER 3: RATE LIMITING ---
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100, 
    message: { error: "⚠️ SYSTEM ALERT: Too many requests. Initiating cooldown sequence." }
});
app.use('/api/', apiLimiter);

const authLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, 
    max: 10, 
    message: { error: "⛔ ACCESS DENIED: Max authentication attempts reached." }
});

// --- 🛡️ SECURITY LAYER 4: PREVENT API CACHING (GHOST CACHE FIX) ---
app.use('/api', (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');
    next();
});

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const JWT_SECRET = process.env.JWT_SECRET;
const dbURI = process.env.DB_URI;

console.log("⏳ Connecting to MongoDB...");
mongoose.connect(dbURI, { serverSelectionTimeoutMS: 30000, socketTimeoutMS: 45000 })
.then(() => console.log("✅ SERVER ONLINE: DATABASE CONNECTED (SECURE MODE)"))
.catch((err) => console.error("❌ DB CONNECTION ERROR:", err.message));

// --- SCHEMAS ---
const pcSchema = new mongoose.Schema({
    name: String, price: String, description: String, lore: String, stock: { type: Number, default: 1 }, 
    images: [String], status: { type: String, default: 'available' }, category: { type: String, default: 'drop' },    
    multitasking: { type: Number, default: 0 },
    specs: { cpu: String, gpu: String, ram: String, ssd: String, mobo: String, psu: String, case: String },
    specDetails: { type: Map, of: String, default: {} }, 
    fps: [{ game: String, score: Number }],
    reviews: [{ user: String, text: String, rating: Number, date: { type: Date, default: Date.now } }],
    votes: { type: Number, default: 0 }
});
const PC = mongoose.model('PC', pcSchema);

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    joined: { type: Date, default: Date.now },
    subscribed: { type: Boolean, default: false },
    resetToken: String,
    resetTokenExpiry: Date,
    wishlist: [{ type: mongoose.Schema.Types.ObjectId, ref: 'PC' }],
    achievements: { type: [String], default: [] }
});
const User = mongoose.model('User', userSchema);

const voteEventSchema = new mongoose.Schema({ 
    title: String, 
    image: String, 
    targetVotes: Number, 
    currentVotes: { type: Number, default: 0 }, 
    startDate: Date, 
    durationDays: Number,
    price: String
});
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

const siteConfigSchema = new mongoose.Schema({
    maintenanceMode: { type: Boolean, default: false },
    maintenanceMessage: { type: String, default: "PHOENIX CODEX is currently undergoing scheduled maintenance. We'll be back online shortly." }
});
const SiteConfig = mongoose.model('SiteConfig', siteConfigSchema);

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

const auth = (req, res, next) => {
    if (req.headers['x-admin-auth'] === ADMIN_PASSWORD) next();
    else res.status(403).json({ error: "⛔ SECURE BREACH DETECTED: WRONG ADMIN PASSWORD" });
};

const authUser = (req, res, next) => {
    const header = req.headers['authorization'] || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: "ACCESS DENIED: NO TOKEN PROVIDED" });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.id;
        next();
    } catch (e) {
        res.status(401).json({ error: "ACCESS DENIED: INVALID OR EXPIRED TOKEN" });
    }
};

// --- 🛡️ SECURITY LAYER 5: MAINTENANCE KILL SWITCH ---
app.use('/api', async (req, res, next) => {
    if (req.path === '/status' || req.path === '/login' || req.headers['x-admin-auth'] === ADMIN_PASSWORD) return next();
    try {
        const config = await SiteConfig.findOne();
        if (config?.maintenanceMode) {
            return res.status(503).json({ maintenance: true, message: config.maintenanceMessage });
        }
    } catch (e) {
        console.error("Maintenance check failed, failing open:", e);
    }
    next();
});

// --- ROUTES ---
app.get('/api/status', async (req, res) => {
    const config = await SiteConfig.findOne();
    res.json({ maintenance: !!config?.maintenanceMode, message: config?.maintenanceMessage || null });
});

app.get('/api/site-config', auth, async (req, res) => {
    let config = await SiteConfig.findOne();
    if (!config) config = await new SiteConfig().save();
    res.json(config);
});

app.post('/api/site-config', auth, async (req, res) => {
    const { maintenanceMode, maintenanceMessage } = req.body;
    let config = await SiteConfig.findOne();
    if (!config) config = new SiteConfig();
    if (typeof maintenanceMode === 'boolean') config.maintenanceMode = maintenanceMode;
    if (typeof maintenanceMessage === 'string') config.maintenanceMessage = maintenanceMessage;
    await config.save();
    res.json({ success: true, config });
});

app.post('/api/register', authLimiter, async (req, res) => {
    try {
        const { username, email, password, subscribed } = req.body;
        if (await User.findOne({ email })) return res.status(400).json({ error: "Email exists" });
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newUser = new User({ username, email, password: hashedPassword, subscribed: !!subscribed });
        await newUser.save();
        if (subscribed) {
            try { await new Newsletter({ email }).save(); } catch (e) { console.error("Newsletter subscribe failed:", e); }
        }
        const token = jwt.sign({ id: newUser._id, username: newUser.username }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ success: true, username: newUser.username, token });
    } catch (e) { res.status(500).json({ error: "Error" }); }
});

app.post('/api/user-login', authLimiter, async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ error: "Invalid Credentials" });
        const isMatch = await bcrypt.compare(password, user.password);
        if (isMatch) {
            const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
            res.json({ success: true, username: user.username, token });
        }
        else res.status(400).json({ error: "Invalid Credentials" });
    } catch (e) { res.status(500).json({ error: "Server Error" }); }
});

app.get('/api/me', authUser, async (req, res) => {
    try {
        const user = await User.findById(req.userId).populate('wishlist');
        if (!user) return res.status(404).json({ error: "User not found" });
        res.json({ username: user.username, wishlist: user.wishlist, achievements: user.achievements });
    } catch (e) { res.status(500).json({ error: "Server Error" }); }
});

app.post('/api/wishlist/:pcId', authUser, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: "User not found" });
        if (!user.wishlist.some(id => id.toString() === req.params.pcId)) {
            user.wishlist.push(req.params.pcId);
            await user.save();
        }
        await user.populate('wishlist');
        res.json({ success: true, wishlist: user.wishlist });
    } catch (e) { res.status(500).json({ error: "Server Error" }); }
});

app.delete('/api/wishlist/:pcId', authUser, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: "User not found" });
        user.wishlist = user.wishlist.filter(id => id.toString() !== req.params.pcId);
        await user.save();
        await user.populate('wishlist');
        res.json({ success: true, wishlist: user.wishlist });
    } catch (e) { res.status(500).json({ error: "Server Error" }); }
});

app.post('/api/achievements', authUser, async (req, res) => {
    try {
        const { id } = req.body;
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: "User not found" });
        if (id && !user.achievements.includes(id)) {
            user.achievements.push(id);
            await user.save();
        }
        res.json({ success: true, achievements: user.achievements });
    } catch (e) { res.status(500).json({ error: "Server Error" }); }
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

app.post('/api/reset-password', async (req, res) => {
    const { token, newPass } = req.body;
    try {
        const user = await User.findOne({ resetToken: token, resetTokenExpiry: { $gt: Date.now() } });
        if (!user) return res.status(400).json({ error: "Invalid Token" });
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPass, salt);
        user.resetToken = undefined;
        user.resetTokenExpiry = undefined;
        await user.save();
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: "Error" }); }
});

app.get('/api/users/count', auth, async (req, res) => { const count = await User.countDocuments(); res.json({ count }); });
app.post('/api/login', authLimiter, (req, res) => { if (req.body.password === ADMIN_PASSWORD) res.json({ success: true }); else res.status(403).json({ success: false }); });

app.get('/api/drops', async (req, res) => { const all = await PC.find(); res.json(all); });
app.post('/api/drops', auth, async (req, res) => { const n = new PC(req.body); await n.save(); res.json(n); });
app.put('/api/drops/:id', auth, async (req, res) => { const u = await PC.findByIdAndUpdate(req.params.id, req.body, {new:true}); res.json(u); });
app.delete('/api/drops/:id', auth, async (req, res) => { await PC.findByIdAndDelete(req.params.id); res.json({msg:"Deleted"}); });

app.get('/api/vote-event', async (req, res) => { const event = await VoteEvent.findOne(); res.json(event || {}); });
app.post('/api/vote-event', auth, async (req, res) => { await VoteEvent.deleteMany({}); const n = new VoteEvent(req.body); await n.save(); res.json(n); });
app.post('/api/cast-vote', async (req, res) => { const event = await VoteEvent.findOne(); if(event) { event.currentVotes += 1; await event.save(); res.json({ votes: event.currentVotes }); } else { res.status(404).json({ error: "No active vote" }); } });

app.post('/api/generate-code', auth, async (req, res) => { const { pcId, pcName } = req.body; const code = 'CDX-' + crypto.randomBytes(3).toString('hex').toUpperCase(); const ticket = new ReviewTicket({ code, pcId, pcName }); await ticket.save(); res.json(ticket); });
app.get('/api/tickets', auth, async (req, res) => { const tickets = await ReviewTicket.find().sort({ generatedAt: -1 }); res.json(tickets); });

app.post('/api/activate-ticket/:id', auth, async (req, res) => {
    try {
        const ticket = await ReviewTicket.findById(req.params.id);
        if(ticket) { ticket.status = 'active'; await ticket.save(); res.json({ success: true }); } 
        else { res.status(404).json({ error: "Ticket not found" }); }
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

app.post('/api/newsletter', authLimiter, async (req, res) => { const { email } = req.body; if(!email) return res.status(400).json({error:"Email required"}); const sub = new Newsletter({ email }); await sub.save(); res.json({ success: true }); });
app.get('/api/newsletter', auth, async (req, res) => { const subs = await Newsletter.find().sort({ date: -1 }); res.json(subs); });

app.listen(PORT, '0.0.0.0', () => { console.log(`🚀 Server running on port ${PORT}`); });