/**
 * MERN Authentication - Express API (single file)
 * Registration, login, logout, protected routes, input validation,
 * plus role-based authorization (admin-only route) and owner-only data.
 */
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { body, param, validationResult, matchedData } = require('express-validator');

const { MONGODB_URI, JWT_SECRET, ADMIN_EMAIL } = process.env;
const PORT = process.env.PORT || 5000;
if (!MONGODB_URI || !JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('Set MONGODB_URI and a JWT_SECRET of at least 32 characters in .env');
  process.exit(1);
}

// ---------- Models ----------
const User = mongoose.model('User', new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 50 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true, select: false }, // hash only, hidden by default
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
}, { timestamps: true }));

const Note = mongoose.model('Note', new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  title: { type: String, required: true, trim: true, maxlength: 100 },
  content: { type: String, trim: true, maxlength: 2000, default: '' },
}, { timestamps: true }));

// ---------- Validation ----------
const strongPassword = (pw) => /[a-z]/.test(pw) && /[A-Z]/.test(pw) && /\d/.test(pw) && /[^A-Za-z0-9]/.test(pw);

const registerRules = [
  body('name').isString().trim().isLength({ min: 2, max: 50 }).withMessage('Name must be 2-50 characters'),
  body('email').isString().trim().toLowerCase().isEmail().withMessage('Enter a valid email').isLength({ max: 100 }),
  body('password').isString().isLength({ min: 12, max: 128 }).withMessage('Password must be 12-128 characters')
    .custom(strongPassword).withMessage('Password needs upper, lower, number and symbol'),
];
const loginRules = [
  body('email').isString().trim().toLowerCase().isEmail().withMessage('Enter a valid email'),
  body('password').isString().notEmpty().isLength({ max: 128 }).withMessage('Password is required'),
];
const noteRules = [
  body('title').isString().trim().notEmpty().withMessage('Title is required').isLength({ max: 100 }),
  body('content').optional({ values: 'falsy' }).isString().trim().isLength({ max: 2000 }),
];
const idRule = [param('id').isMongoId().withMessage('Invalid id')];

function validate(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ message: 'Validation failed', errors: errors.array().map((e) => ({ field: e.path, message: e.msg })) });
  }
  req.clean = matchedData(req, { locations: ['body'], includeOptionals: true }); // unknown fields dropped
  next();
}

// ---------- Authentication helpers ----------
const cookieOpts = () => ({
  httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', maxAge: 60 * 60 * 1000,
});
const publicUser = (u) => ({ id: u._id, name: u.name, email: u.email, role: u.role });
const issueToken = (res, user) => {
  const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
  res.cookie('token', token, cookieOpts());
};

// AUTHENTICATION middleware: "who are you?" -> verifies the token
function requireAuth(req, res, next) {
  try {
    const payload = jwt.verify(req.cookies.token || '', JWT_SECRET);
    req.user = { id: payload.id, role: payload.role };
    next();
  } catch {
    res.status(401).json({ message: 'Please log in' });
  }
}
// AUTHORIZATION middleware: "are you allowed?" -> checks the role
const requireRole = (role) => (req, res, next) =>
  req.user.role === role ? next() : res.status(403).json({ message: 'Forbidden: insufficient permissions' });

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false,
  message: { message: 'Too many attempts. Try again later.' } });
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', 12);

// ---------- App ----------
const app = express();
app.use(helmet());
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
mongoose.set('sanitizeFilter', true); // blocks NoSQL injection like {"$ne": ""}

// Registration
app.post('/api/auth/register', authLimiter, registerRules, validate, async (req, res, next) => {
  try {
    const { name, email, password } = req.clean;
    if (await User.exists({ email })) return res.status(409).json({ message: 'That email is already registered' });
    const passwordHash = await bcrypt.hash(password, 12);
    const role = ADMIN_EMAIL && email === ADMIN_EMAIL.toLowerCase() ? 'admin' : 'user';
    const user = await User.create({ name, email, passwordHash, role });
    issueToken(res, user);
    res.status(201).json(publicUser(user));
  } catch (err) { next(err); }
});

// Login
app.post('/api/auth/login', authLimiter, loginRules, validate, async (req, res, next) => {
  try {
    const { email, password } = req.clean;
    const user = await User.findOne({ email }).select('+passwordHash');
    const ok = await bcrypt.compare(password, user ? user.passwordHash : DUMMY_HASH);
    if (!user || !ok) return res.status(401).json({ message: 'Invalid email or password' }); // generic on purpose
    issueToken(res, user);
    res.json(publicUser(user));
  } catch (err) { next(err); }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token', { ...cookieOpts(), maxAge: undefined });
  res.json({ message: 'Logged out' });
});

// Current session
app.get('/api/auth/me', requireAuth, async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(401).json({ message: 'Please log in' });
    res.json(publicUser(user));
  } catch (err) { next(err); }
});

// PROTECTED functionality: personal notes. Every query is filtered by owner,
// so a logged-in user can only see/change THEIR OWN notes (authorization).
const notes = express.Router();
notes.use(requireAuth);
notes.get('/', async (req, res, next) => {
  try { res.json(await Note.find({ owner: req.user.id }).sort({ createdAt: -1 })); } catch (e) { next(e); }
});
notes.post('/', noteRules, validate, async (req, res, next) => {
  try { res.status(201).json(await Note.create({ ...req.clean, owner: req.user.id })); } catch (e) { next(e); }
});
notes.put('/:id', idRule, noteRules, validate, async (req, res, next) => {
  try {
    const note = await Note.findOneAndUpdate({ _id: req.params.id, owner: req.user.id }, req.clean, { new: true, runValidators: true });
    if (!note) return res.status(404).json({ message: 'Note not found' });
    res.json(note);
  } catch (e) { next(e); }
});
notes.delete('/:id', idRule, validate, async (req, res, next) => {
  try {
    const note = await Note.findOneAndDelete({ _id: req.params.id, owner: req.user.id });
    if (!note) return res.status(404).json({ message: 'Note not found' });
    res.json({ message: 'Note deleted' });
  } catch (e) { next(e); }
});
app.use('/api/notes', notes);

// ADMIN-ONLY functionality: authenticated AND authorized as admin
app.get('/api/admin/users', requireAuth, requireRole('admin'), async (req, res, next) => {
  try { res.json((await User.find().sort({ createdAt: -1 })).map(publicUser)); } catch (e) { next(e); }
});

app.use('/api', (req, res) => res.status(404).json({ message: 'Not found' }));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ message: 'Something went wrong' }); });

mongoose.connect(MONGODB_URI)
  .then(() => app.listen(PORT, () => console.log('API on http://localhost:' + PORT)))
  .catch((e) => { console.error('MongoDB connection failed:', e.message); process.exit(1); });
