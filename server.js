require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const nodemailer = require('nodemailer');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const db = new Database('database.db');

/* ============================================================
   1. KHỞI TẠO DATABASE & TÀI KHOẢN ADMIN (Gắn cứng)
   ============================================================ */
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT DEFAULT 'user', created_at INTEGER DEFAULT (strftime('%s','now')*1000)
  );
  CREATE TABLE IF NOT EXISTS otps (
    id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL, code TEXT NOT NULL, expires_at INTEGER NOT NULL, verified INTEGER DEFAULT 0
  );
`);

const adminEmail = 'htrannhat264@gmail.com';
const adminPass = 'Hoang2010';
const adminName = 'Hoang Admin';

const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(adminEmail);
if (!exists) {
  const hash = bcrypt.hashSync(adminPass, 10);
  db.prepare(`INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, 'admin')`).run(adminName, adminEmail, hash);
  console.log('✅ Đã tạo tài khoản admin:', adminEmail);
}

/* ============================================================
   2. CẤU HÌNH MIDDLEWARE
   ============================================================ */
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(cookieParser());
app.use(session({
  secret: 'hoang_tool_sieu_bi_mat_2025', resave: false, saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000, httpOnly: true, sameSite: 'lax' }
}));

app.use((req, res, next) => {
  const p = req.path.toLowerCase();
  if (p.includes('.env') || p.includes('database.db') || p.includes('server.js') || p.includes('package.json')) {
    return res.status(403).send('Forbidden');
  }
  next();
});

/* ============================================================
   3. MIDDLEWARE GUARDS
   ============================================================ */
function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/');
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).json({ ok: false, msg: 'Không phải admin' });
  next();
}
function requireLoginAPI(req, res, next) {
  if (!req.session.user) return res.status(401).json({ ok: false, msg: 'Chưa đăng nhập' });
  next();
}

/* ============================================================
   4. MAILER
   ============================================================ */
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com', port: 587, secure: false,
  auth: { user: process.env.SMTP_USER || '', pass: process.env.SMTP_PASS || '' }
});
async function sendOTPEmail(to, otp) {
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) return false;
  try {
    await transporter.sendMail({ from: `"HOÀNG TOOL" <${process.env.SMTP_USER}>`, to, subject: 'HOÀNG TOOL — Mã OTP', html: `<h2>Mã OTP: <span style="color:red">${otp}</span></h2>` });
    return true;
  } catch (e) { return false; }
}

/* ============================================================
   5. API AUTH
   ============================================================ */
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase())) return res.status(400).json({ ok: false, msg: 'Email đã tồn tại' });
    const hash = await bcrypt.hash(password, 10);
    db.prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)').run(name.trim(), email.toLowerCase(), hash, 'user');
    res.json({ ok: true, msg: 'Đăng ký thành công' });
  } catch (e) { res.status(500).json({ ok: false, msg: 'Lỗi server' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ ok: false, msg: 'Sai email hoặc mật khẩu' });
    req.session.user = { id: user.id, name: user.name, email: user.email, role: user.role };
    res.json({ ok: true, msg: `Chào ${user.name}`, user: req.session.user });
  } catch (e) { res.status(500).json({ ok: false, msg: 'Lỗi server' }); }
});

app.post('/api/logout', (req, res) => { req.session.destroy(() => { res.clearCookie('connect.sid'); res.json({ ok: true }); }); });
app.get('/api/me', (req, res) => { if (!req.session.user) return res.status(401).json({ ok: false }); res.json({ ok: true, user: req.session.user }); });

app.post('/api/forgot/send-otp', async (req, res) => {
  const email = (req.body.email || '').toLowerCase().trim();
  if (!db.prepare('SELECT id FROM users WHERE email = ?').get(email)) return res.status(400).json({ ok: false, msg: 'Email chưa đăng ký' });
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  db.prepare('DELETE FROM otps WHERE email = ?').run(email);
  db.prepare('INSERT INTO otps (email, code, expires_at) VALUES (?, ?, ?)').run(email, code, Date.now() + 5 * 60 * 1000);
  const sent = await sendOTPEmail(email, code);
  if (!sent) return res.json({ ok: true, msg: 'OTP (DEV)', devOtp: code });
  res.json({ ok: true, msg: 'Đã gửi OTP' });
});

app.post('/api/forgot/verify-otp', (req, res) => {
  const rec = db.prepare('SELECT * FROM otps WHERE email = ? ORDER BY id DESC LIMIT 1').get(req.body.email.toLowerCase());
  if (!rec || Date.now() > rec.expires_at || rec.code !== req.body.code.toString()) return res.status(400).json({ ok: false, msg: 'OTP sai hoặc hết hạn' });
  db.prepare('UPDATE otps SET verified = 1 WHERE id = ?').run(rec.id);
  res.json({ ok: true, msg: 'Thành công' });
});

app.post('/api/forgot/reset-password', async (req, res) => {
  const { email, code, newPassword } = req.body;
  const rec = db.prepare('SELECT * FROM otps WHERE email = ? ORDER BY id DESC LIMIT 1').get(email.toLowerCase());
  if (!rec || rec.code !== code.toString() || !rec.verified) return res.status(400).json({ ok: false, msg: 'Lỗi xác thực' });
  const hash = await bcrypt.hash(newPassword, 10);
  db.prepare('UPDATE users SET password = ? WHERE email = ?').run(hash, email.toLowerCase());
  res.json({ ok: true, msg: 'Thành công' });
});

/* ============================================================
   6. API TOOL & ADMIN
   ============================================================ */
const TOOL_ENDPOINTS = { md5: { url: 'https://upgraded-potato-leu6.onrender.com/api/tx/md5' }, tx: { url: 'https://upgraded-potato-leu6.onrender.com/api/tx' } };
const toolCache = {};
app.get('/api/tool/token', requireLoginAPI, (req, res) => {
  const exp = Date.now() + 2 * 60 * 1000;
  res.json({ ok: true, token: `${exp}.${crypto.createHmac('sha256', 'hoang_hmac_secret').update(`${req.sessionID}|${exp}`).digest('hex')}` });
});
app.get('/api/tool/predict', requireLoginAPI, async (req, res) => {
  const cfg = TOOL_ENDPOINTS[req.query.game]; if (!cfg) return res.status(400).json({ ok: false });
  if (toolCache[req.query.game] && Date.now() < toolCache[req.query.game].exp) return res.json({ ok: true, data: toolCache[req.query.game].data });
  try {
    const raw = await (await fetch(cfg.url, { headers: { Accept: 'application/json' } })).json();
    const d = Array.isArray(raw) ? raw[0] : raw;
    const data = { phien: String(d.Phien_hien_tai ?? d.Phien ?? ''), du_doan: String(d.Du_doan ?? d.du_doan ?? ''), tin_cay: d.Do_tin_cay ?? d.do_tin_cay ?? '' };
    toolCache[req.query.game] = { data, exp: Date.now() + 4000 };
    res.json({ ok: true, data });
  } catch (e) { res.status(502).json({ ok: false }); }
});
app.get('/api/admin/users', requireAdmin, (req, res) => { res.json({ ok: true, users: db.prepare('SELECT id, name, email, role, created_at FROM users').all() }); });
app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (id === req.session.user.id) return res.status(400).json({ ok: false, msg: 'Không thể tự xóa chính mình' });
  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  res.json({ ok: true, msg: 'Đã xóa user' });
});

/* ============================================================
   7. ROUTE TRANG (ĐÚNG LUỒNG: ĐĂNG NHẬP -> GIỚI THIỆU -> GAME)
   ============================================================ */
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/home');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/home', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index2.html'));
});

app.get('/game', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'game.html'));
});

// TRANG ADMIN BÍ MẬT (Cần đăng nhập admin + có key)
app.get('/hoang-tool-control-2286', requireAdmin, (req, res) => {
  if (req.query.key !== '123456') {
    return res.status(403).send('<h1 style="color:red;text-align:center;margin-top:50px;font-family:sans-serif;">404 Not Found</h1>');
  }
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.use(express.static(path.join(__dirname, 'public'), { index: false }));
app.use((req, res) => res.status(404).send('404 Not Found'));
app.listen(PORT, () => console.log(`🚀 Server chạy tại http://localhost:${PORT}`));
