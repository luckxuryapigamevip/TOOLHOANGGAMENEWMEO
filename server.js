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
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    created_at INTEGER DEFAULT (strftime('%s','now')*1000)
  );
  CREATE TABLE IF NOT EXISTS otps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    code TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    verified INTEGER DEFAULT 0
  );
`);

// TỰ ĐỘNG TẠO ADMIN
const adminEmail = 'htrannhat264@gmail.com';
const adminPass = 'Hoang2010';
const adminName = 'Hoang Admin';

const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(adminEmail);
if (!exists) {
  const hash = bcrypt.hashSync(adminPass, 10);
  db.prepare(`INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, 'admin')`)
    .run(adminName, adminEmail, hash);
  console.log('✅ Đã tạo tài khoản admin:', adminEmail);
}

/* ============================================================
   2. CẤU HÌNH MIDDLEWARE CHUNG
   ============================================================ */
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(cookieParser());
app.use(session({
  secret: 'hoang_tool_sieu_bi_mat_2025',
  resave: false,
  saveUninitialized: false,
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
   3. MIDDLEWARE GUARDS (BẢO VỆ TRANG)
   ============================================================ */
function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/');
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ ok: false, msg: 'Không phải admin' });
  }
  next();
}
function requireLoginAPI(req, res, next) {
  if (!req.session.user) return res.status(401).json({ ok: false, msg: 'Chưa đăng nhập' });
  next();
}

/* ============================================================
   4. MAILER (CẤU HÌNH GỬI OTP QUA GMAIL)
   ============================================================ */
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || ''
  }
});

async function sendOTPEmail(to, otp) {
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
    console.warn('⚠️ Chưa cấu hình SMTP. OTP là:', otp);
    return false;
  }
  try {
    await transporter.sendMail({
      from: `"HOÀNG TOOL" <${process.env.SMTP_USER}>`,
      to,
      subject: 'HOÀNG TOOL — Mã OTP',
      html: `<h2>Mã OTP của bạn là: <span style="color:red">${otp}</span></h2>`
    });
    return true;
  } catch (e) {
    console.error('Lỗi gửi mail:', e.message);
    return false;
  }
}

/* ============================================================
   5. API ĐĂNG KÝ / ĐĂNG NHẬP / QUÊN MẬT KHẨU
   ============================================================ */
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ ok: false, msg: 'Thiếu thông tin' });
    if (password.length < 6) return res.status(400).json({ ok: false, msg: 'Mật khẩu ≥ 6 ký tự' });

    const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase());
    if (exists) return res.status(400).json({ ok: false, msg: 'Email đã tồn tại' });

    const hash = await bcrypt.hash(password, 10);
    db.prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)')
      .run(name.trim(), email.toLowerCase(), hash, 'user');
    res.json({ ok: true, msg: 'Đăng ký thành công' });
  } catch (e) { res.status(500).json({ ok: false, msg: 'Lỗi server' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
    if (!user) return res.status(401).json({ ok: false, msg: 'Tài khoản không tồn tại' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ ok: false, msg: 'Mật khẩu sai' });

    req.session.user = { id: user.id, name: user.name, email: user.email, role: user.role };
    res.json({ ok: true, msg: `Chào ${user.name}`, user: req.session.user });
  } catch (e) { res.status(500).json({ ok: false, msg: 'Lỗi server' }); }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => { res.clearCookie('connect.sid'); res.json({ ok: true }); });
});

app.get('/api/me', (req, res) => {
  if (!req.session.user) return res.status(401).json({ ok: false });
  res.json({ ok: true, user: req.session.user });
});

// Quên mật khẩu
app.post('/api/forgot/send-otp', async (req, res) => {
  const email = (req.body.email || '').toLowerCase().trim();
  const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (!user) return res.status(400).json({ ok: false, msg: 'Email chưa đăng ký' });

  db.prepare('DELETE FROM otps WHERE email = ?').run(email);
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  db.prepare('INSERT INTO otps (email, code, expires_at) VALUES (?, ?, ?)').run(email, code, Date.now() + 5 * 60 * 1000);

  const sent = await sendOTPEmail(email, code);
  if (!sent) return res.json({ ok: true, msg: 'OTP (DEV)', devOtp: code });
  res.json({ ok: true, msg: 'Đã gửi OTP' });
});

app.post('/api/forgot/verify-otp', (req, res) => {
  const { email, code } = req.body;
  const rec = db.prepare('SELECT * FROM otps WHERE email = ? ORDER BY id DESC LIMIT 1').get(email.toLowerCase());
  if (!rec || Date.now() > rec.expires_at) return res.status(400).json({ ok: false, msg: 'OTP hết hạn' });
  if (rec.code !== code.toString()) return res.status(400).json({ ok: false, msg: 'OTP sai' });

  db.prepare('UPDATE otps SET verified = 1 WHERE id = ?').run(rec.id);
  res.json({ ok: true, msg: 'Xác thực thành công' });
});

app.post('/api/forgot/reset-password', async (req, res) => {
  const { email, code, newPassword } = req.body;
  const rec = db.prepare('SELECT * FROM otps WHERE email = ? ORDER BY id DESC LIMIT 1').get(email.toLowerCase());
  if (!rec || rec.code !== code.toString() || !rec.verified) return res.status(400).json({ ok: false, msg: 'Lỗi xác thực' });

  const hash = await bcrypt.hash(newPassword, 10);
  db.prepare('UPDATE users SET password = ? WHERE email = ?').run(hash, email.toLowerCase());
  db.prepare('DELETE FROM otps WHERE email = ?').run(email.toLowerCase());
  res.json({ ok: true, msg: 'Đổi mật khẩu thành công' });
});

/* ============================================================
   6. API TOOL & ADMIN
   ============================================================ */
const TOOL_ENDPOINTS = { md5: { url: 'https://upgraded-potato-leu6.onrender.com/api/tx/md5' }, tx: { url: 'https://upgraded-potato-leu6.onrender.com/api/tx' } };
const toolCache = {};
app.get('/api/tool/token', requireLoginAPI, (req, res) => {
  const exp = Date.now() + 2 * 60 * 1000;
  const sig = crypto.createHmac('sha256', 'hoang_hmac_secret').update(`${req.sessionID}|${exp}`).digest('hex');
  res.json({ ok: true, token: `${exp}.${sig}` });
});
app.get('/api/tool/predict', requireLoginAPI, async (req, res) => {
  const cfg = TOOL_ENDPOINTS[req.query.game];
  if (!cfg) return res.status(400).json({ ok: false });
  const cached = toolCache[req.query.game];
  if (cached && Date.now() < cached.exp) return res.json({ ok: true, data: cached.data });

  try {
    const up = await fetch(cfg.url, { headers: { Accept: 'application/json' } });
    const raw = await up.json();
    const d = Array.isArray(raw) ? raw[0] : raw;
    const data = { phien: String(d.Phien_hien_tai ?? d.Phien ?? ''), du_doan: String(d.Du_doan ?? d.du_doan ?? ''), tin_cay: d.Do_tin_cay ?? d.do_tin_cay ?? '' };
    toolCache[req.query.game] = { data, exp: Date.now() + 4000 };
    res.json({ ok: true, data });
  } catch (e) { res.status(502).json({ ok: false }); }
});
app.get('/api/admin/users', requireAdmin, (req, res) => {
  res.json({ ok: true, users: db.prepare('SELECT id, name, email, role, created_at FROM users').all() });
});

/* ============================================================
   7. ROUTE TRANG (ĐÚNG LUỒNG: ĐĂNG NHẬP -> GIỚI THIỆU -> GAME)
   ============================================================ */
// Trang chủ (Đăng nhập). Nếu đã đăng nhập thì nhảy sang /intro
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/intro');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Trang Giới thiệu (Bắt buộc đăng nhập mới xem được)
app.get('/intro', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index2.html'));
});

// Kho Game (Bắt buộc đăng nhập mới xem được)
app.get('/game', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'game.html'));
});

// Trang Admin
app.get('/admin', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Load file tĩnh (ảnh, css) nhưng không cho truy cập file index gốc
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// Bắt lỗi 404
app.use((req, res) => res.status(404).send('404 Not Found'));

app.listen(PORT, () => {
  console.log(`🚀 HOÀNG TOOL SERVER chạy tại http://localhost:${PORT}`);
});
