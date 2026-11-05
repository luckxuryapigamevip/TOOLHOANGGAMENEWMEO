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
   KHỞI TẠO DATABASE
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

  CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
  CREATE INDEX IF NOT EXISTS idx_otps_email ON otps(email);
`);

/* Tạo admin mặc định */
const adminEmail = (process.env.ADMIN_EMAIL || '').toLowerCase();
if (adminEmail) {
  const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(adminEmail);
  if (!exists) {
    const hash = bcrypt.hashSync(process.env.ADMIN_PASS || 'admin123', 10);
    db.prepare(`INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, 'admin')`)
      .run(process.env.ADMIN_NAME || 'Admin', adminEmail, hash);
    console.log('✅ Đã tạo admin:', adminEmail);
  }
}

/* ============================================================
   MIDDLEWARE
   ============================================================ */
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET || 'secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    sameSite: 'lax',
    secure: false
  }
}));

/* Chặn truy cập file nhạy cảm */
app.use((req, res, next) => {
  const p = req.path.toLowerCase();
  if (p.includes('.env') || p.includes('database.db') ||
      p.includes('server.js') || p.includes('package.json')) {
    return res.status(403).send('Forbidden');
  }
  next();
});

/* ============================================================
   GUARDS
   ============================================================ */
function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/');
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ ok: false, msg: 'Bạn không phải admin' });
  }
  next();
}
function requireLoginAPI(req, res, next) {
  if (!req.session.user) return res.status(401).json({ ok: false, msg: 'Chưa đăng nhập' });
  next();
}

/* ============================================================
   MAILER
   ============================================================ */
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: Number(process.env.SMTP_PORT) || 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

async function sendOTPEmail(to, otp) {
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
    console.warn('⚠️  Chưa cấu hình SMTP. OTP:', otp);
    return false;
  }
  try {
    await transporter.sendMail({
      from: `"HOÀNG TOOL" <${process.env.SMTP_USER}>`,
      to,
      subject: 'HOÀNG TOOL — Mã OTP của bạn',
      html: `
        <div style="font-family:sans-serif;max-width:480px;margin:auto;padding:30px;
                    background:#0d1220;color:#e8eefc;border-radius:16px">
          <h2 style="color:#3b82f6;margin:0 0 16px">HOÀNG TOOL</h2>
          <p>Mã OTP đổi mật khẩu của bạn là:</p>
          <div style="font-size:36px;font-weight:900;letter-spacing:8px;
                      color:#8b5cf6;text-align:center;padding:20px;background:#0a0f1c;
                      border-radius:12px;margin:20px 0">${otp}</div>
          <p style="color:#8b98b5;font-size:.9rem">Mã có hiệu lực 5 phút. Không chia sẻ cho ai.</p>
        </div>
      `
    });
    return true;
  } catch (e) {
    console.error('Mail error:', e.message);
    return false;
  }
}

/* ============================================================
   AUTH API
   ============================================================ */
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ ok: false, msg: 'Thiếu thông tin' });
    if (password.length < 6) return res.status(400).json({ ok: false, msg: 'Mật khẩu phải từ 6 ký tự' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ ok: false, msg: 'Email không hợp lệ' });

    const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase());
    if (exists) return res.status(400).json({ ok: false, msg: 'Email đã tồn tại' });

    const hash = await bcrypt.hash(password, 10);
    db.prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)')
      .run(name.trim(), email.toLowerCase(), hash, 'user');

    res.json({ ok: true, msg: 'Đăng ký thành công' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, msg: 'Lỗi server' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ ok: false, msg: 'Thiếu thông tin' });

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
    if (!user) return res.status(401).json({ ok: false, msg: 'Tài khoản không tồn tại' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ ok: false, msg: 'Mật khẩu sai' });

    req.session.user = {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role
    };

    res.json({ ok: true, msg: `Chào mừng ${user.name}!`, user: req.session.user });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, msg: 'Lỗi server' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ ok: true, msg: 'Đã đăng xuất' });
  });
});

app.get('/api/me', (req, res) => {
  if (!req.session.user) return res.status(401).json({ ok: false });
  res.json({ ok: true, user: req.session.user });
});

/* ============================================================
   FORGOT PASSWORD — OTP
   ============================================================ */
app.post('/api/forgot/send-otp', async (req, res) => {
  try {
    const email = (req.body.email || '').toLowerCase().trim();
    if (!email) return res.status(400).json({ ok: false, msg: 'Thiếu email' });

    const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (!user) return res.status(400).json({ ok: false, msg: 'Email chưa được đăng ký' });

    db.prepare('DELETE FROM otps WHERE email = ?').run(email);

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const exp = Date.now() + 5 * 60 * 1000;
    db.prepare('INSERT INTO otps (email, code, expires_at) VALUES (?, ?, ?)')
      .run(email, code, exp);

    const sent = await sendOTPEmail(email, code);
    if (!sent) {
      console.warn('[DEV OTP]', email, '→', code);
      return res.json({ ok: true, msg: 'OTP đã tạo (DEV)', devOtp: code });
    }
    res.json({ ok: true, msg: 'Đã gửi OTP tới email' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, msg: 'Lỗi gửi mail' });
  }
});

app.post('/api/forgot/verify-otp', (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) return res.status(400).json({ ok: false, msg: 'Thiếu thông tin' });

    const rec = db.prepare('SELECT * FROM otps WHERE email = ? ORDER BY id DESC LIMIT 1')
      .get(email.toLowerCase());

    if (!rec) return res.status(400).json({ ok: false, msg: 'Chưa gửi OTP' });
    if (Date.now() > rec.expires_at) {
      db.prepare('DELETE FROM otps WHERE id = ?').run(rec.id);
      return res.status(400).json({ ok: false, msg: 'OTP hết hạn' });
    }
    if (rec.code !== code.toString()) {
      return res.status(400).json({ ok: false, msg: 'OTP sai' });
    }

    db.prepare('UPDATE otps SET verified = 1 WHERE id = ?').run(rec.id);
    res.json({ ok: true, msg: 'Xác thực OTP thành công' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, msg: 'Lỗi server' });
  }
});

app.post('/api/forgot/reset-password', async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;
    if (!email || !code || !newPassword) return res.status(400).json({ ok: false, msg: 'Thiếu thông tin' });
    if (newPassword.length < 6) return res.status(400).json({ ok: false, msg: 'Mật khẩu phải từ 6 ký tự' });

    const rec = db.prepare('SELECT * FROM otps WHERE email = ? ORDER BY id DESC LIMIT 1')
      .get(email.toLowerCase());

    if (!rec || rec.code !== code.toString() || !rec.verified) {
      return res.status(400).json({ ok: false, msg: 'Chưa xác thực OTP hợp lệ' });
    }

    const hash = await bcrypt.hash(newPassword, 10);
    db.prepare('UPDATE users SET password = ? WHERE email = ?').run(hash, email.toLowerCase());
    db.prepare('DELETE FROM otps WHERE email = ?').run(email.toLowerCase());

    res.json({ ok: true, msg: 'Đổi mật khẩu thành công' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, msg: 'Lỗi server' });
  }
});

/* ============================================================
   🔐 TOOL PROXY — ẨN URL GỐC KHỎI CLIENT
   ============================================================ */
const TOOL_ENDPOINTS = {
  md5: { url: 'https://upgraded-potato-leu6.onrender.com/api/tx/md5' },
  tx:  { url: 'https://upgraded-potato-leu6.onrender.com/api/tx' }
};

const toolCache = {};
const CACHE_TTL = 4000;

const rateLimitMap = {};
const RATE_LIMIT = 30;
const RATE_WINDOW = 60000;

function checkRateLimit(sid) {
  const now = Date.now();
  let rec = rateLimitMap[sid];
  if (!rec || now > rec.resetAt) {
    rec = rateLimitMap[sid] = { count: 0, resetAt: now + RATE_WINDOW };
  }
  rec.count++;
  return rec.count <= RATE_LIMIT;
}

function normalizePrediction(raw) {
  const d = Array.isArray(raw) ? raw[0] : raw;
  if (!d || typeof d !== 'object') return null;
  return {
    phien: String(d.Phien_hien_tai ?? d.Phien ?? d.phien ?? ''),
    du_doan: String(d.Du_doan ?? d.du_doan ?? d.prediction ?? ''),
    tin_cay: d.Do_tin_cay ?? d.do_tin_cay ?? d.confidence ?? '',
    ts: Date.now()
  };
}

/* Cấp token HMAC cho session — hết hạn 2 phút */
const HMAC_SECRET = process.env.HMAC_SECRET || 'hoang_tool_hmac_2025';

app.get('/api/tool/token', requireLoginAPI, (req, res) => {
  const exp = Date.now() + 2 * 60 * 1000;
  const payload = `${req.sessionID}|${exp}`;
  const sig = crypto.createHmac('sha256', HMAC_SECRET).update(payload).digest('hex');
  res.json({ ok: true, token: `${exp}.${sig}` });
});

function verifyToolToken(req, res, next) {
  const token = req.headers['x-tool-token'] || req.query.t;
  if (!token) return res.status(401).json({ ok: false, msg: 'Thiếu token' });
  const parts = String(token).split('.');
  if (parts.length !== 2) return res.status(401).json({ ok: false, msg: 'Token sai định dạng' });
  const exp = Number(parts[0]);
  const sig = parts[1];
  if (!exp || Date.now() > exp) return res.status(401).json({ ok: false, msg: 'Token hết hạn' });
  const payload = `${req.sessionID}|${exp}`;
  const expected = crypto.createHmac('sha256', HMAC_SECRET).update(payload).digest('hex');
  if (sig !== expected) return res.status(401).json({ ok: false, msg: 'Token sai' });
  next();
}

app.get('/api/tool/predict', requireLoginAPI, verifyToolToken, async (req, res) => {
  try {
    const gameKey = String(req.query.game || '').toLowerCase();
    const cfg = TOOL_ENDPOINTS[gameKey];
    if (!cfg) return res.status(400).json({ ok: false, msg: 'Game không hợp lệ' });

    const ref = req.headers.referer || '';
    const host = req.headers.host || '';
    if (ref && !ref.includes(host)) {
      return res.status(403).json({ ok: false, msg: 'Forbidden' });
    }

    const sid = req.sessionID;
    if (!checkRateLimit(sid)) {
      return res.status(429).json({ ok: false, msg: 'Quá nhiều request' });
    }

    const cacheKey = gameKey;
    const cached = toolCache[cacheKey];
    if (cached && Date.now() < cached.exp) {
      return res.json({ ok: true, data: cached.data, cached: true });
    }

    const controller = new AbortController();
    const tid = setTimeout(() => controller.abort(), 8000);
    const upstream = await fetch(cfg.url, {
      signal: controller.signal,
      headers: { 'Accept': 'application/json', 'User-Agent': 'HoangTool/1.0' },
      cache: 'no-store'
    });
    clearTimeout(tid);

    if (!upstream.ok) return res.status(502).json({ ok: false, msg: 'Server tool lỗi' });

    const raw = await upstream.json();
    const data = normalizePrediction(raw);
    if (!data) return res.status(502).json({ ok: false, msg: 'Dữ liệu không hợp lệ' });

    toolCache[cacheKey] = { data, exp: Date.now() + CACHE_TTL };
    res.json({ ok: true, data });
  } catch (err) {
    console.error('[tool proxy]', err.message);
    res.status(500).json({ ok: false, msg: 'Lỗi server' });
  }
});

/* Dọn cache định kỳ */
setInterval(() => {
  const now = Date.now();
  for (const k in toolCache) if (now > toolCache[k].exp) delete toolCache[k];
  for (const sid in rateLimitMap) if (now > rateLimitMap[sid].resetAt) delete rateLimitMap[sid];
}, 30000);

/* ============================================================
   ADMIN API
   ============================================================ */
app.get('/api/admin/users', requireAdmin, (req, res) => {
  const users = db.prepare('SELECT id, name, email, role, created_at FROM users ORDER BY id DESC').all();
  res.json({ ok: true, users });
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (id === req.session.user.id) return res.status(400).json({ ok: false, msg: 'Không thể tự xóa' });
  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  res.json({ ok: true, msg: 'Đã xóa user' });
});

/* ============================================================
   ROUTE TRANG
   ============================================================ */
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/game');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/intro', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index2.html'));
});

app.get('/game', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'game.html'));
});

app.get('/admin', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.use(express.static(path.join(__dirname, 'public'), { index: false }));

app.use((req, res) => res.status(404).send('404 Not Found'));

/* ============================================================
   START
   ============================================================ */
app.listen(PORT, () => {
  console.log(`
  ╔══════════════════════════════════════════╗
  ║   🚀 HOÀNG TOOL SERVER                   ║
  ║   → http://localhost:${PORT}                ║
  ║   Admin: ${(process.env.ADMIN_EMAIL || 'chưa set').padEnd(22)} ║
  ╚══════════════════════════════════════════╝
  `);
});