const express  = require('express');
const cors     = require('cors');
const session  = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const multer   = require('multer');
const path     = require('path');
const fs       = require('fs');
const crypto   = require('crypto');

// ── CLOUDFLARE R2 CONFIG ──
const R2_ACCOUNT_ID   = process.env.R2_ACCOUNT_ID   || '';
const R2_ACCESS_KEY   = process.env.R2_ACCESS_KEY_ID || '';
const R2_SECRET_KEY   = process.env.R2_SECRET_ACCESS_KEY || '';
const R2_BUCKET       = process.env.R2_BUCKET_NAME   || 'checkbox-task-uploads';
const R2_PUBLIC_URL   = process.env.R2_PUBLIC_URL    || '';
const R2_ENDPOINT     = process.env.R2_ENDPOINT      || '';
const USE_R2          = R2_ACCESS_KEY && R2_SECRET_KEY && R2_ENDPOINT;

// AWS Signature V4 — R2 ga fayl yuklash uchun (npm kerak emas)
async function r2Upload(filename, buffer, contentType) {
  const endpoint = R2_ENDPOINT.replace(/\/+$/, '');
  const safe = filename.replace(/[^a-zA-Z0-9._-]/g, '_');
  const url = `${endpoint}/${R2_BUCKET}/${safe}`;
  const host = new URL(url).host;

  const now = new Date();
  // amzDate: yyyyMMddTHHmmssZ — muhim: to'liq format
  const pad = n => String(n).padStart(2,'0');
  const amzDate = `${now.getUTCFullYear()}${pad(now.getUTCMonth()+1)}${pad(now.getUTCDate())}T${pad(now.getUTCHours())}${pad(now.getUTCMinutes())}${pad(now.getUTCSeconds())}Z`;
  const dateStamp = amzDate.slice(0,8);

  const payloadHash = crypto.createHash('sha256').update(buffer).digest('hex');

  // Canonical request — headerlar alifbo tartibida, har biri yangi qatorda
  const ch = `host:${host}
x-amz-content-sha256:${payloadHash}
x-amz-date:${amzDate}
`;
  const sh = 'host;x-amz-content-sha256;x-amz-date';
  const cr = `PUT
/${R2_BUCKET}/${safe}

${ch}
${sh}
${payloadHash}`;

  const scope = `${dateStamp}/auto/s3/aws4_request`;
  const sts = `AWS4-HMAC-SHA256
${amzDate}
${scope}
${crypto.createHash('sha256').update(cr).digest('hex')}`;

  const H = (k, d) => crypto.createHmac('sha256', k).update(d).digest();
  const sk = H(H(H(H(Buffer.from('AWS4' + R2_SECRET_KEY), dateStamp), 'auto'), 's3'), 'aws4_request');
  const sig = crypto.createHmac('sha256', sk).update(sts).digest('hex');
  const auth = `AWS4-HMAC-SHA256 Credential=${R2_ACCESS_KEY}/${scope}, SignedHeaders=${sh}, Signature=${sig}`;

  const res = await fetch(url, {
    method: 'PUT',
    headers: {
      'Authorization': auth,
      'Content-Type': contentType,
      'Content-Length': String(buffer.length),
      'x-amz-content-sha256': payloadHash,
      'x-amz-date': amzDate,
    },
    body: buffer,
    duplex: 'half'
  });
  if (!res.ok) throw new Error(`R2 upload failed: ${res.status} ${await res.text()}`);
  return `${R2_PUBLIC_URL}/${safe}`;
}

async function r2Delete(filename) {
  if (!filename || !USE_R2) return;
  try {
    const endpoint = R2_ENDPOINT.replace(/\/+$/, '');
    const safeFilename = filename.replace(/[^a-zA-Z0-9._-]/g, '_');
    const objectUrl = `${endpoint}/${R2_BUCKET}/${safeFilename}`;
    const parsedUrl = new URL(objectUrl);
    const host = parsedUrl.host;
    const canonicalUri = parsedUrl.pathname;
    const now = new Date();
    const amzDate = now.toISOString().replace(/[-:]/g,'').replace(/\.\d{3}/,'').slice(0,15) + 'Z';
    const dateStamp = amzDate.slice(0, 8);
    const emptyHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const signedHeaderNames = 'host;x-amz-content-sha256;x-amz-date';
    const canonicalHeaders = `host:${host}\nx-amz-content-sha256:${emptyHash}\nx-amz-date:${amzDate}\n`;
    const cr = ['DELETE', canonicalUri, '', canonicalHeaders, signedHeaderNames, emptyHash].join('\n');
    const credentialScope = `${dateStamp}/auto/s3/aws4_request`;
    const hashedCR = crypto.createHash('sha256').update(cr).digest('hex');
    const sts = `AWS4-HMAC-SHA256\n${amzDate}\n${credentialScope}\n${hashedCR}`;
    const hmac = (k,d,e) => crypto.createHmac('sha256',k).update(d).digest(e);
    const sk = hmac(hmac(hmac(hmac('AWS4'+R2_SECRET_KEY,dateStamp),'auto'),'s3'),'aws4_request');
    const sig = hmac(sk, sts, 'hex');
    const auth = `AWS4-HMAC-SHA256 Credential=${R2_ACCESS_KEY}/${credentialScope}, SignedHeaders=${signedHeaderNames}, Signature=${sig}`;
    await fetch(objectUrl, { method:'DELETE', headers:{ 'Authorization':auth, 'x-amz-content-sha256':emptyHash, 'x-amz-date':amzDate } });
  } catch(e) { console.error('r2Delete error:', e.message); }
}

// ── PAROL HASHLASH (Node.js built-in crypto) ──
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(pw, salt, 100000, 64, 'sha512').toString('hex');
  return salt + ':' + hash;
}
function verifyPassword(pw, stored) {
  if (!stored || !stored.includes(':')) return stored === pw;
  const [salt, hash] = stored.split(':');
  return crypto.pbkdf2Sync(pw, salt, 100000, 64, 'sha512').toString('hex') === hash;
}

// ── RATE LIMITING (built-in) ──
const _rl = new Map();
function rateLimit(key, max, windowMs) {
  const now = Date.now();
  const e = _rl.get(key) || { n: 0, t: now };
  if (now - e.t > windowMs) { e.n = 1; e.t = now; } else e.n++;
  _rl.set(key, e);
  if (_rl.size > 10000) { for (const [k,v] of _rl) { if (now - v.t > windowMs*2) _rl.delete(k); } }
  return e.n > max;
}


const app  = express();
const PORT = process.env.PORT || 3001;
const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID     || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const UPLOADS_DIR = process.env.UPLOADS_PATH || path.join(__dirname, 'uploads');
const DATA_FILE   = process.env.DATA_PATH   || path.join(__dirname, 'data.json');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// ── DB ──
function loadDB() {
  if (!fs.existsSync(DATA_FILE)) {
    const e = { users:[], lists:[], tasks:[], files:[], archive:[], shared_tasks:[], comments:[], sessions:{} };
    fs.writeFileSync(DATA_FILE, JSON.stringify(e, null, 2));
    return e;
  }
  try {
    const db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    if (!db.comments)     db.comments = [];
    if (!db.archive)      db.archive  = [];
    if (!db.shared_tasks) db.shared_tasks = [];
    if (!db.files)        db.files    = [];
    if (!db.sessions)     db.sessions = {};
    return db;
  } catch {
    return { users:[], lists:[], tasks:[], files:[], archive:[], shared_tasks:[], comments:[] };
  }
}
function saveDB(db) { fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2)); }

// ── MULTER ──
const ALLOWED_EXT  = /\.(jpg|jpeg|png|gif|webp|svg|mp4|webm|mov|avi|pdf|doc|docx|xls|xlsx|ppt|pptx|txt|csv|zip|json)$/i;
const ALLOWED_MIME = ['image/jpeg','image/png','image/gif','image/webp','image/svg+xml',
  'video/mp4','video/webm','video/quicktime','video/x-msvideo',
  'application/pdf','application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.ms-powerpoint',
  'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  'application/vnd.openxmlformats-officedocument.presentationml.slideshow',
  'text/plain','text/csv','application/zip','application/x-zip-compressed',
  'application/octet-stream'];
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOADS_DIR),
    filename: (req, file, cb) => {
      const ext  = path.extname(file.originalname).toLowerCase();
      const base = path.basename(file.originalname, ext).replace(/[^\w\-]/g,'_').slice(0,50);
      cb(null, Date.now() + '_' + base + ext);
    }
  }),
  limits: { fileSize: 200 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED_EXT.test(ext) || !ALLOWED_MIME.includes(file.mimetype))
      return cb(new Error('Bu fayl turi ruxsat etilmagan'));
    cb(null, true);
  }
});

app.use(express.json({ limit: '10mb' }));

// Xavfsizlik headerlari
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// CORS — faqat ruxsat etilgan originlar
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // mobile / curl
    if (origin.endsWith('.railway.app') || origin.includes('localhost') || ALLOWED_ORIGINS.includes(origin))
      return cb(null, true);
    cb(new Error('CORS: ruxsat etilmagan'));
  },
  credentials: true
}));

// Session — xavfsiz sozlamalar, env dan secret
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7*24*60*60*1000, httpOnly: true, sameSite: 'lax' }
}));
app.use(passport.initialize());
app.use(passport.session());
app.use('/uploads', express.static(UPLOADS_DIR));
app.use(express.static(path.join(__dirname, 'public')));

// ── GOOGLE ──
if (GOOGLE_CLIENT_ID) {
  passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID, clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || ('http://localhost:' + PORT + '/auth/google/callback')
  }, (at, rt, profile, done) => {
    const db = loadDB();
    const email = profile.emails[0].value, name = profile.displayName, gId = profile.id, avatar = profile.photos?.[0]?.value || '';
    let user = db.users.find(u => u.google_id === gId) || db.users.find(u => u.username === email);
    if (user) { user.google_id = gId; user.avatar = avatar; user.name = name; }
    else { user = { id: nid(), username: email, password: null, name, google_id: gId, avatar, created_at: Date.now() }; db.users.push(user); }
    saveDB(db); done(null, user);
  }));
  passport.serializeUser((u, done) => done(null, u.id));
  passport.deserializeUser((id, done) => { const db = loadDB(); done(null, db.users.find(u => u.id === id) || false); });
  app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
  app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/?auth_error=1' }),
    (req, res) => { const t = mkToken(req.user); res.redirect('/?token=' + t); });
} else {
  passport.serializeUser((u, done) => done(null, u.id));
  passport.deserializeUser((id, done) => done(null, false));
  app.get('/auth/google', (req, res) => res.redirect('/?auth_error=google_not_configured'));
}
app.get('/auth/google/status', (req, res) => res.json({ configured: !!GOOGLE_CLIENT_ID }));

// ── HELPERS ──
const nid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
const safeUser = (u) => ({ id: u.id, username: u.username, name: u.name, surname: u.surname || '', patronymic: u.patronymic || '', avatar: u.avatar || '', bg: u.bg || '' });

// Tokenlar data.json ga saqlanadi — Railway restart bo'lsa ham yo'qolmaydi
function mkToken(user) {
  const t = nid();
  const db = loadDB();
  if (!db.sessions) db.sessions = {};
  db.sessions[t] = { userId: user.id, created: Date.now() };
  saveDB(db);
  return t;
}
function getSession(token) {
  if (!token) return null;
  const db = loadDB();
  const sess = (db.sessions || {})[token];
  if (!sess) return null;
  // 30 kundan eski tokenlarni o'chirish
  if (Date.now() - sess.created > 30 * 24 * 60 * 60 * 1000) {
    delete db.sessions[token]; saveDB(db); return null;
  }
  return db.users.find(u => u.id === sess.userId) || null;
}
function deleteSession(token) {
  const db = loadDB();
  if (db.sessions && db.sessions[token]) { delete db.sessions[token]; saveDB(db); }
}
function auth(req, res, next) {
  const t = req.headers['x-token'];
  const user = getSession(t);
  if (user) { req.user = user; return next(); }
  res.status(401).json({ error: 'Login kerak' });
}
const fmtFile = f => ({ id: f.id, name: f.name, url: f.url || ('/uploads/' + f.filename), type: f.mimetype, size: f.size });

function buildTaskTree(taskId, db) {
  const task = db.tasks.find(t => t.id === taskId); if (!task) return null;
  const children = db.tasks.filter(t => t.parent_id === taskId)
    .sort((a, b) => a.completed - b.completed || b.created_at - a.created_at)
    .map(c => buildTaskTree(c.id, db));
  const files = (db.files || []).filter(f => f.ref_id === taskId).map(fmtFile);
  const comments = (db.comments || []).filter(c => c.task_id === taskId).sort((a, b) => a.created_at - b.created_at);
  return { ...task, completed: !!task.completed, children, files, comments };
}
function listTasks(listId, db) {
  return db.tasks.filter(t => t.list_id === listId && !t.parent_id)
    .sort((a, b) => a.completed - b.completed || b.created_at - a.created_at)
    .map(t => buildTaskTree(t.id, db));
}
function deleteTaskDeep(taskId, db) {
  db.tasks.filter(t => t.parent_id === taskId).forEach(c => deleteTaskDeep(c.id, db));
  // Fayllarni diskdan va R2 dan o'chirish
  (db.files || []).filter(f => f.ref_id === taskId).forEach(f => {
    if (USE_R2 && f.url && f.url.startsWith('http')) {
      r2Delete(f.filename).catch(() => {});
    } else if (f.filename) {
      const fp = path.join(UPLOADS_DIR, f.filename);
      try { if (fs.existsSync(fp)) fs.unlinkSync(fp); } catch {}
    }
  });
  db.files        = (db.files       || []).filter(f => f.ref_id  !== taskId);
  db.comments     = (db.comments    || []).filter(c => c.task_id !== taskId);
  db.shared_tasks = (db.shared_tasks || []).filter(s => s.task_id !== taskId);
  db.tasks        = db.tasks.filter(t => t.id !== taskId);
}

// ══════════════════════════════════════════
// PERMISSION HELPER — 'owner'|'edit'|'view'|null
// ══════════════════════════════════════════
function getTaskPermission(taskId, userId, userEmail, db) {
  const task = db.tasks.find(t => t.id === taskId);
  if (!task) return null;
  function findRoot(t) {
    if (!t.parent_id) return t;
    const p = db.tasks.find(x => x.id === t.parent_id);
    return p ? findRoot(p) : t;
  }
  const root = findRoot(task);
  // Egasi?
  const ownList = db.lists.find(l => l.id === root.list_id && l.user_id === userId);
  if (ownList) return 'owner';
  // Ulashilganmi?
  const share = db.shared_tasks.find(s =>
    s.task_id === root.id &&
    s.recipient_email === userEmail &&
    s.status === 'accepted'
  );
  return share ? share.permission : null;
}

// ── AUTH ──
app.post('/api/register', (req, res) => {
  const ip = req.ip || 'x';
  if (rateLimit('reg:'+ip, 5, 60*60*1000)) return res.status(429).json({ error: "Juda ko'p urinish. 1 soat kuting." });
  const { username, password, name } = req.body || {};
  if (!username?.trim() || !password || !name?.trim()) return res.status(400).json({ error: 'Ism, username va parol kerak' });
  if (password.length < 8) return res.status(400).json({ error: "Parol kamida 8 ta belgi bo'lishi kerak" });
  const db = loadDB(); const uname = username.toLowerCase().trim().slice(0,100);
  if (db.users.find(u => u.username === uname)) return res.status(400).json({ error: 'Bu username band' });
  const safeName = name.trim().replace(/<[^>]*>/g,'').slice(0,100);
  const user = { id: nid(), username: uname, password: hashPassword(password), name: safeName, surname: '', patronymic: '', google_id: null, avatar: '', bg: '', created_at: Date.now() };
  db.users.push(user); saveDB(db);
  res.json({ token: mkToken(user), user: safeUser(user) });
});
app.post('/api/login', (req, res) => {
  const ip = req.ip || 'x';
  if (rateLimit('login:'+ip, 10, 5*60*1000)) return res.status(429).json({ error: "Juda ko'p urinish. 5 daqiqa kuting." });
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username va parol kerak' });
  const db = loadDB();
  const user = db.users.find(u => u.username === (username||'').toLowerCase().trim());
  if (!user || !verifyPassword(password, user.password)) return res.status(401).json({ error: "Username yoki parol noto'g'ri" });
  res.json({ token: mkToken(user), user: safeUser(user) });
});
app.get('/api/me', (req, res) => {
  const t = req.headers['x-token'];
  const user = getSession(t);
  if (!user) return res.status(401).json({ error: 'Unauthorized' });
  res.json(safeUser(user));
});
app.post('/api/logout', (req, res) => { deleteSession(req.headers['x-token']); res.json({ ok: true }); });

// ── PROFIL ──
app.put('/api/profile', auth, (req, res) => {
  const db = loadDB(); const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'Topilmadi' });
  const { name, surname, patronymic, bg } = req.body;
  if (name?.trim()) user.name = name.trim();
  if (surname    !== undefined) user.surname    = surname.trim();
  if (patronymic !== undefined) user.patronymic = patronymic.trim();
  if (bg         !== undefined) user.bg         = bg;
  saveDB(db); res.json(safeUser(user));
});
app.post('/api/profile/avatar', auth, upload.single('avatar'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Fayl yo'q" });
  const db = loadDB(); const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'Topilmadi' });
  if (user.avatar && user.avatar.startsWith('/uploads/')) { const old = path.join(UPLOADS_DIR, path.basename(user.avatar)); if (fs.existsSync(old)) try { fs.unlinkSync(old); } catch {} }
  user.avatar = '/uploads/' + req.file.filename;
  saveDB(db); res.json({ avatar: user.avatar });
});
app.post('/api/profile/bg', auth, upload.single('bg'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Fayl yo'q" });
  const db = loadDB(); const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'Topilmadi' });
  user.bg = '/uploads/' + req.file.filename;
  saveDB(db); res.json({ bg: user.bg });
});

// ── LISTS ──
app.get('/api/lists', auth, (req, res) => {
  const db = loadDB();
  const myLists = db.lists.filter(l => l.user_id === req.user.id);
  const result = myLists.sort((a, b) => {
    if (a.is_shared_inbox) return 1;
    if (b.is_shared_inbox) return -1;
    return a.created_at - b.created_at;
  }).map(l => ({ ...l, tasks: listTasks(l.id, db) }));

  // Qabul qilingan ulashilgan topshiriqlarni "Ulashilgan topshiriqlar" ro'yxatida ko'rsatish
  // Asl task dan real-time ma'lumot olamiz
  const accepted = db.shared_tasks.filter(s =>
    s.recipient_email === req.user.username && s.status === 'accepted'
  );
  if (accepted.length > 0) {
    let sharedList = result.find(l => l.is_shared_inbox);
    if (!sharedList) {
      // DB dan topamiz yoki yaratamiz
      let sl = db.lists.find(l => l.user_id === req.user.id && l.is_shared_inbox);
      if (!sl) {
        sl = { id: nid(), user_id: req.user.id, title: 'Ulashilgan topshiriqlar', is_shared_inbox: true, created_at: Date.now() };
        db.lists.push(sl); saveDB(db);
      }
      sharedList = { ...sl, tasks: [] };
      result.push(sharedList);
    }
    // Har bir qabul qilingan share uchun asl topshiriqni olamiz
    const sharedTasks = [];
    accepted.forEach(s => {
      const task = db.tasks.find(t => t.id === s.task_id);
      if (task) {
        const tree = buildTaskTree(task.id, db);
        if (tree) sharedTasks.push({ ...tree, _shared: true, _shareId: s.id, _permission: s.permission, _ownerEmail: '' });
      }
    });
    sharedList.tasks = sharedTasks;
  }

  res.json(result);
});
app.post('/api/lists', auth, (req, res) => {
  if (!req.body.title?.trim()) return res.status(400).json({ error: 'Nom kerak' });
  const db = loadDB();
  const title = req.body.title.trim().replace(/<[^>]*>/g,'').slice(0,200);
  const list = { id: nid(), user_id: req.user.id, title, created_at: Date.now() };
  db.lists.push(list); saveDB(db); res.json({ ...list, tasks: [] });
});
app.put('/api/lists/:id', auth, (req, res) => {
  const db = loadDB(); const list = db.lists.find(l => l.id === req.params.id && l.user_id === req.user.id);
  if (!list) return res.status(404).json({ error: 'Topilmadi' });
  list.title = req.body.title; saveDB(db); res.json({ ok: true });
});
app.delete('/api/lists/:id', auth, (req, res) => {
  const db = loadDB(); const idx = db.lists.findIndex(l => l.id === req.params.id && l.user_id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'Topilmadi' });
  db.tasks.filter(t => t.list_id === req.params.id && !t.parent_id).forEach(t => deleteTaskDeep(t.id, db));
  db.lists.splice(idx, 1); saveDB(db); res.json({ ok: true });
});

// ── TASKS ──
app.post('/api/lists/:lid/tasks', auth, (req, res) => {
  const db = loadDB();
  if (!db.lists.find(l => l.id === req.params.lid && l.user_id === req.user.id)) return res.status(404).json({ error: 'Topilmadi' });
  const task = { id: nid(), list_id: req.params.lid, parent_id: null, user_id: req.user.id, text: req.body.text.trim(), completed: false, priority: 'medium', status: 'todo', deadline: req.body.deadline || null, created_at: Date.now() };
  db.tasks.push(task); saveDB(db); res.json(buildTaskTree(task.id, db));
});
app.post('/api/tasks/:pid/children', auth, (req, res) => {
  const db = loadDB();
  const perm = getTaskPermission(req.params.pid, req.user.id, req.user.username, db);
  if (!perm) return res.status(404).json({ error: 'Topilmadi' });
  if (perm === 'view') return res.status(403).json({ error: "Faqat ko'rish huquqi bor" });
  const parent = db.tasks.find(t => t.id === req.params.pid);
  const task = { id: nid(), list_id: parent.list_id, parent_id: req.params.pid, user_id: req.user.id, text: req.body.text.trim(), completed: false, priority: parent.priority || 'medium', status: 'todo', deadline: req.body.deadline || null, created_at: Date.now() };
  db.tasks.push(task); saveDB(db); res.json(buildTaskTree(task.id, db));
});
app.put('/api/tasks/:id', auth, (req, res) => {
  const db = loadDB();
  const perm = getTaskPermission(req.params.id, req.user.id, req.user.username, db);
  if (!perm) return res.status(404).json({ error: 'Topilmadi' });
  if (perm === 'view') return res.status(403).json({ error: "Faqat ko'rish huquqi bor" });
  const task = db.tasks.find(t => t.id === req.params.id);
  const b = req.body;
  if (b.text      !== undefined) task.text      = b.text;
  if (b.completed !== undefined) task.completed = !!b.completed;
  if (b.priority  !== undefined) task.priority  = b.priority;
  if (b.status    !== undefined) task.status    = b.status;
  if (b.deadline  !== undefined) task.deadline  = b.deadline;
  saveDB(db); res.json({ ok: true });
});
app.delete('/api/tasks/:id', auth, (req, res) => {
  const db = loadDB();
  const perm = getTaskPermission(req.params.id, req.user.id, req.user.username, db);
  if (!perm) return res.status(404).json({ error: 'Topilmadi' });
  if (perm === 'view') return res.status(403).json({ error: "Faqat ko'rish huquqi bor" });
  deleteTaskDeep(req.params.id, db); saveDB(db); res.json({ ok: true });
});

// ── COMMENTS ──
// Topshiriq fayllarini olish
app.get('/api/tasks/:id/files', auth, (req, res) => {
  const db = loadDB();
  const perm = getTaskPermission(req.params.id, req.user.id, req.user.username, db);
  if (!perm) return res.status(404).json({ error: 'Topilmadi' });
  const files = (db.files || []).filter(f => f.ref_id === req.params.id).map(fmtFile);
  res.json(files);
});

app.get('/api/tasks/:id/comments', auth, (req, res) => {
  const db = loadDB();
  res.json((db.comments || []).filter(c => c.task_id === req.params.id).sort((a, b) => a.created_at - b.created_at));
});
app.post('/api/tasks/:id/comments', auth, (req, res) => {
  const db = loadDB();
  const perm = getTaskPermission(req.params.id, req.user.id, req.user.username, db);
  if (!perm) return res.status(404).json({ error: 'Topilmadi' });
  // view va edit huquqida ham izoh yozish mumkin (faqat o'qish emas)
  const task = db.tasks.find(t => t.id === req.params.id);
  const c = { id: nid(), task_id: req.params.id, author: req.user.name, author_id: req.user.id, text: req.body.text.trim(), created_at: Date.now() };
  if (!db.comments) db.comments = [];
  db.comments.push(c); saveDB(db); res.json(c);
});
app.delete('/api/comments/:id', auth, (req, res) => {
  const db = loadDB();
  const comment = (db.comments || []).find(c => c.id === req.params.id);
  if (!comment) return res.status(404).json({ error: 'Topilmadi' });
  // Faqat o'z izohini o'chira oladi
  if (String(comment.author_id) !== String(req.user.id)) {
    return res.status(403).json({ error: "Faqat o'z izohingizni o'chira olasiz" });
  }
  const idx = db.comments.indexOf(comment);
  db.comments.splice(idx, 1); saveDB(db); res.json({ ok: true });
});

// ── ARXIV ──
app.post('/api/tasks/:id/archive', auth, (req, res) => {
  const db = loadDB();
  const task = db.tasks.find(t => t.id === req.params.id);
  if (!task) return res.status(404).json({ error: 'Topilmadi' });
  // Topshiriq egasi yoki ulashilgan (edit/view) — ikkalasi ham arxivlay oladi
  // Lekin faqat o'z listiga tegishli taskni arxivlaydi
  const list = db.lists.find(l => l.id === task.list_id && l.user_id === req.user.id);
  if (!list) {
    // Ulashilgan topshiriqmi? — ulashilgan bo'lsa ham arxivlay oladi
    const perm = getTaskPermission(req.params.id, req.user.id, req.user.username, db);
    if (!perm) return res.status(403).json({ error: "Ruxsat yo'q" });
    // Ulashilgan topshiriqni shared_tasks dan o'chiramiz (faqat shu user uchun)
    // Asl task o'chirilmaydi — faqat ulashish bekor qilinadi
    db.shared_tasks = db.shared_tasks.filter(s =>
      !(s.task_id === task.id && s.recipient_email === req.user.username)
    );
    saveDB(db);
    return res.json({ ok: true, shared_removed: true });
  }
  const tree = buildTaskTree(task.id, db);
  // Files va comments ni task_data ichida saqlaymiz (restore uchun)
  function enrichTree(node) {
    // Fayllarni to'liq saqlash (url field bilan birga)
    node.files = (db.files || []).filter(f => f.ref_id === node.id).map(f => ({
      id: f.id, name: f.name, filename: f.filename,
      url: f.url || ('/uploads/' + f.filename),  // URL ni saqlaymiz
      type: f.mimetype, size: f.size,
      uploaded_by: f.uploaded_by
    }));
    node.comments = (db.comments || []).filter(c => c.task_id === node.id);
    (node.children || []).forEach(c => enrichTree(c));
    return node;
  }
  enrichTree(tree);
  db.archive.push({
    id: nid(), user_id: String(req.user.id),
    task_data: JSON.stringify(tree),
    from_list: list.title, list_id: list.id,
    parent_id: task.parent_id || null,
    archived_at: Date.now()
  });
  deleteTaskDeep(task.id, db); saveDB(db); res.json({ ok: true });
});
app.post('/api/lists/:lid/archive-completed', auth, (req, res) => {
  const db = loadDB(); const list = db.lists.find(l => l.id === req.params.lid && l.user_id === req.user.id);
  if (!list) return res.status(404).json({ error: 'Topilmadi' });
  const done = db.tasks.filter(t => t.list_id === req.params.lid && !t.parent_id && t.completed);
  if (!done.length) return res.status(400).json({ error: "Bajarilgan vazifalar yo'q" });
  done.forEach(task => {
    const tree = buildTaskTree(task.id, db);
    // Files va comments saqlash
    (function enrichNode(n){
      n.files = (db.files||[]).filter(f=>f.ref_id===n.id).map(f=>({
        id:f.id, name:f.name, filename:f.filename,
        url: f.url || ('/uploads/'+f.filename),
        type:f.mimetype, size:f.size, uploaded_by:f.uploaded_by
      }));
      n.comments = (db.comments||[]).filter(c=>c.task_id===n.id);
      (n.children||[]).forEach(enrichNode);
    })(tree);
    db.archive.push({ id: nid(), user_id: String(req.user.id), task_data: JSON.stringify(tree), from_list: list.title, list_id: list.id, parent_id: task.parent_id || null, archived_at: Date.now() });
    deleteTaskDeep(task.id, db);
  });
  saveDB(db); res.json({ ok: true, count: done.length });
});

app.get('/api/archive', auth, (req, res) => {
  const db = loadDB();
  const uid = String(req.user.id);
  // user_id yo'q (eski yozuv) — list egasini tekshirib ko'rsatamiz
  const myArchive = db.archive.filter(a => {
    if (String(a.user_id) === uid) return true;
    if (!a.user_id || a.user_id === 'undefined' || a.user_id === 'null') {
      // Eski yozuv: list egasimi?
      if (a.list_id) {
        const list = db.lists.find(l => l.id === a.list_id);
        if (list && String(list.user_id) === uid) { a.user_id = uid; return true; }
      }
      // from_list orqali topish
      const list = db.lists.find(l => l.title === a.from_list && String(l.user_id) === uid);
      if (list) { a.user_id = uid; return true; }
      return false;
    }
    return false;
  });
  // user_id tuzatilgan bo'lsa saqlab qo'yamiz
  const needsSave = myArchive.some(a => !a._savedUserId);
  if (needsSave) saveDB(db);

  res.json(myArchive.sort((a, b) => b.archived_at - a.archived_at).map(r => {
    let td;
    try { td = JSON.parse(r.task_data); } catch(e) { td = { text: r.from_list || 'Topshiriq', children: [] }; }
    return {
      id: String(r.id),  // ARXIV yozuvining IDsi (task.id EMAS) — har doim String
      taskText: td.text || '(nomsiz)',
      taskData: td,      // to'liq task (children bilan)
      fromList: r.from_list || '',
      listId: r.list_id || '',
      parentId: r.parent_id || null,
      archivedAt: r.archived_at || 0,
      childCount: (td.children||[]).length ? td.children.reduce(function cnt(s,c){return s+1+(c.children||[]).reduce(cnt,0);},0) : 0
    };
  }));
});

// ARXIVDAN QAYTARISH
app.post('/api/archive/:id/unarchive', auth, (req, res) => {
  const db = loadDB();
  const idx = db.archive.findIndex(a => String(a.id) === String(req.params.id));
  if (idx === -1) {
    console.log('[UNARCHIVE] topilmadi. Soralgan ID:', req.params.id, '| Mavjud IDlar:', db.archive.map(a=>a.id));
    return res.status(404).json({ error: 'Arxiv yozuvi topilmadi (ID: ' + req.params.id + ')' });
  }
  const row = db.archive[idx];
  const uid = String(req.user.id);
  // Egasi tekshirish — user_id yo'q eski yozuvlarga ham ruxsat
  if (row.user_id && row.user_id !== 'undefined' && row.user_id !== 'null' && String(row.user_id) !== uid) {
    // list orqali tekshirib ko'ramiz
    const list = db.lists.find(l => l.id === row.list_id);
    if (!list || String(list.user_id) !== uid) {
      return res.status(403).json({ error: "Bu arxiv yozuvi sizga tegishli emas" });
    }
  }
  let td;
  try { td = JSON.parse(row.task_data); } catch(e) { td = { text: row.from_list || 'Topshiriq', children: [] }; }

  // Ro'yxatni topamiz
  let list = db.lists.find(l => l.id === row.list_id && l.user_id === req.user.id)
          || db.lists.find(l => l.user_id === req.user.id && l.title === row.from_list);
  if (!list) {
    list = { id: nid(), user_id: req.user.id, title: row.from_list || 'Arxivdan', created_at: Date.now() };
    db.lists.push(list);
  }

  // Original parent hali mavjudmi? — mavjud bo'lsa, shu parentga qo'shamiz (ierarxiyani saqlash)
  let rootParentId = null;
  if (row.parent_id) {
    const parentExists = db.tasks.find(t => t.id === row.parent_id && t.list_id === list.id);
    if (parentExists) {
      rootParentId = row.parent_id;
      console.log('[UNARCHIVE] parent topildi, ierarxiyaga qaytariladi:', row.parent_id);
    } else {
      console.log('[UNARCHIVE] parent topilmadi, root sifatida qaytariladi');
    }
  }

  function restoreTask(node, parentId) {
    const newId = nid();
    db.tasks.push({
      id: newId, list_id: list.id, parent_id: parentId || null,
      user_id: req.user.id, text: node.text || '',
      completed: node.completed || false,
      priority: node.priority || 'medium',
      status: node.status || 'todo',
      deadline: node.deadline || null,
      created_at: node.created_at || Date.now()
    });
    // Fayllarni qaytarish — R2 va local URL larni to'g'ri saqlash
    if (node.files && node.files.length) {
      node.files.forEach(f => {
        const fileUrl = f.url || '';
        const isR2 = fileUrl.startsWith('http');
        // filename: R2 da to'liq URL dan oxirgi qism, local da /uploads/ dan keyin
        const filename = f.filename ||
          (isR2 ? fileUrl.split('/').pop() : fileUrl.replace('/uploads/', ''));
        db.files.push({
          id: nid(),
          ref_id: newId,
          filename: filename || '',
          url: isR2 ? fileUrl : null,  // R2 URL ni saqlaymiz
          name: f.name || filename || '',
          mimetype: f.type || f.mimetype || 'application/octet-stream',
          size: f.size || 0,
          uploaded_by: f.uploaded_by || '',
          uploaded_at: Date.now()
        });
      });
    }
    // Izohlarni qaytarish
    if (node.comments && node.comments.length) {
      node.comments.forEach(c => {
        db.comments.push({
          id: nid(), task_id: newId,
          user_id: c.user_id || req.user.id,
          author: c.author || req.user.name || '',
          text: c.text || '',
          created_at: c.created_at || Date.now()
        });
      });
    }
    (node.children || []).forEach(c => restoreTask(c, newId));
  }
  restoreTask(td, rootParentId);
  db.archive.splice(idx, 1);
  saveDB(db);
  res.json({ ok: true, listId: list.id });
});

// ARXIVDAN O'CHIRISH
app.delete('/api/archive/:id', auth, (req, res) => {
  const db = loadDB();
  const idx = db.archive.findIndex(a => String(a.id) === String(req.params.id));
  if (idx === -1) {
    console.log('[DELETE ARCHIVE] topilmadi. Soralgan ID:', req.params.id, '| Mavjud IDlar:', db.archive.map(a=>a.id));
    return res.status(404).json({ error: 'Topilmadi (ID: ' + req.params.id + ')' });
  }
  const row = db.archive[idx];
  const uid = String(req.user.id);
  if (row.user_id && row.user_id !== 'undefined' && row.user_id !== 'null' && String(row.user_id) !== uid) {
    const list = db.lists.find(l => l.id === row.list_id);
    if (!list || String(list.user_id) !== uid) {
      return res.status(403).json({ error: "Bu arxiv yozuvi sizga tegishli emas" });
    }
  }
  db.archive.splice(idx, 1);
  saveDB(db);
  res.json({ ok: true });
});

// ── FILES ──
app.post('/api/files', auth, upload.array('files'), async (req, res) => {
  try {
  const { refId } = req.body; const db = loadDB();
  if (refId) {
    const perm = getTaskPermission(refId, req.user.id, req.user.username, db);
    if (!perm) return res.status(404).json({ error: 'Topilmadi' });
    if (perm === 'view') return res.status(403).json({ error: "Faqat ko'rish huquqi bor, fayl yuklay olmaysiz" });
  }
  const saved = [];
  for (const f of (req.files || [])) {
    const fileId = nid();
    let fileUrl, filename;
    if (USE_R2) {
      // R2 ga yuklash
      try {
        const buffer = fs.readFileSync(f.path);
        const r2name = fileId + '_' + f.originalname.replace(/[^\w.\-]/g,'_');
        fileUrl = await r2Upload(r2name, buffer, f.mimetype);
        filename = r2name;
        // Local faylni o'chirish
        try { fs.unlinkSync(f.path); } catch {}
      } catch(e) {
        console.error('R2 upload error details:', e.message, '| USE_R2:', USE_R2, '| endpoint:', R2_ENDPOINT, '| bucket:', R2_BUCKET);
        fileUrl = '/uploads/' + f.filename;
        filename = f.filename;
      }
    } else {
      fileUrl = '/uploads/' + f.filename;
      filename = f.filename;
    }
    const file = { id: fileId, ref_id: refId, name: f.originalname, filename, url: fileUrl, mimetype: f.mimetype, size: f.size, uploaded_by: req.user.name, uploaded_at: Date.now() };
    db.files.push(file);
    saved.push({ id: file.id, name: file.name, url: fileUrl, type: file.mimetype, size: file.size });
  }
  try { saveDB(db); } catch(e) { console.error('saveDB error:', e.message); }
  res.json(saved);
  } catch(globalErr) {
    console.error('Upload global error:', globalErr.message, globalErr.stack);
    res.status(500).json({ error: 'Yuklash xatosi: ' + globalErr.message });
  }
});
app.delete('/api/files/:id', auth, (req, res) => {
  const db = loadDB();
  const fileIdx = (db.files || []).findIndex(f => f.id === req.params.id);
  if (fileIdx === -1) return res.status(404).json({ error: 'Topilmadi' });
  const file = db.files[fileIdx];
  // Topshiriq huquqini tekshirish
  if (file.ref_id) {
    const perm = getTaskPermission(file.ref_id, req.user.id, req.user.username, db);
    if (!perm) return res.status(403).json({ error: "Ruxsat yo'q" });
    if (perm === 'view') return res.status(403).json({ error: "Faqat ko'rish huquqi bor, fayl o'chira olmaysiz" });
  }
  // Faylni o'chirish — R2 yoki local
  if (USE_R2 && file.url && file.url.startsWith('http')) {
    r2Delete(file.filename).catch(e => console.error('R2 delete error:', e.message));
  } else {
    const fp = path.join(UPLOADS_DIR, file.filename);
    if (fs.existsSync(fp)) try { fs.unlinkSync(fp); } catch {}
  }
  db.files.splice(fileIdx, 1); saveDB(db); res.json({ ok: true });
});

// ── FAYL PROXY — barcha fayl turlari uchun (R2 public access shart emas) ──
app.get('/api/files/:id/proxy', auth, async (req, res) => {
  const db = loadDB();
  const file = (db.files || []).find(f => f.id === req.params.id);
  if (!file) return res.status(404).json({ error: 'Topilmadi' });
  if (file.ref_id) {
    const perm = getTaskPermission(file.ref_id, req.user.id, req.user.username, db);
    if (!perm) return res.status(403).json({ error: "Ruxsat yo'q" });
  }
  try {
    // R2 URL ni aniqlash — ikki usul bilan urinib ko'ramiz
    let r2Url = null;
    if (USE_R2) {
      if (file.url && file.url.startsWith('http') && !file.url.includes('undefined') && !file.url.includes('null')) {
        r2Url = file.url;
      }
      // url ishonchsiz yoki yo'q bo'lsa — filename dan reconstruct
      if (!r2Url && file.filename) {
        const endpoint = R2_ENDPOINT.replace(/\/+$/, '');
        const safe = file.filename.replace(/[^a-zA-Z0-9._-]/g, '_');
        r2Url = `${endpoint}/${R2_BUCKET}/${safe}`;
      }
    }

    if (r2Url) {
      console.log('[PROXY] fetching:', r2Url.substring(0, 80));
      const resp = await fetch(r2Url);
      // Agar stored url ishlamasa, filename dan reconstruct qilib qayta urinib ko'ramiz
      if (!resp.ok && file.url && file.url !== r2Url && file.filename) {
        const endpoint = R2_ENDPOINT.replace(/\/+$/, '');
        const safe = file.filename.replace(/[^a-zA-Z0-9._-]/g, '_');
        const r2Url2 = `${endpoint}/${R2_BUCKET}/${safe}`;
        console.log('[PROXY] retry with reconstructed URL:', r2Url2.substring(0, 80));
        const resp2 = await fetch(r2Url2);
        if (!resp2.ok) {
          console.error('[PROXY] both URLs failed:', resp.status, resp2.status);
          return res.status(502).send('R2 xatosi: ' + resp2.status);
        }
        const ct2 = file.mimetype || resp2.headers.get('content-type') || 'application/octet-stream';
        res.setHeader('Content-Type', ct2);
        res.setHeader('Content-Disposition', 'inline; filename="' + encodeURIComponent(file.name || 'file') + '"');
        res.setHeader('Cache-Control', 'private, max-age=3600');
        return res.send(Buffer.from(await resp2.arrayBuffer()));
      }
      if (!resp.ok) {
        console.error('[PROXY] R2 xatosi:', resp.status, r2Url);
        return res.status(502).send('R2 xatosi: ' + resp.status);
      }
      const ct = file.mimetype || resp.headers.get('content-type') || 'application/octet-stream';
      res.setHeader('Content-Type', ct);
      res.setHeader('Content-Disposition', 'inline; filename="' + encodeURIComponent(file.name || 'file') + '"');
      res.setHeader('Cache-Control', 'private, max-age=3600');
      const buf = Buffer.from(await resp.arrayBuffer());
      res.send(buf);
    } else {
      // Local fayl
      const fname = file.filename || path.basename((file.url || '').replace(/^\/uploads\//, ''));
      const fp = path.join(UPLOADS_DIR, fname);
      if (!fs.existsSync(fp)) return res.status(404).send('Fayl topilmadi: ' + fname);
      res.setHeader('Content-Disposition', 'inline; filename="' + encodeURIComponent(file.name || 'file') + '"');
      res.setHeader('Cache-Control', 'private, max-age=3600');
      res.sendFile(fp);
    }
  } catch(e) {
    console.error('[PROXY] catch xatosi:', e.message);
    res.status(500).json({ error: 'Proxy xatosi: ' + e.message });
  }
});

// ── FAYL MATNINI O'QISH (TXT, CSV, JSON) — R2 CORS muammosini hal qiladi ──
app.get('/api/files/:id/content', auth, async (req, res) => {
  const db = loadDB();
  const file = (db.files || []).find(f => f.id === req.params.id);
  if (!file) return res.status(404).json({ error: 'Topilmadi' });
  // Huquq tekshirish
  if (file.ref_id) {
    const perm = getTaskPermission(file.ref_id, req.user.id, req.user.username, db);
    if (!perm) return res.status(403).json({ error: "Ruxsat yo'q" });
  }
  try {
    let text;
    if (USE_R2) {
      let r2Url = null;
      if (file.url && file.url.startsWith('http')) {
        r2Url = file.url;
      } else if (file.filename) {
        const endpoint = R2_ENDPOINT.replace(/\/+$/, '');
        const safe = file.filename.replace(/[^a-zA-Z0-9._-]/g, '_');
        r2Url = `${endpoint}/${R2_BUCKET}/${safe}`;
      }
      if (r2Url) {
        const resp = await fetch(r2Url);
        if (!resp.ok) return res.status(502).json({ error: 'R2 xatosi: ' + resp.status });
        text = await resp.text();
      }
    }
    if (text === undefined) {
      // Local fayldan o'qish
      const fname = file.filename || path.basename((file.url || '').replace(/^\/uploads\//, ''));
      const fp = path.join(UPLOADS_DIR, fname);
      if (!fs.existsSync(fp)) return res.status(404).json({ error: 'Fayl diskda topilmadi' });
      text = fs.readFileSync(fp, 'utf8');
    }
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.send(text);
  } catch(e) {
    res.status(500).json({ error: 'Faylni o\'qishda xatolik: ' + e.message });
  }
});

// ── SHARING ──
app.post('/api/tasks/:tid/share', auth, (req, res) => {
  const db = loadDB(); const task = db.tasks.find(t => t.id === req.params.tid);
  if (!task) return res.status(404).json({ error: 'Topilmadi' });
  const list = db.lists.find(l => l.id === task.list_id && l.user_id === req.user.id);
  if (!list) return res.status(403).json({ error: "Ruxsat yo'q" });
  const em = (req.body.email || '').toLowerCase().trim();
  if (em === req.user.username) return res.status(400).json({ error: "O'zingizga ulasha olmaysiz" });
  if (db.shared_tasks.find(s => s.task_id === task.id && s.recipient_email === em)) return res.status(400).json({ error: 'Allaqachon ulashilgan' });
  const s = { id: nid(), task_id: task.id, owner_id: req.user.id, recipient_email: em, permission: req.body.permission, status: 'pending', task_data: JSON.stringify(buildTaskTree(task.id, db)), created_at: Date.now() };
  db.shared_tasks.push(s); saveDB(db); res.json({ id: s.id, email: em, permission: req.body.permission });
});
app.delete('/api/tasks/:tid/share/:email', auth, (req, res) => {
  const db = loadDB(); const task = db.tasks.find(t => t.id === req.params.tid);
  if (!task) return res.status(404).json({ error: 'Topilmadi' });
  db.shared_tasks = db.shared_tasks.filter(s => !(s.task_id === task.id && s.recipient_email === req.params.email.toLowerCase()));
  saveDB(db); res.json({ ok: true });
});
app.get('/api/shared-to-me', auth, (req, res) => {
  const db = loadDB();
  res.json(db.shared_tasks.filter(s => s.recipient_email === req.user.username).sort((a, b) => b.created_at - a.created_at).map(r => {
    const owner = db.users.find(u => u.id === r.owner_id);
    // Topshiriqning hozirgi holatini ham yuboramiz (agar hali mavjud bo'lsa)
    let taskData;
    try { taskData = JSON.parse(r.task_data); } catch { taskData = {}; }
    // Hozirgi task ma'lumotlarini yangilash
    const liveTask = db.tasks.find(t => t.id === taskData.id);
    if (liveTask) {
      taskData = { ...taskData, text: liveTask.text, completed: liveTask.completed, priority: liveTask.priority, status: liveTask.status };
    }
    return { id: r.id, taskData, ownerName: owner?.name || '', ownerEmail: owner?.username || '', permission: r.permission, status: r.status, taskId: taskData.id };
  }));
});
app.put('/api/shared/:id/accept', auth, (req, res) => {
  const db = loadDB();
  const s = db.shared_tasks.find(s => s.id === req.params.id && s.recipient_email === req.user.username);
  if (!s) return res.status(404).json({ error: 'Topilmadi' });
  // Faqat statusni o'zgartirish — nusxa emas!
  // Asl topshiriqqa to'g'ridan-to'g'ri kirish beriladi
  s.status = 'accepted';
  // "Ulashilgan topshiriqlar" ro'yxatini yaratish (agar yo'q bo'lsa)
  let sharedList = db.lists.find(l => l.user_id === req.user.id && l.is_shared_inbox);
  if (!sharedList) {
    sharedList = { id: nid(), user_id: req.user.id, title: 'Ulashilgan topshiriqlar', is_shared_inbox: true, created_at: Date.now() };
    db.lists.push(sharedList);
  }
  // Eski nusxalarni o'chirish (agar avval copy qilingan bo'lsa)
  const oldCopied = db.tasks.filter(t => t.shared_from === s.id);
  oldCopied.forEach(t => deleteTaskDeep(t.id, db));
  saveDB(db);
  res.json({ ok: true, listId: sharedList.id });
});
app.delete('/api/shared/:id', auth, (req, res) => {
  const db = loadDB(); db.shared_tasks = db.shared_tasks.filter(s => !(s.id === req.params.id && s.recipient_email === req.user.username));
  saveDB(db); res.json({ ok: true });
});

// ── SHARED TASK OPERATIONS ──
// Ulashilgan topshiriqqa quyi topshiriq qo'shish (tahrirlash huquqi bo'lsa)
app.post('/api/shared-task/:sid/add-child', auth, (req, res) => {
  const db = loadDB();
  const share = db.shared_tasks.find(s => s.id === req.params.sid && s.recipient_email === req.user.username);
  if (!share) return res.status(404).json({ error: 'Topilmadi' });
  if (share.permission !== 'edit') return res.status(403).json({ error: "Tahrirlash huquqi yo'q" });
  const parentTaskId = req.body.parentTaskId;
  const parentTask = db.tasks.find(t => t.id === parentTaskId);
  if (!parentTask) return res.status(404).json({ error: 'Asosiy topshiriq topilmadi' });
  // Yangi quyi topshiriq yaratamiz
  const newTask = {
    id: nid(), list_id: parentTask.list_id, parent_id: parentTaskId,
    user_id: parentTask.user_id, // Egasining nomidan
    text: req.body.text.trim(), completed: false,
    priority: 'medium', status: 'todo', deadline: null, created_at: Date.now()
  };
  db.tasks.push(newTask);
  // Shared task_data ni yangilaymiz
  try {
    const td = JSON.parse(share.task_data);
    if (!td.children) td.children = [];
    td.children.push({ id: newTask.id, text: newTask.text, completed: false, children: [] });
    share.task_data = JSON.stringify(td);
  } catch {}
  saveDB(db);
  res.json({ ok: true, task: newTask });
});

// ── SHARED TASK OPERATIONS ──
// Ulashilgan topshiriqqa quyi topshiriq qo'shish

app.get('/api/admin/backup', auth, (req, res) => {
  const db = loadDB();
  // Faqat superadmin emailga ruxsat
  const SUPERADMIN_EMAIL = 'ausembayev@gmail.com';
  if (req.user.username !== SUPERADMIN_EMAIL) {
    return res.status(403).json({ error: "Ruxsat etilmagan" });
  }
  // 2. So'rov brauzerdan kelganmi tekshirish (tashqi skriptlar blok)
  const origin = req.headers['origin'];
  const referer = req.headers['referer'];
  const host = req.headers['host'];
  const isFromBrowser = (referer && referer.includes(host)) || !origin;
  if (origin && !origin.includes(host)) {
    return res.status(403).json({ error: "Ruxsat etilmagan so'rov" });
  }
  // 3. Backup tokenini tekshirish — har safar yangi token talab qilinadi
  const backupToken = req.query.bt;
  const validToken = (db.sessions || {})[req.headers['x-token']];
  if (!validToken) return res.status(401).json({ error: "Login kerak" });
  // 4. Foydalanuvchi ma'lumotlarini tozalab yuborish — parollar olib tashlanadi
  const date = new Date().toISOString().slice(0, 10);
  res.setHeader('Content-Disposition', 'attachment; filename="checkbox-backup-' + date + '.json"');
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  const safeUsers = db.users.map(u => ({
    ...u,
    password: undefined,  // parollar backup da bo'lmaydi
    google_id: undefined  // Google ID ham olib tashlanadi
  }));
  const backup = {
    ...db,
    users: safeUsers,
    sessions: {}  // sessionlar olib tashlanadi
  };
  res.json(backup);
});

// ── BACKUP ENDPOINT — admin data.json yuklab oladi ──

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ── STARTUP: eski arxiv yozuvlarini tuzatish ──
const startupDB = loadDB();
let fixedCount = 0;
startupDB.archive.forEach(a => {
  if (!a.user_id || a.user_id === 'undefined' || a.user_id === 'null') {
    const list = startupDB.lists.find(l => l.title === a.from_list);
    if (list) { a.user_id = String(list.user_id); fixedCount++; }
    else if (startupDB.users.length > 0) { a.user_id = String(startupDB.users[0].id); fixedCount++; }
  }
});
if (fixedCount > 0) {
  saveDB(startupDB);
  console.log(`✅ ${fixedCount} ta eski arxiv yozuvi avtomatik tuzatildi`);
}

async function migrateLocalFilesToR2() {
  if (!USE_R2) return;
  const db = loadDB();
  const activeTaskIds = new Set((db.tasks || []).map(t => t.id));
  let migrated = 0, freed = 0, orphansRemoved = 0;
  let dbChanged = false;

  // 1. Yetim fayllarni (o'chirilgan task ga tegishli) DB dan va R2/diskdan o'chirish
  const orphanFiles = (db.files || []).filter(f => f.ref_id && !activeTaskIds.has(f.ref_id));
  for (const f of orphanFiles) {
    if (USE_R2 && f.url && f.url.startsWith('http')) {
      r2Delete(f.filename).catch(() => {});
    } else if (f.filename) {
      const fp = path.join(UPLOADS_DIR, f.filename);
      try { if (fs.existsSync(fp)) fs.unlinkSync(fp); } catch {}
    }
    orphansRemoved++;
  }
  if (orphansRemoved > 0) {
    db.files = (db.files || []).filter(f => !f.ref_id || activeTaskIds.has(f.ref_id));
    db.comments = (db.comments || []).filter(c => activeTaskIds.has(c.task_id));
    dbChanged = true;
    console.log(`🗑️  Yetim fayllar o'chirildi: ${orphansRemoved} ta`);
  }

  // 2. Local fayllarni R2 ga ko'chirish
  for (const file of (db.files || [])) {
    if (!file.url || !file.url.startsWith('/uploads/')) continue;
    const localPath = path.join(UPLOADS_DIR, file.filename || path.basename(file.url));
    if (!fs.existsSync(localPath)) continue;
    try {
      const buffer = fs.readFileSync(localPath);
      const r2name = file.id + '_' + (file.filename || path.basename(file.url));
      const newUrl = await r2Upload(r2name, buffer, file.mimetype || 'application/octet-stream');
      file.url = newUrl;
      file.filename = r2name;
      freed += buffer.length;
      try { fs.unlinkSync(localPath); } catch {}
      migrated++;
      dbChanged = true;
    } catch(e) {
      console.error('Migrate error:', file.filename, e.message);
    }
  }
  if (migrated > 0) console.log(`✅ R2 ga ko'chirildi: ${migrated} ta fayl (${(freed/1024/1024).toFixed(1)} MB)`);

  // 3. Local da yetim fayllarni tozalash
  try {
    const dbFilenames = new Set((db.files || []).map(f => f.filename).filter(Boolean));
    const localFiles = fs.readdirSync(UPLOADS_DIR).filter(f => f !== '.gitkeep');
    let cleaned = 0;
    for (const fname of localFiles) {
      if (!dbFilenames.has(fname)) {
        try { fs.unlinkSync(path.join(UPLOADS_DIR, fname)); cleaned++; } catch {}
      }
    }
    if (cleaned > 0) console.log(`🗑️  Local yetim fayllar: ${cleaned} ta o'chirildi`);
  } catch {}

  if (dbChanged) saveDB(db);
}

app.listen(PORT, async () => {
  console.log('\n╔══════════════════════════════════════╗');
  console.log('║  ✅  http://localhost:' + PORT + '           ║');
  console.log('╚══════════════════════════════════════╝\n');
  if (!GOOGLE_CLIENT_ID) console.log('ℹ️  Google login sozlanmagan\n');
  // Local fayllarni R2 ga ko'chirish (Volume bo'shatish)
  migrateLocalFilesToR2().catch(e => console.error('Migration error:', e.message));
});
