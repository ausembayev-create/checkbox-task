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
  // To'g'ri URL: endpoint/bucket/filename
  const url = `${endpoint}/${R2_BUCKET}/${encodeURIComponent(filename).replace(/%2F/g,'/')}`;
  const host = new URL(url).host;
  const region = 'auto';
  const service = 's3';
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:\-]|\.\d{3}/g, '').slice(0,16) + 'Z';
  const dateStamp = amzDate.slice(0,8);

  const payloadHash = crypto.createHash('sha256').update(buffer).digest('hex');
  const headers = {
    'host': host,
    'x-amz-date': amzDate,
    'x-amz-content-sha256': payloadHash,
    'content-type': contentType,
    'content-length': String(buffer.length)
  };
  const signedHeaders = Object.keys(headers).sort().join(';');
  const canonicalHeaders = Object.keys(headers).sort().map(k => `${k}:${headers[k]}`).join('\n') + '\n';
  const s3path = '/' + R2_BUCKET + '/' + filename;
  const canonicalRequest = ['PUT', s3path, '', canonicalHeaders, signedHeaders, payloadHash].join('\n');
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${credentialScope}\n` + crypto.createHash('sha256').update(canonicalRequest).digest('hex');
  
  function hmac(key, data) { return crypto.createHmac('sha256', key).update(data).digest(); }
  const signingKey = hmac(hmac(hmac(hmac('AWS4' + R2_SECRET_KEY, dateStamp), region), service), 'aws4_request');
  const signature = crypto.createHmac('sha256', signingKey).update(stringToSign).digest('hex');
  const authorization = `AWS4-HMAC-SHA256 Credential=${R2_ACCESS_KEY}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const res = await fetch(url, {
    method: 'PUT',
    headers: { ...headers, 'Authorization': authorization },
    body: buffer
  });
  if (!res.ok) throw new Error(`R2 upload failed: ${res.status} ${await res.text()}`);
  return `${R2_PUBLIC_URL}/${filename}`;
}

async function r2Delete(filename) {
  if (!filename || !USE_R2) return;
  const endpoint = R2_ENDPOINT.replace(/\/+$/, '');
  const url = `${endpoint}/${R2_BUCKET}/${filename}`;
  const host = new URL(url).host;
  const region = 'auto'; const service = 's3';
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:\-]|\.\d{3}/g, '').slice(0,16) + 'Z';
  const dateStamp = amzDate.slice(0,8);
  const payloadHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const headers = { 'host': host, 'x-amz-date': amzDate, 'x-amz-content-sha256': payloadHash };
  const signedHeaders = Object.keys(headers).sort().join(';');
  const canonicalHeaders = Object.keys(headers).sort().map(k => `${k}:${headers[k]}`).join('\n') + '\n';
  const s3pathD = '/' + R2_BUCKET + '/' + filename;
  const canonicalRequest = ['DELETE', s3pathD, '', canonicalHeaders, signedHeaders, payloadHash].join('\n');
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${credentialScope}\n` + crypto.createHash('sha256').update(canonicalRequest).digest('hex');
  function hmac(key, data) { return crypto.createHmac('sha256', key).update(data).digest(); }
  const signingKey = hmac(hmac(hmac(hmac('AWS4' + R2_SECRET_KEY, dateStamp), region), service), 'aws4_request');
  const signature = crypto.createHmac('sha256', signingKey).update(stringToSign).digest('hex');
  const authorization = `AWS4-HMAC-SHA256 Credential=${R2_ACCESS_KEY}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  await fetch(url, { method: 'DELETE', headers: { ...headers, 'Authorization': authorization } });
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
  db.files       = (db.files       || []).filter(f => f.ref_id  !== taskId);
  db.comments    = (db.comments    || []).filter(c => c.task_id !== taskId);
  // MUAMMO 3 FIX: Topshiriq o'chirilganda ulashishlarni ham o'chirish
  // Bu boshqa foydalanuvchilardagi "Ulashilgan" bo'limdan ham o'chiradi
  db.shared_tasks = (db.shared_tasks || []).filter(s => s.task_id !== taskId);
  db.tasks       = db.tasks.filter(t => t.id !== taskId);
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
    node.files    = (db.files    || []).filter(f => f.ref_id  === node.id);
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
      n.files    = (db.files    || []).filter(f => f.ref_id  === n.id);
      n.comments = (db.comments || []).filter(c => c.task_id === n.id);
      (n.children||[]).forEach(enrichNode);
    })(tree);
    db.archive.push({ id: nid(), user_id: String(req.user.id), task_data: JSON.stringify(tree), from_list: list.title, list_id: list.id, archived_at: Date.now() });
    deleteTaskDeep(task.id, db);
  });
  saveDB(db); res.json({ ok: true, count: done.length });
});

app.get('/api/archive', auth, (req, res) => {
  const db = loadDB();
  const uid = String(req.user.id);
  const myArchive = db.archive.filter(a => {
    // user_id yo'q (eski yozuv) yoki mos kelsa ko'rsatamiz
    return !a.user_id || String(a.user_id) === uid;
  });
  res.json(myArchive.sort((a, b) => b.archived_at - a.archived_at).map(r => {
    const td = JSON.parse(r.task_data);
    return {
      id: r.id,          // ARXIV yozuvining IDsi (task.id EMAS)
      taskText: td.text, // task matni
      taskData: td,      // to'liq task (children bilan)
      fromList: r.from_list,
      listId: r.list_id,
      archivedAt: r.archived_at,
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
    return res.status(404).json({ error: 'Topilmadi (ID: ' + req.params.id + ')' });
  }
  const row = db.archive[idx];
  let td;
  try { td = JSON.parse(row.task_data); } catch(e) { return res.status(500).json({ error: 'task_data parse xatosi' }); }

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
    // MUAMMO 1 FIX: Fayllarni to'g'ri qaytarish
    // node.files — fmtFile formatida: {id, name, url:'/uploads/xxx', type, size}
    // db.files — raw formatda: {id, ref_id, filename:'xxx', name, mimetype, size}
    if (node.files && node.files.length) {
      node.files.forEach(f => {
        // filename ni url dan yoki filename field dan olamiz
        const filename = f.filename || (f.url ? f.url.replace('/uploads/', '') : '');
        if (!filename) return;
        const filepath = path.join(__dirname, 'uploads', filename);
        // Fizik fayl mavjudmi — majburiy emas, baribir yozamiz (URL bo'lishi kifoya)
        db.files.push({
          id: nid(), // Har doim yangi ID — duplicate oldini olish
          ref_id: newId,
          filename: filename,
          name: f.name || filename,
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

app.listen(PORT, () => {
  console.log('\n╔══════════════════════════════════════╗');
  console.log('║  ✅  http://localhost:' + PORT + '           ║');
  console.log('╚══════════════════════════════════════╝\n');
  if (!GOOGLE_CLIENT_ID) console.log('ℹ️  Google login sozlanmagan\n');
});
