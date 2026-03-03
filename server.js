const express  = require('express');
const cors     = require('cors');
const session  = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const multer   = require('multer');
const path     = require('path');
const fs       = require('fs');

const app  = express();
const PORT = process.env.PORT || 3001;
const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID     || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const DATA_FILE   = process.env.DATA_PATH || path.join(__dirname, 'data.json');
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
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOADS_DIR),
    filename:    (req, file, cb) => cb(null, Date.now() + '_' + file.originalname.replace(/[^\w.\-]/g, '_').slice(0, 80))
  }),
  limits: { fileSize: 500 * 1024 * 1024 }
});

app.use(express.json({ limit: '10mb' }));
app.use(cors({ origin: true, credentials: true }));
app.use(session({ secret: 'cbsecret2024', resave: false, saveUninitialized: false, cookie: { maxAge: 7*24*60*60*1000 } }));
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
const fmtFile = f => ({ id: f.id, name: f.name, url: '/uploads/' + f.filename, type: f.mimetype, size: f.size });

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
  db.files    = (db.files    || []).filter(f => f.ref_id  !== taskId);
  db.comments = (db.comments || []).filter(c => c.task_id !== taskId);
  db.tasks    = db.tasks.filter(t => t.id !== taskId);
}

// ── AUTH ──
app.post('/api/register', (req, res) => {
  const { username, password, name } = req.body || {};
  if (!username?.trim() || !password || !name?.trim()) return res.status(400).json({ error: 'Ism, username va parol kerak' });
  const db = loadDB(); const uname = username.toLowerCase().trim();
  if (db.users.find(u => u.username === uname)) return res.status(400).json({ error: 'Bu username band' });
  const user = { id: nid(), username: uname, password, name: name.trim(), surname: '', patronymic: '', google_id: null, avatar: '', bg: '', created_at: Date.now() };
  db.users.push(user); saveDB(db);
  res.json({ token: mkToken(user), user: safeUser(user) });
});
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {}; const db = loadDB();
  const user = db.users.find(u => u.username === (username || '').toLowerCase().trim() && u.password === password);
  if (!user) return res.status(401).json({ error: "Username yoki parol noto'g'ri" });
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
  res.json(db.lists.filter(l => l.user_id === req.user.id).sort((a, b) => a.created_at - b.created_at).map(l => ({ ...l, tasks: listTasks(l.id, db) })));
});
app.post('/api/lists', auth, (req, res) => {
  if (!req.body.title?.trim()) return res.status(400).json({ error: 'Nom kerak' });
  const db = loadDB();
  const list = { id: nid(), user_id: req.user.id, title: req.body.title.trim(), created_at: Date.now() };
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
  const db = loadDB(); const parent = db.tasks.find(t => t.id === req.params.pid);
  if (!parent) return res.status(404).json({ error: 'Topilmadi' });
  const list = db.lists.find(l => l.id === parent.list_id && l.user_id === req.user.id);
  if (!list) return res.status(403).json({ error: "Ruxsat yo'q" });
  const task = { id: nid(), list_id: parent.list_id, parent_id: req.params.pid, user_id: req.user.id, text: req.body.text.trim(), completed: false, priority: parent.priority || 'medium', status: 'todo', deadline: req.body.deadline || null, created_at: Date.now() };
  db.tasks.push(task); saveDB(db); res.json(buildTaskTree(task.id, db));
});
app.put('/api/tasks/:id', auth, (req, res) => {
  const db = loadDB(); const task = db.tasks.find(t => t.id === req.params.id);
  if (!task) return res.status(404).json({ error: 'Topilmadi' });
  const list = db.lists.find(l => l.id === task.list_id && l.user_id === req.user.id);
  if (!list) return res.status(403).json({ error: "Ruxsat yo'q" });
  const b = req.body;
  if (b.text      !== undefined) task.text      = b.text;
  if (b.completed !== undefined) task.completed = !!b.completed;
  if (b.priority  !== undefined) task.priority  = b.priority;
  if (b.status    !== undefined) task.status    = b.status;
  if (b.deadline  !== undefined) task.deadline  = b.deadline;
  saveDB(db); res.json({ ok: true });
});
app.delete('/api/tasks/:id', auth, (req, res) => {
  const db = loadDB(); const task = db.tasks.find(t => t.id === req.params.id);
  if (!task) return res.status(404).json({ error: 'Topilmadi' });
  const list = db.lists.find(l => l.id === task.list_id && l.user_id === req.user.id);
  if (!list) return res.status(403).json({ error: "Ruxsat yo'q" });
  deleteTaskDeep(req.params.id, db); saveDB(db); res.json({ ok: true });
});

// ── COMMENTS ──
app.get('/api/tasks/:id/comments', auth, (req, res) => {
  const db = loadDB();
  res.json((db.comments || []).filter(c => c.task_id === req.params.id).sort((a, b) => a.created_at - b.created_at));
});
app.post('/api/tasks/:id/comments', auth, (req, res) => {
  const db = loadDB();
  const task = db.tasks.find(t => t.id === req.params.id); if (!task) return res.status(404).json({ error: 'Topilmadi' });
  const c = { id: nid(), task_id: req.params.id, author: req.user.name, author_id: req.user.id, text: req.body.text.trim(), created_at: Date.now() };
  if (!db.comments) db.comments = [];
  db.comments.push(c); saveDB(db); res.json(c);
});
app.delete('/api/comments/:id', auth, (req, res) => {
  const db = loadDB();
  const idx = (db.comments || []).findIndex(c => c.id === req.params.id && c.author_id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'Topilmadi' });
  db.comments.splice(idx, 1); saveDB(db); res.json({ ok: true });
});

// ── ARXIV ──
app.post('/api/tasks/:id/archive', auth, (req, res) => {
  const db = loadDB(); const task = db.tasks.find(t => t.id === req.params.id);
  if (!task) return res.status(404).json({ error: 'Topilmadi' });
  const list = db.lists.find(l => l.id === task.list_id && l.user_id === req.user.id);
  if (!list) return res.status(403).json({ error: "Ruxsat yo'q" });
  const tree = buildTaskTree(task.id, db);
  // parent_id ni ham saqlaymiz — qaytarilganda original joyiga tiklash uchun
  db.archive.push({
    id: nid(), user_id: String(req.user.id),
    task_data: JSON.stringify(tree),
    from_list: list.title, list_id: list.id,
    parent_id: task.parent_id || null,  // original parent
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
      completed: false, priority: node.priority || 'medium',
      status: 'todo', deadline: node.deadline || null, created_at: Date.now()
    });
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
app.post('/api/files', auth, upload.array('files'), (req, res) => {
  const { refId } = req.body; const db = loadDB();
  const saved = (req.files || []).map(f => {
    const file = { id: nid(), ref_id: refId, name: f.originalname, filename: f.filename, mimetype: f.mimetype, size: f.size, uploaded_by: req.user.name, uploaded_at: Date.now() };
    db.files.push(file); return fmtFile(file);
  });
  saveDB(db); res.json(saved);
});
app.delete('/api/files/:id', auth, (req, res) => {
  const db = loadDB(); const idx = (db.files || []).findIndex(f => f.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Topilmadi' });
  const fp = path.join(UPLOADS_DIR, db.files[idx].filename);
  if (fs.existsSync(fp)) try { fs.unlinkSync(fp); } catch {}
  db.files.splice(idx, 1); saveDB(db); res.json({ ok: true });
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
    return { id: r.id, taskData: JSON.parse(r.task_data), ownerName: owner?.name || '', permission: r.permission, status: r.status };
  }));
});
app.put('/api/shared/:id/accept', auth, (req, res) => {
  const db = loadDB(); const s = db.shared_tasks.find(s => s.id === req.params.id && s.recipient_email === req.user.username);
  if (s) { s.status = 'accepted'; saveDB(db); } res.json({ ok: true });
});
app.delete('/api/shared/:id', auth, (req, res) => {
  const db = loadDB(); db.shared_tasks = db.shared_tasks.filter(s => !(s.id === req.params.id && s.recipient_email === req.user.username));
  saveDB(db); res.json({ ok: true });
});

// ── DEBUG (faqat development) ──
app.get('/api/debug/archive', auth, (req, res) => {
  const db = loadDB();
  res.json(db.archive.map(a => ({ id: a.id, user_id: a.user_id, user_id_type: typeof a.user_id, from_list: a.from_list })));
});

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
