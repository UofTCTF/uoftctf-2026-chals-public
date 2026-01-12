const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const createDOMPurify = require('dompurify');
const express = require('express');
const { JSDOM } = require('jsdom');

const PORT = process.env.PORT || 3000;
const FLAG = process.env.FLAG || 'uoftctf{fake_flag}';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'adminpass';
const APP_ORIGIN = process.env.APP_ORIGIN || 'http://localhost:3000';
const BOT_ORIGIN = process.env.BOT_ORIGIN || 'http://localhost:4000';
const POW_DIFFICULTY = Number.parseInt(process.env.POW_DIFFICULTY || '5000', 10);
const POW_ENABLED = Number.isFinite(POW_DIFFICULTY) && POW_DIFFICULTY > 0;

const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'db.json');

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);
const appOrigin = new URL(APP_ORIGIN);
const appPort = appOrigin.port || (appOrigin.protocol === 'https:' ? '443' : '80');
const allowedReportHosts = new Set([appOrigin.host]);
if (appOrigin.hostname === 'localhost') {
  allowedReportHosts.add(`127.0.0.1:${appPort}`);
}
if (appOrigin.hostname === '127.0.0.1') {
  allowedReportHosts.add(`localhost:${appPort}`);
}

const app = express();
app.disable('x-powered-by');

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());
app.use('/static', express.static(path.join(__dirname, 'public')));
app.use('/static/dompurify', express.static(path.join(__dirname, 'node_modules', 'dompurify', 'dist')));

function ensureDataFile() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  if (!fs.existsSync(DATA_FILE)) {
    const adminHash = bcrypt.hashSync(ADMIN_PASSWORD, 10);
    const now = Date.now();
    const seed = {
      nextUserId: 2,
      nextPostId: 2,
      users: [
        {
          id: 1,
          username: 'admin',
          passHash: adminHash,
          isAdmin: true
        }
      ],
      posts: [
        {
          id: 1,
          userId: 1,
          savedContent: '<p>Admin draft: keep the blog tidy.</p>',
          draftContent: '',
          createdAt: now,
          updatedAt: now
        }
      ],
      sessions: {},
      magicLinks: {}
    };
    fs.writeFileSync(DATA_FILE, JSON.stringify(seed, null, 2));
  }
}

function loadDb() {
  ensureDataFile();
  const db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  const touched = normalizeDb(db);
  if (touched) {
    saveDb(db);
  }
  return db;
}

function saveDb(db) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
}

function cookieOptions() {
  return {
    httpOnly: false,
    sameSite: 'Lax',
    path: '/'
  };
}

function getUserById(db, id) {
  return db.users.find((user) => user.id === id) || null;
}

function getUserByName(db, username) {
  return db.users.find((user) => user.username === username) || null;
}

function normalizeDb(db) {
  let touched = false;
  if (!Array.isArray(db.posts)) {
    db.posts = [];
    touched = true;
  }
  if (!db.nextPostId) {
    db.nextPostId = 1;
    touched = true;
  }
  db.posts.forEach((post) => {
    if (!post.id) {
      post.id = db.nextPostId++;
      touched = true;
    }
    if (!post.createdAt) {
      post.createdAt = Date.now();
      touched = true;
    }
    if (!post.updatedAt) {
      post.updatedAt = post.createdAt;
      touched = true;
    }
  });
  const maxId = db.posts.reduce((max, post) => Math.max(max, post.id || 0), 0);
  if (db.nextPostId <= maxId) {
    db.nextPostId = maxId + 1;
    touched = true;
  }
  return touched;
}

function getUserPosts(db, userId) {
  return db.posts
    .filter((post) => post.userId === userId)
    .sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
}

function getPostById(db, userId, postId) {
  return db.posts.find((post) => post.userId === userId && post.id === postId) || null;
}

function createPost(db, userId) {
  const now = Date.now();
  const post = {
    id: db.nextPostId++,
    userId,
    savedContent: '',
    draftContent: '',
    createdAt: now,
    updatedAt: now
  };
  db.posts.push(post);
  return post;
}

function createSession(db, userId) {
  const sid = crypto.randomBytes(18).toString('hex');
  db.sessions[sid] = {
    userId,
    createdAt: Date.now()
  };
  return sid;
}

function resolveSession(req, db) {
  const sid = req.cookies.sid;
  if (!sid) {
    return null;
  }
  const session = db.sessions[sid];
  if (!session) {
    return null;
  }
  return getUserById(db, session.userId);
}

function sanitizeHtml(input) {
  return DOMPurify.sanitize(input || '');
}

const POW_VERSION = 's';
const POW_MOD = (1n << 1279n) - 1n;
const POW_ONE = 1n;

function powBytesToBigInt(buf) {
  if (!buf || buf.length === 0) {
    return 0n;
  }
  return BigInt(`0x${buf.toString('hex')}`);
}

function powGenerateChallenge(difficulty) {
  const dBytes = Buffer.alloc(4);
  dBytes.writeUInt32BE(difficulty);
  const xBytes = crypto.randomBytes(16);
  return `${POW_VERSION}.${dBytes.toString('base64')}.${xBytes.toString('base64')}`;
}

function powDecodeChallenge(value) {
  const parts = String(value || '').split('.', 3);
  if (parts.length !== 3 || parts[0] !== POW_VERSION) {
    return null;
  }
  const dBytes = Buffer.from(parts[1], 'base64');
  if (dBytes.length > 4) {
    return null;
  }
  const padded = Buffer.concat([Buffer.alloc(4 - dBytes.length), dBytes]);
  const difficulty = padded.readUInt32BE(0);
  const xBytes = Buffer.from(parts[2], 'base64');
  return { difficulty, x: powBytesToBigInt(xBytes) };
}

function powDecodeSolution(value) {
  const parts = String(value || '').split('.', 2);
  if (parts.length !== 2 || parts[0] !== POW_VERSION) {
    return null;
  }
  const yBytes = Buffer.from(parts[1], 'base64');
  return powBytesToBigInt(yBytes);
}

function powCheck(challenge, solution, expectedDifficulty) {
  const decoded = powDecodeChallenge(challenge);
  if (!decoded || decoded.difficulty !== expectedDifficulty) {
    return false;
  }
  const y = powDecodeSolution(solution);
  if (y === null) {
    return false;
  }
  let current = y;
  for (let i = 0; i < decoded.difficulty; i += 1) {
    current = (current ^ POW_ONE);
    current = (current * current) % POW_MOD;
  }
  if (current === decoded.x) {
    return true;
  }
  return current === (POW_MOD - decoded.x);
}

function reportContext(status, error) {
  return {
    status,
    error,
    powChallenge: POW_ENABLED ? powGenerateChallenge(POW_DIFFICULTY) : null
  };
}

function safeRedirect(value) {
  if (!value || typeof value !== 'string') {
    return '/dashboard';
  }
  try {
    const parsed = new URL(value, APP_ORIGIN);
    if (parsed.origin !== appOrigin.origin) {
      return '/dashboard';
    }
    if (!parsed.pathname.startsWith('/')) {
      return '/dashboard';
    }
    return `${parsed.pathname}${parsed.search}${parsed.hash}`;
  } catch (err) {
    return '/dashboard';
  }
}

function normalizeReportUrl(input) {
  if (!input || typeof input !== 'string') {
    return null;
  }
  let url;
  try {
    if (input.startsWith('/')) {
      url = new URL(input, APP_ORIGIN);
    } else {
      url = new URL(input);
    }
  } catch (err) {
    return null;
  }
  if (url.protocol !== 'http:') {
    return null;
  }
  if (!allowedReportHosts.has(url.host)) {
    return null;
  }
  url.host = appOrigin.host;
  return url.toString();
}

function requireLogin(req, res, next) {
  if (!req.user) {
    return res.redirect('/login');
  }
  return next();
}

app.use((req, res, next) => {
  const db = loadDb();
  req.db = db;
  req.user = resolveSession(req, db);
  res.locals.user = req.user;
  next();
});

app.get('/', (req, res) => {
  if (req.user) {
    return res.redirect('/dashboard');
  }
  return res.render('index');
});

app.get('/register', (req, res) => {
  return res.render('register', { error: null });
});

app.post('/register', (req, res) => {
  const db = req.db;
  const username = (req.body.username || '').trim();
  const password = req.body.password || '';

  if (!username || !password) {
    return res.render('register', { error: 'Username and password are required.' });
  }
  if (getUserByName(db, username)) {
    return res.render('register', { error: 'Username already exists.' });
  }

  const userId = db.nextUserId++;
  const passHash = bcrypt.hashSync(password, 10);
  db.users.push({ id: userId, username, passHash, isAdmin: false });
  saveDb(db);

  return res.redirect('/login');
});

app.get('/login', (req, res) => {
  return res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const db = req.db;
  const username = (req.body.username || '').trim();
  const password = req.body.password || '';
  const user = getUserByName(db, username);

  if (!user || !bcrypt.compareSync(password, user.passHash)) {
    return res.render('login', { error: 'Invalid username or password.' });
  }

  const existingSid = req.cookies.sid;
  if (existingSid) {
    res.cookie('sid_prev', existingSid, cookieOptions());
  }
  const sid = createSession(db, user.id);
  saveDb(db);
  res.cookie('sid', sid, cookieOptions());

  return res.redirect('/dashboard');
});

app.post('/logout', (req, res) => {
  res.clearCookie('sid');
  res.clearCookie('sid_prev');
  return res.redirect('/');
});

app.get('/dashboard', requireLogin, (req, res) => {
  const posts = getUserPosts(req.db, req.user.id).map((post) => ({
    id: post.id,
    updatedAt: post.updatedAt,
    preview: sanitizeHtml(post.savedContent)
  }));
  return res.render('dashboard', {
    posts
  });
});

app.get('/post/:id', requireLogin, (req, res) => {
  const postId = Number.parseInt(req.params.id, 10);
  if (!Number.isFinite(postId)) {
    return res.status(404).send('Not found.');
  }
  const post = getPostById(req.db, req.user.id, postId);
  if (!post) {
    return res.status(404).send('Not found.');
  }
  return res.render('post', {
    post,
    content: sanitizeHtml(post.savedContent)
  });
});

app.get('/edit', requireLogin, (req, res) => {
  const db = req.db;
  const post = createPost(db, req.user.id);
  saveDb(db);
  return res.redirect(`/edit/${post.id}`);
});

app.get('/edit/new', requireLogin, (req, res) => {
  return res.redirect('/edit');
});

app.get('/edit/:id', requireLogin, (req, res) => {
  const postId = Number.parseInt(req.params.id, 10);
  if (!Number.isFinite(postId)) {
    return res.status(404).send('Not found.');
  }
  const post = getPostById(req.db, req.user.id, postId);
  if (!post) {
    return res.status(404).send('Not found.');
  }
  const draftContent = post.draftContent || post.savedContent || '';
  return res.render('editor', {
    post,
    draftContent
  });
});

app.post('/api/save', requireLogin, (req, res) => {
  const db = req.db;
  const postId = Number.parseInt(req.body.postId, 10);
  if (!Number.isFinite(postId)) {
    return res.status(400).json({ ok: false });
  }
  const post = getPostById(db, req.user.id, postId);
  if (!post) {
    return res.status(404).json({ ok: false });
  }
  const rawContent = String(req.body.content || '');
  const sanitized = sanitizeHtml(rawContent);
  post.savedContent = sanitized;
  post.draftContent = sanitized;
  post.updatedAt = Date.now();
  saveDb(db);
  return res.json({ ok: true });
});

app.post('/api/autosave', requireLogin, (req, res) => {
  const db = req.db;
  const postId = Number.parseInt(req.body.postId, 10);
  if (!Number.isFinite(postId)) {
    return res.status(400).json({ ok: false });
  }
  const post = getPostById(db, req.user.id, postId);
  if (!post) {
    return res.status(404).json({ ok: false });
  }
  const rawContent = String(req.body.content || '');
  post.draftContent = rawContent;
  post.updatedAt = Date.now();
  saveDb(db);
  return res.json({ ok: true });
});

app.get('/account', requireLogin, (req, res) => {
  const links = Object.entries(req.db.magicLinks)
    .filter(([, entry]) => entry.userId === req.user.id)
    .map(([token]) => token);
  return res.render('account', { links });
});

app.post('/magic/generate', requireLogin, (req, res) => {
  const db = req.db;
  const token = crypto.randomBytes(16).toString('hex');
  db.magicLinks[token] = { userId: req.user.id, createdAt: Date.now() };
  saveDb(db);
  return res.redirect('/account');
});

app.get('/magic/:token', (req, res) => {
  const db = req.db;
  const token = req.params.token;
  const record = db.magicLinks[token];
  if (!record) {
    return res.status(404).send('Invalid token.');
  }

  const existingSid = req.cookies.sid;
  if (existingSid) {
    res.cookie('sid_prev', existingSid, cookieOptions());
  }
  const sid = createSession(db, record.userId);
  saveDb(db);
  res.cookie('sid', sid, cookieOptions());

  const target = safeRedirect(req.query.redirect);
  return res.redirect(target);
});

app.get('/report', requireLogin, (req, res) => {
  return res.render('report', reportContext(null, null));
});

app.post('/report', requireLogin, async (req, res) => {
  const rawUrl = (req.body.url || '').trim();
  const target = normalizeReportUrl(rawUrl);
  if (!target) {
    return res.render('report', reportContext(null, 'Only local URLs are allowed.'));
  }
  if (POW_ENABLED) {
    const challenge = req.body.pow_challenge || '';
    const solution = req.body.pow_solution || '';
    if (!powCheck(challenge, solution, POW_DIFFICULTY)) {
      return res.render('report', reportContext(null, 'Proof of work failed.'));
    }
  }

  try {
    const response = await fetch(`${BOT_ORIGIN}/visit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: target })
    });

    if (!response.ok) {
      throw new Error(`bot status ${response.status}`);
    }

    return res.render('report', reportContext('Admin is on the way.', null));
  } catch (err) {
    return res.render('report', reportContext(null, 'Bot request failed. Try again in a moment.'));
  }
});

app.get('/flag', requireLogin, (req, res) => {
  if (!req.user.isAdmin) {
    return res.status(403).send('Admins only.');
  }
  return res.send(FLAG);
});

app.listen(PORT, () => {
  console.log(`personal-blog web listening on ${PORT}`);
});
