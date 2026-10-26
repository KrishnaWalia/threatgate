/**
 * DEMO TARGET — a tiny stand-in for "the website ThreatGate protects".
 * Run on :3000; the WAF on :8080 forwards clean traffic to it.
 * Browse http://localhost:8080 (through the WAF), NOT :3000.
 *
 * It is deliberately NOT vulnerable (it escapes all output and never
 * touches a database or the filesystem) — it only needs to look like
 * an app with a search box, a login, an API and a file endpoint, so
 * there's something realistic to attack in a demo.
 */
const express = require('express');
const app = express();
const PORT = process.env.TARGET_PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

app.get('/', (req, res) => {
  res.send(`<!doctype html><meta charset="utf-8"><title>ShopDemo</title>
<body style="font-family:system-ui;max-width:640px;margin:40px auto;padding:0 16px">
<h1>ShopDemo <small style="color:#888">(protected by ThreatGate)</small></h1>
<p>This is the protected site. You are viewing it <b>through the WAF</b>.</p>
<h3>Search</h3><form action="/search"><input name="q" placeholder="try: hello"> <button>Search</button></form>
<h3>Login</h3><form method="POST" action="/login"><input name="username" placeholder="username"> <input name="password" type="password" placeholder="password"> <button>Sign in</button></form>
<p style="color:#888">Valid demo login: <code>demo / demo1234</code></p>
<h3>Other endpoints</h3><ul><li><a href="/api/products?id=1">/api/products?id=1</a></li><li><a href="/files?name=report.pdf">/files?name=report.pdf</a></li></ul>
</body>`);
});

app.get('/search', (req, res) => res.send(`<h2>Results for: ${esc(req.query.q || '')}</h2><p>0 results (demo).</p>`));
app.get('/api/products', (req, res) => res.json({ id: esc(req.query.id || 'all'), name: 'Demo product', price: 19.99 }));
app.get('/api/users', (req, res) => res.json({ id: esc(req.query.id || ''), name: 'Demo user' }));
app.get('/files', (req, res) => res.json({ requested: esc(req.query.name || ''), note: 'Demo endpoint — serves nothing.' }));
app.post('/comments', (req, res) => res.json({ ok: true, stored: esc(JSON.stringify(req.body)).slice(0, 200) }));

app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (username === 'demo' && password === 'demo1234') return res.json({ ok: true, message: 'Welcome back, demo!' });
  res.status(401).json({ ok: false, error: 'Invalid username or password' });
});

app.listen(PORT, () => console.log(`[target] Demo site (unprotected!) -> http://localhost:${PORT}  — visit it via the WAF on :8080`));
