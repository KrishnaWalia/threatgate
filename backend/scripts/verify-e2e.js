/**
 * verify-e2e.js — proves the three tracks talk to each other live:
 *   login (C) -> open socket (C/B) -> send attacks via proxy (A)
 *   -> see them arrive over Socket.io (B) -> check REST + role rules (C)
 *
 *   npm run verify        (stack must be running: npm run dev)
 */
const { io } = require('socket.io-client');
const API = process.env.API_URL || 'http://localhost:4000';
const WAF = process.env.WAF_URL || 'http://localhost:8080';
let failed = 0;
const check = (name, cond, extra = '') => { if (!cond) failed++; console.log(`${cond ? '  ✓' : '  ✗'} ${name}${extra ? '  — ' + extra : ''}`); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const j = async (url, opts = {}, token) => {
  const res = await fetch(url, { ...opts, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(opts.headers || {}) } });
  let body = null; try { body = await res.json(); } catch {}
  return { status: res.status, body };
};
const via = (path, ip, opts = {}) => fetch(WAF + path, { ...opts, headers: { 'X-Forwarded-For': ip, Accept: 'application/json', ...(opts.headers || {}) } });

(async () => {
  console.log('\nAuth (Track C)');
  const admin = (await j(`${API}/api/auth/login`, { method: 'POST', body: JSON.stringify({ email: 'admin@threatgate.dev', password: 'Admin123!' }) })).body;
  const viewer = (await j(`${API}/api/auth/login`, { method: 'POST', body: JSON.stringify({ email: 'viewer@threatgate.dev', password: 'Viewer123!' }) })).body;
  check('admin login returns a JWT', !!admin?.token);
  check('viewer login returns a JWT', !!viewer?.token);
  check('bad password is rejected (401)', (await j(`${API}/api/auth/login`, { method: 'POST', body: JSON.stringify({ email: 'admin@threatgate.dev', password: 'nope' }) })).status === 401);
  check('no token -> 401', (await j(`${API}/api/dashboard/logs`)).status === 401);
  check('garbage token -> 401', (await j(`${API}/api/dashboard/logs`, {}, 'abc.def.ghi')).status === 401);

  console.log('\nLive pipeline: proxy (A) -> log + emit (B) -> socket (C)');
  const socket = io(API, { auth: { token: viewer.token }, transports: ['websocket'] });
  const events = [];
  socket.on('attack:new', (row) => events.push(row));
  await new Promise((res, rej) => { socket.on('connect', res); socket.on('connect_error', rej); setTimeout(() => rej(new Error('socket timeout')), 4000); });
  check('socket accepts a valid token', socket.connected);
  const bad = io(API, { auth: { token: 'bogus' }, transports: ['websocket'], reconnection: false });
  const badErr = await new Promise((res) => { bad.on('connect_error', (e) => res(e.message)); setTimeout(() => res('timeout'), 3000); });
  check('socket rejects an invalid token', /Invalid|token/i.test(badErr), badErr); bad.close();

  const ip = '198.18.0.' + (10 + Math.floor(Math.random() * 200));
  await via('/search?q=hello', ip);
  await via("/api/users?id=1' OR '1'='1", ip);
  await sleep(400);
  const allowed = events.find((e) => e.ip_address === ip && e.action === 'allowed');
  const blocked = events.find((e) => e.ip_address === ip && e.action === 'blocked');
  check('allowed request pushed over Socket.io', !!allowed, allowed && allowed.path);
  check('blocked SQLi pushed over Socket.io with category+score', blocked?.category === 'sqli' && blocked?.risk_score >= 50, blocked && `${blocked.category} / ${blocked.risk_score}`);
  check('socket row has the schema columns', blocked && ['id', 'ip_address', 'method', 'path', 'category', 'risk_score', 'action', 'created_at'].every((k) => k in blocked));

  console.log('\nREST (Track C reading Track B data)');
  const logs = await j(`${API}/api/dashboard/logs?limit=10`, {}, viewer.token);
  check('viewer can read logs', logs.status === 200 && logs.body.logs.length > 0);
  const stats = await j(`${API}/api/dashboard/stats`, {}, viewer.token);
  check('stats reflect traffic', stats.body.totalRequests > 0 && stats.body.totalBlocked > 0, JSON.stringify({ total: stats.body.totalRequests, blocked: stats.body.totalBlocked }));
  check('stats include category + timeline data', stats.body.byCategory.length > 0 && stats.body.timeline.length > 0);

  console.log('\nRole-based access (admin vs viewer)');
  check('viewer -> GET blocked-ips is 403', (await j(`${API}/api/dashboard/blocked-ips`, {}, viewer.token)).status === 403);
  check('admin -> GET blocked-ips is 200', (await j(`${API}/api/dashboard/blocked-ips`, {}, admin.token)).status === 200);
  check('viewer -> PATCH rule is 403', (await j(`${API}/api/dashboard/rules/10`, { method: 'PATCH', body: JSON.stringify({ is_active: false }) }, viewer.token)).status === 403);

  console.log('\nUnblock flow');
  const victim = '198.18.1.' + (10 + Math.floor(Math.random() * 200));
  for (let i = 0; i < 5; i++) await via('/login', victim, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'username=x&password=y' });
  await sleep(300);
  check('IP is blocked after repeated failed logins', (await via('/', victim)).status === 403);
  const list = (await j(`${API}/api/dashboard/blocked-ips`, {}, admin.token)).body.blockedIps;
  const row = list.find((r) => r.ip_address === victim);
  check('block appears in admin Blocked IPs list', !!row, row && row.reason);
  check('viewer cannot unblock (403)', (await j(`${API}/api/dashboard/blocked-ips/${row.id}`, { method: 'DELETE' }, viewer.token)).status === 403);
  check('admin unblocks (200)', (await j(`${API}/api/dashboard/blocked-ips/${row.id}`, { method: 'DELETE' }, admin.token)).status === 200);
  check('unblocked IP can browse again', (await via('/', victim)).status === 200);

  console.log('\nRules-as-data: toggle a rule live');
  const probe = '/search?q=' + encodeURIComponent('<iframe src=//x.example>');
  check('rule 13 (iframe) blocks by default', (await via(probe, '198.18.2.1')).status === 403);
  await j(`${API}/api/dashboard/rules/13`, { method: 'PATCH', body: JSON.stringify({ is_active: false }) }, admin.token);
  check('after disabling rule 13 the same request passes', (await via(probe, '198.18.2.2')).status === 200);
  await j(`${API}/api/dashboard/rules/13`, { method: 'PATCH', body: JSON.stringify({ is_active: true }) }, admin.token);
  check('re-enabled -> blocked again', (await via(probe, '198.18.2.3')).status === 403);

  socket.close();
  console.log(failed === 0 ? '\nAll checks passed ✔\n' : `\n${failed} check(s) FAILED ✗\n`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error('verify crashed:', e.message); process.exit(2); });
