/**
 * attack-demo.js — fires realistic normal + malicious traffic THROUGH
 * the WAF so the dashboard lights up, and checks the outcome of each
 * request. Doubles as the integration test:
 *
 *     npm run attack            (exit code 1 if any expectation fails)
 *
 * It spoofs different client IPs with X-Forwarded-For, which works
 * only because .env has TRUST_XFF=true (demo setting).
 */
const WAF = process.env.WAF_URL || 'http://localhost:8080';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0;

async function send({ ip, method = 'GET', path, body, json, expect, label }) {
  const headers = { 'X-Forwarded-For': ip, Accept: 'application/json' };
  let payload;
  if (json) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(json); }
  if (body) { headers['Content-Type'] = 'application/x-www-form-urlencoded'; payload = body; }
  const res = await fetch(WAF + path, { method, headers, body: payload });
  await res.arrayBuffer();
  const ok = expect === undefined || (Array.isArray(expect) ? expect.includes(res.status) : res.status === expect);
  if (!ok) failures++;
  console.log(`${ok ? '  ✓' : '  ✗'} ${String(res.status).padEnd(3)} ${ip.padEnd(14)} ${method.padEnd(4)} ${label || path}`.slice(0, 120));
  return res.status;
}

async function main() {
  const health = await fetch(WAF + '/__threatgate/health').catch(() => null);
  if (!health || !health.ok) {
    console.error(`Cannot reach the WAF at ${WAF}. Start everything first:  npm run dev`);
    process.exit(2);
  }
  // Fresh attacker IPs each run, so re-running the demo within the 5-minute
  // block window still behaves the same (an already-blocked IP would not).
  const r = () => 20 + Math.floor(Math.random() * 230);
  const a = `203.0.113.${r()}`, b = `198.51.100.${r()}`, c = `192.0.2.${r()}`, d = `203.0.113.${r()}`;

  console.log('\n1) Normal traffic — must be ALLOWED (200)');
  await send({ ip: '10.0.0.14', path: '/', expect: 200 });
  await send({ ip: '10.0.0.14', path: '/search?q=hello+world', expect: 200 });
  await send({ ip: '10.0.0.15', path: '/api/products?id=1', expect: 200 });
  await send({ ip: '10.0.0.15', path: '/search?q=O%27Brien', expect: 200, label: "/search?q=O'Brien (apostrophe is fine)" });
  await send({ ip: '10.0.0.16', method: 'POST', path: '/comments', json: { text: 'Great product!' }, expect: 200 });
  await send({ ip: '10.0.0.16', method: 'POST', path: '/login', body: 'username=demo&password=demo1234', expect: 200, label: '/login (valid credentials)' });

  console.log('\n2) SQL injection — must be BLOCKED (403)');
  await send({ ip: a, path: "/api/users?id=1' OR '1'='1", expect: 403 });
  await send({ ip: a, path: '/api/products?id=1 UNION SELECT username,password FROM users', expect: 403 });
  await send({ ip: a, path: "/api/users?id=admin'--", expect: 403 });
  await send({ ip: a, path: '/api/products?id=1;DROP TABLE users', expect: 403 });
  await send({ ip: a, path: '/api/products?id=1%27%20OR%20%271%27%3D%271', expect: 403, label: '/api/products?id=1%27%20OR%20%271%27%3D%271 (URL-encoded)' });

  console.log('\n3) Cross-site scripting — must be BLOCKED (403)');
  await send({ ip: b, path: '/search?q=<script>alert(1)</script>', expect: 403 });
  await send({ ip: b, path: '/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E', expect: 403 });
  await send({ ip: b, method: 'POST', path: '/comments', json: { text: '<script>document.cookie</script>' }, expect: 403, label: '/comments  (XSS in JSON body)' });
  await send({ ip: b, path: '/search?q=%253Cscript%253E', expect: 403, label: '/search?q=%253Cscript%253E (double-encoded)' });

  console.log('\n4) Path traversal — must be BLOCKED (403)');
  await send({ ip: c, path: '/files?name=../../../../etc/passwd', expect: 403 });
  await send({ ip: c, path: '/files?name=..%2f..%2f..%2fetc%2fpasswd', expect: 403 });
  await send({ ip: c, path: '/.env', expect: 403 });

  console.log('\n5) Brute-force login — failures 401, then the IP gets auto-blocked (403)');
  for (let i = 1; i <= 7; i++) {
    await send({ ip: d, method: 'POST', path: '/login', body: `username=admin&password=guess${i}`,
      expect: i <= 5 ? 401 : 403, label: `/login  wrong password attempt #${i}` });
    await sleep(120);
  }
  console.log('   …even a CORRECT login is refused while blocked:');
  await send({ ip: d, method: 'POST', path: '/login', body: 'username=demo&password=demo1234', expect: 403, label: '/login (valid creds, but IP is blocked)' });
  console.log('   …and other visitors are unaffected:');
  await send({ ip: '10.0.0.14', path: '/', expect: 200 });

  console.log('\n6) Repeated attacks from one IP — auto-blocked after strike limit');
  const e = `192.0.2.${r()}`;
  for (let i = 1; i <= 10; i++) {
    await send({ ip: e, path: `/search?q=<script>alert(${i})</script>`, expect: 403, label: `XSS probe #${i}` });
    await sleep(60);
  }
  await send({ ip: e, path: '/', expect: 403, label: '/ (harmless request, but IP now blocked)' });

  console.log(failures === 0 ? '\nAll expectations met ✔  — open http://localhost:5173 to see the dashboard.\n'
    : `\n${failures} expectation(s) FAILED ✗\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => { console.error(err); process.exit(2); });
