const test = require('node:test');
const assert = require('node:assert');
const { inspect, normalize, score } = require('../waf/detector');
const { compileRules } = require('../waf/detector');
const { DEFAULT_RULES } = require('../waf/rules');

const rules = compileRules(DEFAULT_RULES);
const THRESHOLD = 50;
const req = (url, headers = {}) => ({ originalUrl: url, headers });
const run = (url, body = '', headers) => inspect(req(url, headers), body, rules);

// ---- must BLOCK ------------------------------------------------
const attacks = [
  ['sqli', "/api/users?id=1' OR '1'='1"],
  ['sqli', '/api/users?id=1 OR 1=1'],
  ['sqli', '/items?id=1 UNION SELECT username,password FROM users'],
  ['sqli', '/items?id=1/**/UNION/**/SELECT/**/1,2'],
  ['sqli', "/login?user=admin'--"],
  ['sqli', '/items?id=1;DROP TABLE users'],
  ['sqli', '/items?id=1 AND SLEEP(5)'],
  ['sqli', '/items?id=1%27%20OR%20%271%27%3D%271'],           // URL-encoded
  ['sqli', '/x?q=SELECT+*+FROM+information_schema.tables'],
  ['xss', '/search?q=<script>alert(1)</script>'],
  ['xss', '/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'],     // encoded
  ['xss', '/search?q=%253Cscript%253E'],                        // double-encoded
  ['xss', '/search?q=<img src=x onerror=alert(1)>'],
  ['xss', '/go?u=javascript:alert(document.cookie)'],
  ['xss', '/search?q=&#60;script&#62;alert(1)'],                // HTML entities
  ['xss', '/p?x=<iframe src=//evil.example>'],
  ['path_traversal', '/files?name=../../../../etc/passwd'],
  ['path_traversal', '/files?name=..%2f..%2f..%2fetc%2fpasswd'],
  ['path_traversal', '/files?name=%252e%252e%252f%252e%252e%252fetc%252fpasswd'],
  ['path_traversal', '/files?name=..\\..\\windows\\win.ini'],
  ['path_traversal', '/.env'],
  ['path_traversal', '/.git/config'],
  ['path_traversal', '/page?f=php://filter/convert.base64-encode/resource=index'],
];
for (const [cat, url] of attacks) {
  test(`blocks ${cat}: ${url}`, () => {
    const r = run(url);
    assert.ok(r.riskScore >= THRESHOLD, `risk ${r.riskScore} < ${THRESHOLD}`);
    assert.strictEqual(r.category, cat);
  });
}

test('blocks XSS in a POST body', () => {
  const r = run('/comments', 'text=<script>alert(1)</script>');
  assert.ok(r.riskScore >= THRESHOLD);
  assert.strictEqual(r.category, 'xss');
  assert.strictEqual(r.matches[0].where, 'body');
});

test('blocks SQLi in User-Agent header', () => {
  const r = run('/', '', { 'user-agent': "' OR '1'='1" });
  assert.ok(r.riskScore >= THRESHOLD);
});

// ---- must ALLOW (false-positive guard) -------------------------
const benign = [
  '/',
  '/search?q=hello+world',
  '/api/products?id=5',
  '/api/orders?id=5&sort=price',
  '/search?q=select+the+best+items+from+our+store',   // weak rule only (40)
  '/blog/2024/05/how-to-write-sql',
  '/search?q=O%27Brien',                                // apostrophe in a name
  '/files?name=report.pdf',
  '/about/team.html',
  "/search?q=rock+and+roll",
  '/assets/app.v2.min.js',
];
for (const url of benign) {
  test(`allows: ${url}`, () => {
    const r = run(url);
    assert.ok(r.riskScore < THRESHOLD, `false positive: risk ${r.riskScore} (${r.matches.map((m) => m.id)})`);
  });
}

test('allows normal JSON login body', () => {
  const r = run('/login', JSON.stringify({ username: 'alice', password: 'Hunter2!' }));
  assert.ok(r.riskScore < THRESHOLD);
});

// ---- scoring formula -------------------------------------------
test('score(): strongest rule + half of the others, capped at 100', () => {
  const s = score([
    { id: 1, category: 'sqli', weight: 80 },
    { id: 2, category: 'sqli', weight: 40 },
    { id: 3, category: 'xss', weight: 20 },
  ]);
  // 80 + 0.5*(40+20) = 110 -> capped at 100
  assert.strictEqual(s.riskScore, 100);
  assert.strictEqual(score([{ id: 1, category: 'xss', weight: 60 }, { id: 2, category: 'xss', weight: 20 }]).riskScore, 70);
  assert.strictEqual(score([]).riskScore, 0);
});

test('weak signals combine to tip over the threshold', () => {
  // rule 9 (select..from, 40) + rule 16 (alert(, 40) -> 40 + 20 = 60
  const r = run('/search?q=select a from b alert(1)');
  assert.ok(r.riskScore >= THRESHOLD);
});

test('a repeated payload does not inflate the score', () => {
  const once = run('/x?a=<script>').riskScore;
  const many = run('/x?a=<script>&b=<script>&c=<script>').riskScore;
  assert.strictEqual(once, many);
});

test('normalize(): decodes layered encoding and strips SQL comments', () => {
  assert.strictEqual(normalize('%253Cscript%253E'), '<script>');
  assert.strictEqual(normalize('UNION/**/SELECT'), 'UNION SELECT');
  assert.strictEqual(normalize('a%zzb'), 'a%zzb'); // malformed escape never throws
});
