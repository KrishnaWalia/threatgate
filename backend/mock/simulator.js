const pool = require('../db/pool');
const { emitAttackLog } = require('../socket');

/**
 * DEMO-ONLY traffic generator.
 *
 * Track A (proxy + detection) and Track B (real-time pipeline +
 * brute-force logic) are built by teammates and land later during
 * integration. Until then, this fakes what Track B would normally
 * do on every real request: insert a row into attack_logs, then
 * push it over the socket. It writes to the exact same table with
 * the exact same shape real traffic will use, so nothing about the
 * dashboard changes when the real pipeline is swapped in — this
 * file is simply deleted (or DEMO_MODE=false) at integration time.
 */
const SAMPLE_REQUESTS = [
  { method: 'GET', path: '/api/products?id=1', category: 'none', risk: 0 },
  { method: 'GET', path: "/api/users?id=1' OR '1'='1", category: 'sqli', risk: 85 },
  { method: 'POST', path: '/comments', category: 'xss', risk: 60, body: '<script>alert(1)</script>' },
  { method: 'GET', path: '/files?name=../../../../etc/passwd', category: 'path_traversal', risk: 70 },
  { method: 'POST', path: '/login', category: 'brute_force', risk: 45 },
  { method: 'GET', path: '/api/orders?id=5', category: 'none', risk: 0 },
  { method: 'GET', path: '/search?q=hello', category: 'none', risk: 0 },
  { method: 'GET', path: "/api/login?user=admin'--", category: 'sqli', risk: 90 },
];

const SAMPLE_IPS = ['203.0.113.7', '198.51.100.23', '192.0.2.44', '203.0.113.99', '10.0.0.14'];

function randomFrom(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function startSimulator(io, orgId) {
  console.log(`[demo] Mock attack simulator running for org ${orgId}. Set DEMO_MODE=false to disable.`);

  const interval = setInterval(async () => {
    const sample = randomFrom(SAMPLE_REQUESTS);
    const ip = randomFrom(SAMPLE_IPS);
    const action = sample.risk >= 50 ? 'blocked' : 'allowed';

    try {
      const [result] = await pool.query(
        `INSERT INTO attack_logs
           (org_id, ip_address, method, path, category, risk_score, action, user_agent)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [orgId, ip, sample.method, sample.path, sample.category, sample.risk, action, 'demo-simulator/1.0']
      );

      const [[row]] = await pool.query(
        `SELECT id, ip_address, method, path, category, risk_score, action, created_at
         FROM attack_logs WHERE id = ?`,
        [result.insertId]
      );

      emitAttackLog(io, orgId, row);
    } catch (err) {
      console.error('[demo] simulator insert failed:', err.message);
    }
  }, 2500);

  return () => clearInterval(interval);
}

module.exports = { startSimulator };
