const logStore = require('../store/logStore');
const { emitAttackLog } = require('../socket');

/**
 * DEMO-ONLY traffic generator (DEMO_MODE=true). Not needed once the
 * real proxy is running — real requests through the WAF on :8080
 * produce the same rows through the same pipeline. Kept as a way to
 * fill the dashboard when you have no traffic to show.
 */
const SAMPLE_REQUESTS = [
  { method: 'GET', path: '/api/products?id=1', category: 'none', risk: 0 },
  { method: 'GET', path: "/api/users?id=1' OR '1'='1", category: 'sqli', risk: 75 },
  { method: 'POST', path: '/comments', category: 'xss', risk: 80 },
  { method: 'GET', path: '/files?name=../../../../etc/passwd', category: 'path_traversal', risk: 92 },
  { method: 'POST', path: '/login', category: 'brute_force', risk: 90 },
  { method: 'GET', path: '/search?q=hello', category: 'none', risk: 0 },
];
const SAMPLE_IPS = ['203.0.113.7', '198.51.100.23', '192.0.2.44', '203.0.113.99', '10.0.0.14'];
const pick = (a) => a[Math.floor(Math.random() * a.length)];

function startSimulator(io, orgId) {
  console.log(`[demo] Mock traffic simulator running for org ${orgId}. Set DEMO_MODE=false to disable.`);
  const timer = setInterval(async () => {
    const s = pick(SAMPLE_REQUESTS);
    try {
      const row = await logStore.insertLog({
        orgId, ip: pick(SAMPLE_IPS), method: s.method, path: s.path, category: s.category,
        riskScore: s.risk, action: s.risk >= 50 ? 'blocked' : 'allowed', userAgent: 'demo-simulator/1.0',
      });
      emitAttackLog(io, orgId, row);
    } catch (err) {
      console.error('[demo] simulator insert failed:', err.message);
    }
  }, 2500);
  return () => clearInterval(timer);
}

module.exports = { startSimulator };
