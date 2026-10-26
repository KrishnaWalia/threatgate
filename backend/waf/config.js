/**
 * WAF configuration — every tunable lives here, read from .env,
 * so nothing about thresholds or windows is hardcoded in logic.
 * Call AFTER dotenv.config().
 */
const num = (v, d) => (v !== undefined && v !== '' && !Number.isNaN(Number(v)) ? Number(v) : d);

function loadConfig(env = process.env) {
  return {
    // --- Proxy (Track A) ---
    wafPort: num(env.WAF_PORT, 8080),
    targetUrl: env.TARGET_URL || 'http://localhost:3000',
    wafOrgId: num(env.WAF_ORG_ID, 1),
    blockThreshold: num(env.BLOCK_THRESHOLD, 50), // risk >= this -> 403
    maxBodyBytes: num(env.MAX_BODY_BYTES, 1024 * 1024),
    inspectBodyBytes: num(env.INSPECT_BODY_BYTES, 100 * 1024),
    trustXff: env.TRUST_XFF === 'true',

    // --- Brute force / rate limit (Track B) ---
    loginPathRegex: new RegExp(env.LOGIN_PATH_REGEX || '/(login|signin|sign-in|auth)\\b', 'i'),
    loginFailMax: num(env.LOGIN_FAIL_MAX, 5),
    loginFailWindowMs: num(env.LOGIN_FAIL_WINDOW_MS, 60_000),
    rateLimitMax: num(env.RATE_LIMIT_MAX, 100),
    rateLimitWindowMs: num(env.RATE_LIMIT_WINDOW_MS, 10_000),
    attackStrikeMax: num(env.ATTACK_STRIKE_MAX, 8),
    attackStrikeWindowMs: num(env.ATTACK_STRIKE_WINDOW_MS, 60_000),
    blockDurationMs: num(env.BLOCK_DURATION_MS, 5 * 60_000),
  };
}

module.exports = { loadConfig };
