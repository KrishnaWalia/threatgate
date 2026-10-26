/**
 * BRUTE-FORCE / RATE-LIMIT LOGIC — Track B.
 *
 * Three independent counters, all built on the same SlidingWindow:
 *
 *   1. failed logins   : >= LOGIN_FAIL_MAX  401/403s on a login path
 *                        within LOGIN_FAIL_WINDOW_MS         -> block
 *   2. request rate    : >= RATE_LIMIT_MAX requests within
 *                        RATE_LIMIT_WINDOW_MS (flood / scraping) -> block
 *   3. attack strikes  : >= ATTACK_STRIKE_MAX requests *blocked by the
 *                        detector* within ATTACK_STRIKE_WINDOW_MS
 *                        (someone probing repeatedly)         -> block
 *
 * THE COUNTING WINDOW (sliding, not fixed)
 * ----------------------------------------
 * For each key (org + IP) we keep the list of timestamps of its
 * events. On every new event we:
 *   a) drop timestamps older than (now - windowMs)
 *   b) push `now`
 *   c) the count is the list's length
 * So "5 failures in 60 s" means *any* 60-second stretch, evaluated
 * continuously. A fixed window ("reset every minute on the minute")
 * lets an attacker fire 5 at 0:59 and 5 more at 1:01 — 10 attempts in
 * 2 seconds, never tripping a limit of 5. The sliding window can't
 * be gamed that way.
 *
 * WHY THE BLOCK EXPIRY WORKS THE WAY IT DOES
 * ------------------------------------------
 * A block is a row {ip, blocked_at, expires_at = now + BLOCK_DURATION}.
 * Expiry is checked LAZILY: findActiveBlock() compares expires_at to
 * the current time on every request from that IP. We don't depend on a
 * timer firing at the right moment — if the server was busy, or
 * restarted (in DB mode), the answer is still correct because it is
 * computed from stored timestamps, not from "has a setTimeout run".
 * A background sweep (purgeExpired) only exists to free memory/rows.
 * expires_at = NULL means a permanent block (manual, from the admin).
 *
 * When a block is created the offender's counters are reset, so the
 * moment the block expires they start from zero rather than being
 * re-blocked instantly by stale history.
 */

class SlidingWindow {
  constructor(windowMs) {
    this.windowMs = windowMs;
    this.hits = new Map(); // key -> [timestamps, oldest first]
  }

  /** Record one event; return how many events are in the window now. */
  hit(key, now = Date.now()) {
    const cutoff = now - this.windowMs;
    let arr = this.hits.get(key) || [];
    let i = 0;
    while (i < arr.length && arr[i] <= cutoff) i++; // a) drop the old
    if (i > 0) arr = arr.slice(i);
    arr.push(now);                                  // b) add this one
    this.hits.set(key, arr);
    return arr.length;                              // c) count
  }

  reset(key) {
    this.hits.delete(key);
  }

  /** Forget keys with no recent events (memory hygiene only). */
  sweep(now = Date.now()) {
    const cutoff = now - this.windowMs;
    for (const [key, arr] of this.hits) {
      if (arr.length === 0 || arr[arr.length - 1] <= cutoff) this.hits.delete(key);
    }
  }
}

function createBruteForce({ store, config, onBlock = () => {} }) {
  const failedLogins = new SlidingWindow(config.loginFailWindowMs);
  const requestRate = new SlidingWindow(config.rateLimitWindowMs);
  const attackStrikes = new SlidingWindow(config.attackStrikeWindowMs);
  const all = [failedLogins, requestRate, attackStrikes];

  const keyOf = (orgId, ip) => `${orgId}:${ip}`;

  async function blockIp(orgId, ip, reason, durationMs = config.blockDurationMs) {
    const row = await store.addBlock({ orgId, ip, reason, durationMs });
    all.forEach((w) => w.reset(keyOf(orgId, ip)));
    try { await onBlock(orgId, ip, reason, row); } catch (e) { console.error('[bruteforce] onBlock failed:', e.message); }
    return row;
  }

  return {
    blockIp,

    /** Is this IP currently blocked? Expiry is evaluated inside the store. */
    check: (orgId, ip) => store.findActiveBlock(orgId, ip),

    /** Every request. Returns the block row if this request tripped the rate limit. */
    async trackRequest(orgId, ip) {
      const n = requestRate.hit(keyOf(orgId, ip));
      if (n > config.rateLimitMax) {
        return blockIp(orgId, ip, `Rate limit exceeded (${n} requests in ${config.rateLimitWindowMs / 1000}s)`);
      }
      return null;
    },

    /** Each request the detector blocked. */
    async trackAttack(orgId, ip) {
      const n = attackStrikes.hit(keyOf(orgId, ip));
      if (n >= config.attackStrikeMax) {
        return blockIp(orgId, ip, `Repeated attacks (${n} malicious requests in ${config.attackStrikeWindowMs / 1000}s)`);
      }
      return null;
    },

    /** Each 401/403 response on a login path. */
    async trackFailedLogin(orgId, ip) {
      const n = failedLogins.hit(keyOf(orgId, ip));
      if (n >= config.loginFailMax) {
        return blockIp(orgId, ip, `Brute force: ${n} failed logins in ${config.loginFailWindowMs / 1000}s`);
      }
      return null;
    },

    /** A successful login clears that IP's failure history. */
    clearFailedLogins: (orgId, ip) => failedLogins.reset(keyOf(orgId, ip)),

    /** Admin unblocked an IP — give it a clean slate. */
    clearAll: (orgId, ip) => all.forEach((w) => w.reset(keyOf(orgId, ip))),

    sweep() {
      all.forEach((w) => w.sweep());
      return store.purgeExpired();
    },
  };
}

module.exports = { SlidingWindow, createBruteForce };
