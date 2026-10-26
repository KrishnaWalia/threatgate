const test = require('node:test');
const assert = require('node:assert');
const { SlidingWindow, createBruteForce } = require('../waf/bruteforce');
const store = require('../store/logStore');
const { loadConfig } = require('../waf/config');

test('SlidingWindow counts only events inside the window', () => {
  const w = new SlidingWindow(1000);
  assert.strictEqual(w.hit('ip', 0), 1);
  assert.strictEqual(w.hit('ip', 400), 2);
  assert.strictEqual(w.hit('ip', 800), 3);
  assert.strictEqual(w.hit('ip', 1100), 3); // t=0 slid out, t=1100 joined
  assert.strictEqual(w.hit('ip', 2500), 1); // everything older than 1s is gone
});

test('SlidingWindow is not fooled by the fixed-window boundary trick', () => {
  const w = new SlidingWindow(60_000);
  for (let i = 0; i < 5; i++) w.hit('ip', 59_000 + i);       // 5 hits just before a minute boundary
  assert.strictEqual(w.hit('ip', 61_000), 6);                  // a fixed window would have reset to 1
});

test('SlidingWindow keys are independent; reset() clears one key', () => {
  const w = new SlidingWindow(1000);
  w.hit('a', 0); w.hit('a', 1);
  assert.strictEqual(w.hit('b', 2), 1);
  w.reset('a');
  assert.strictEqual(w.hit('a', 3), 1);
});

test('failed logins: blocks on the Nth failure, not before', async () => {
  const bf = createBruteForce({ store, config: { ...loadConfig({}), loginFailMax: 3, blockDurationMs: 60_000 } });
  assert.strictEqual(await bf.trackFailedLogin(1, '9.9.9.1'), null);
  assert.strictEqual(await bf.trackFailedLogin(1, '9.9.9.1'), null);
  const block = await bf.trackFailedLogin(1, '9.9.9.1');
  assert.ok(block && /Brute force/.test(block.reason));
  assert.ok(await bf.check(1, '9.9.9.1'), 'IP is blocked');
  assert.strictEqual(await bf.check(1, '9.9.9.2'), null, 'other IPs unaffected');
  assert.strictEqual(await bf.check(2, '9.9.9.1'), null, 'other orgs unaffected');
});

test('block expires on its own (lazy expiry) and counters start fresh', async () => {
  const bf = createBruteForce({ store, config: { ...loadConfig({}), loginFailMax: 2, blockDurationMs: 150 } });
  await bf.trackFailedLogin(1, '9.9.9.3');
  await bf.trackFailedLogin(1, '9.9.9.3');
  assert.ok(await bf.check(1, '9.9.9.3'), 'blocked right after');
  await new Promise((r) => setTimeout(r, 250));
  assert.strictEqual(await bf.check(1, '9.9.9.3'), null, 'expired -> allowed again');
  assert.strictEqual(await bf.trackFailedLogin(1, '9.9.9.3'), null, 'old failures were forgotten, one new failure does not re-block');
});

test('rate limit blocks the request AFTER the max', async () => {
  const bf = createBruteForce({ store, config: { ...loadConfig({}), rateLimitMax: 5, rateLimitWindowMs: 10_000 } });
  for (let i = 0; i < 5; i++) assert.strictEqual(await bf.trackRequest(1, '9.9.9.4'), null);
  assert.ok(await bf.trackRequest(1, '9.9.9.4'), '6th request in the window trips it');
});

test('a successful login clears the failure history', async () => {
  const bf = createBruteForce({ store, config: { ...loadConfig({}), loginFailMax: 3 } });
  await bf.trackFailedLogin(1, '9.9.9.5'); await bf.trackFailedLogin(1, '9.9.9.5');
  bf.clearFailedLogins(1, '9.9.9.5');
  assert.strictEqual(await bf.trackFailedLogin(1, '9.9.9.5'), null);
});

test('permanent block (durationMs null) never expires; purge keeps it', async () => {
  await store.addBlock({ orgId: 1, ip: '9.9.9.6', reason: 'manual', durationMs: null });
  await store.purgeExpired();
  assert.ok(await store.findActiveBlock(1, '9.9.9.6'));
});
