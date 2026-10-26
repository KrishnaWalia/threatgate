/**
 * logStore — attack_logs + blocked_ips storage, behind one interface.
 *
 *   USE_DB=false (default) -> in-memory arrays. No MySQL needed. Data
 *                             resets when the server restarts.
 *   USE_DB=true            -> the real tables from schema/schema.sql.
 *
 * Both implementations return rows in the SAME shape (snake_case, the
 * column names from the schema contract), so the Socket.io payload and
 * the REST responses are identical in either mode.
 *
 * Interface:
 *   insertLog(entry)            -> row
 *   listLogs(orgId, limit)      -> rows (newest first)
 *   getStats(orgId)             -> { totals..., byCategory, timeline }
 *   listBlocked(orgId)          -> active blocks only
 *   addBlock({orgId, ip, reason, durationMs|null}) -> row
 *   findActiveBlock(orgId, ip)  -> row | null   (expiry checked HERE)
 *   removeBlock(orgId, id)      -> removed row | null
 *   purgeExpired()              -> number removed
 */
const USE_DB = process.env.USE_DB === 'true';

// =====================================================================
// In-memory implementation
// =====================================================================
const MAX_MEMORY_LOGS = 5000;
let logs = [];            // newest at the END; we reverse on read
let blocks = [];
let nextLogId = 1;
let nextBlockId = 1;

const nowIso = () => new Date().toISOString();
const isActive = (b, now = Date.now()) => !b.expires_at || new Date(b.expires_at).getTime() > now;

async function memInsertLog(e) {
  const row = {
    id: nextLogId++,
    org_id: e.orgId,
    ip_address: e.ip,
    method: e.method,
    path: String(e.path).slice(0, 2048),
    category: e.category,
    risk_score: e.riskScore,
    action: e.action,
    matched_rule_id: e.matchedRuleId ?? null,
    user_agent: e.userAgent ? String(e.userAgent).slice(0, 512) : null,
    created_at: nowIso(),
  };
  logs.push(row);
  if (logs.length > MAX_MEMORY_LOGS) logs = logs.slice(-MAX_MEMORY_LOGS);
  return row;
}

async function memListLogs(orgId, limit) {
  const out = [];
  for (let i = logs.length - 1; i >= 0 && out.length < limit; i--) {
    if (logs[i].org_id === orgId) out.push(logs[i]);
  }
  return out;
}

async function memGetStats(orgId) {
  const now = Date.now();
  const mine = logs.filter((l) => l.org_id === orgId);
  const dayAgo = now - 24 * 3600_000;
  const hourAgo = now - 3600_000;

  const byCat = {};
  const buckets = {};
  let totalBlocked = 0;
  for (const l of mine) {
    const t = new Date(l.created_at).getTime();
    if (l.action === 'blocked') totalBlocked++;
    if (t >= dayAgo) byCat[l.category] = (byCat[l.category] || 0) + 1;
    if (t >= hourAgo) {
      const d = new Date(t);
      const key = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
      buckets[key] = buckets[key] || { bucket: key, blocked: 0, allowed: 0 };
      buckets[key][l.action]++;
    }
  }
  return {
    totalRequests: mine.length,
    totalBlocked,
    totalAllowed: mine.length - totalBlocked,
    activeBlockedIps: blocks.filter((b) => b.org_id === orgId && isActive(b, now)).length,
    byCategory: Object.entries(byCat).map(([category, count]) => ({ category, count })),
    timeline: Object.values(buckets).sort((a, b) => a.bucket.localeCompare(b.bucket)),
  };
}

async function memListBlocked(orgId) {
  const now = Date.now();
  return blocks
    .filter((b) => b.org_id === orgId && isActive(b, now))
    .sort((a, b) => b.blocked_at.localeCompare(a.blocked_at));
}

async function memAddBlock({ orgId, ip, reason, durationMs }) {
  // One row per (org, ip) — matches UNIQUE KEY uniq_org_ip in the schema.
  blocks = blocks.filter((b) => !(b.org_id === orgId && b.ip_address === ip));
  const row = {
    id: nextBlockId++,
    org_id: orgId,
    ip_address: ip,
    reason: reason || null,
    blocked_at: nowIso(),
    expires_at: durationMs ? new Date(Date.now() + durationMs).toISOString() : null,
  };
  blocks.push(row);
  return row;
}

async function memFindActiveBlock(orgId, ip) {
  const b = blocks.find((x) => x.org_id === orgId && x.ip_address === ip);
  if (!b) return null;
  if (!isActive(b)) {
    // Lazy expiry: the moment we SEE an expired block, we drop it.
    blocks = blocks.filter((x) => x !== b);
    return null;
  }
  return b;
}

async function memRemoveBlock(orgId, id) {
  const b = blocks.find((x) => x.org_id === orgId && x.id === Number(id));
  if (!b) return null;
  blocks = blocks.filter((x) => x !== b);
  return b;
}

async function memPurgeExpired() {
  const before = blocks.length;
  const now = Date.now();
  blocks = blocks.filter((b) => isActive(b, now));
  return before - blocks.length;
}

// =====================================================================
// MySQL implementation (USE_DB=true) — same queries as the schema contract
// =====================================================================
const pool = () => require('../db/pool');

async function dbInsertLog(e) {
  const [result] = await pool().query(
    `INSERT INTO attack_logs
       (org_id, ip_address, method, path, category, risk_score, action, matched_rule_id, user_agent)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [e.orgId, e.ip, e.method, String(e.path).slice(0, 2048), e.category, e.riskScore, e.action,
      e.matchedRuleId ?? null, e.userAgent ? String(e.userAgent).slice(0, 512) : null]
  );
  const [[row]] = await pool().query(
    `SELECT id, org_id, ip_address, method, path, category, risk_score, action, matched_rule_id, created_at
     FROM attack_logs WHERE id = ?`, [result.insertId]);
  return row;
}

async function dbListLogs(orgId, limit) {
  const [rows] = await pool().query(
    `SELECT id, ip_address, method, path, category, risk_score, action, created_at
     FROM attack_logs WHERE org_id = ? ORDER BY created_at DESC, id DESC LIMIT ?`,
    [orgId, limit]);
  return rows;
}

async function dbGetStats(orgId) {
  const [[totals]] = await pool().query(
    `SELECT COUNT(*) AS totalRequests, SUM(action = 'blocked') AS totalBlocked,
            SUM(action = 'allowed') AS totalAllowed
     FROM attack_logs WHERE org_id = ?`, [orgId]);
  const [byCategory] = await pool().query(
    `SELECT category, COUNT(*) AS count FROM attack_logs
     WHERE org_id = ? AND created_at >= NOW() - INTERVAL 24 HOUR GROUP BY category`, [orgId]);
  const [timeline] = await pool().query(
    `SELECT DATE_FORMAT(created_at, '%H:%i') AS bucket,
            SUM(action = 'blocked') AS blocked, SUM(action = 'allowed') AS allowed
     FROM attack_logs WHERE org_id = ? AND created_at >= NOW() - INTERVAL 1 HOUR
     GROUP BY bucket ORDER BY bucket ASC`, [orgId]);
  const [[active]] = await pool().query(
    `SELECT COUNT(*) AS count FROM blocked_ips
     WHERE org_id = ? AND (expires_at IS NULL OR expires_at > NOW())`, [orgId]);
  return {
    totalRequests: Number(totals.totalRequests) || 0,
    totalBlocked: Number(totals.totalBlocked) || 0,
    totalAllowed: Number(totals.totalAllowed) || 0,
    activeBlockedIps: Number(active.count) || 0,
    byCategory, timeline,
  };
}

async function dbListBlocked(orgId) {
  const [rows] = await pool().query(
    `SELECT id, ip_address, reason, blocked_at, expires_at FROM blocked_ips
     WHERE org_id = ? AND (expires_at IS NULL OR expires_at > NOW()) ORDER BY blocked_at DESC`, [orgId]);
  return rows;
}

async function dbAddBlock({ orgId, ip, reason, durationMs }) {
  const secs = durationMs ? Math.ceil(durationMs / 1000) : null;
  await pool().query(
    `INSERT INTO blocked_ips (org_id, ip_address, reason, expires_at)
     VALUES (?, ?, ?, IF(? IS NULL, NULL, DATE_ADD(NOW(), INTERVAL ? SECOND)))
     ON DUPLICATE KEY UPDATE reason = VALUES(reason), blocked_at = NOW(), expires_at = VALUES(expires_at)`,
    [orgId, ip, reason || null, secs, secs]);
  const [[row]] = await pool().query(
    'SELECT id, org_id, ip_address, reason, blocked_at, expires_at FROM blocked_ips WHERE org_id = ? AND ip_address = ?',
    [orgId, ip]);
  return row;
}

async function dbFindActiveBlock(orgId, ip) {
  const [rows] = await pool().query(
    `SELECT id, ip_address, reason, blocked_at, expires_at FROM blocked_ips
     WHERE org_id = ? AND ip_address = ? AND (expires_at IS NULL OR expires_at > NOW()) LIMIT 1`, [orgId, ip]);
  return rows[0] || null;
}

async function dbRemoveBlock(orgId, id) {
  const [[row]] = await pool().query('SELECT id, ip_address FROM blocked_ips WHERE id = ? AND org_id = ?', [id, orgId]);
  if (!row) return null;
  await pool().query('DELETE FROM blocked_ips WHERE id = ? AND org_id = ?', [id, orgId]);
  return row;
}

async function dbPurgeExpired() {
  const [r] = await pool().query('DELETE FROM blocked_ips WHERE expires_at IS NOT NULL AND expires_at <= NOW()');
  return r.affectedRows;
}

const impl = USE_DB
  ? { insertLog: dbInsertLog, listLogs: dbListLogs, getStats: dbGetStats, listBlocked: dbListBlocked,
      addBlock: dbAddBlock, findActiveBlock: dbFindActiveBlock, removeBlock: dbRemoveBlock, purgeExpired: dbPurgeExpired }
  : { insertLog: memInsertLog, listLogs: memListLogs, getStats: memGetStats, listBlocked: memListBlocked,
      addBlock: memAddBlock, findActiveBlock: memFindActiveBlock, removeBlock: memRemoveBlock, purgeExpired: memPurgeExpired };

module.exports = impl;
