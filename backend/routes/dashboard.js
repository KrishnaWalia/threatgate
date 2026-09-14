const express = require('express');
const { requireAuth, requireRole } = require('../middleware/auth');

const router = express.Router();
const USE_DB = process.env.USE_DB === 'true';

// Every route below runs requireAuth first, and every query is
// scoped by req.user.orgId — this is what stops org A's viewer
// from ever seeing org B's traffic, regardless of role.
router.use(requireAuth);

/**
 * These routes all read attack_logs / blocked_ips, which don't
 * exist until MySQL is wired up (USE_DB=true in .env). Rather than
 * let `require('../db/pool')` crash the process at startup with no
 * DB present, we only load the pool lazily and return a clear 503
 * here instead — so the landing page, login, and auth flow work
 * completely on their own before the database is ready.
 */
router.use((req, res, next) => {
  if (!USE_DB) {
    return res.status(503).json({
      error: 'Dashboard data requires a database connection. Set USE_DB=true in backend/.env once MySQL is set up (see schema/schema.sql).',
    });
  }
  next();
});

function getPool() {
  return require('../db/pool');
}

/**
 * GET /api/dashboard/logs?limit=50
 * Most recent attack_logs rows for this org. Viewers and admins
 * both get this — reading the feed doesn't require elevated
 * privilege, only acting on it does.
 */
router.get('/logs', async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
  try {
    const [rows] = await getPool().query(
      `SELECT id, ip_address, method, path, category, risk_score, action, created_at
       FROM attack_logs
       WHERE org_id = ?
       ORDER BY created_at DESC, id DESC
       LIMIT ?`,
      [req.user.orgId, limit]
    );
    res.json({ logs: rows });
  } catch (err) {
    console.error('logs error:', err.message);
    res.status(500).json({ error: 'Could not load logs' });
  }
});

/**
 * GET /api/dashboard/stats
 * Aggregates for the top stat cards + charts: totals, a
 * blocked-vs-allowed split, and a breakdown by attack category
 * over the last 24 hours.
 */
router.get('/stats', async (req, res) => {
  try {
    const [[totals]] = await getPool().query(
      `SELECT
         COUNT(*) AS totalRequests,
         SUM(action = 'blocked') AS totalBlocked,
         SUM(action = 'allowed') AS totalAllowed
       FROM attack_logs WHERE org_id = ?`,
      [req.user.orgId]
    );

    const [byCategory] = await getPool().query(
      `SELECT category, COUNT(*) AS count
       FROM attack_logs
       WHERE org_id = ? AND created_at >= NOW() - INTERVAL 24 HOUR
       GROUP BY category`,
      [req.user.orgId]
    );

    const [timeline] = await getPool().query(
      `SELECT DATE_FORMAT(created_at, '%H:%i') AS bucket,
              SUM(action = 'blocked') AS blocked,
              SUM(action = 'allowed') AS allowed
       FROM attack_logs
       WHERE org_id = ? AND created_at >= NOW() - INTERVAL 1 HOUR
       GROUP BY bucket
       ORDER BY bucket ASC`,
      [req.user.orgId]
    );

    const [[activeBlocks]] = await getPool().query(
      `SELECT COUNT(*) AS count FROM blocked_ips
       WHERE org_id = ? AND (expires_at IS NULL OR expires_at > NOW())`,
      [req.user.orgId]
    );

    res.json({
      totalRequests: Number(totals.totalRequests) || 0,
      totalBlocked: Number(totals.totalBlocked) || 0,
      totalAllowed: Number(totals.totalAllowed) || 0,
      activeBlockedIps: Number(activeBlocks.count) || 0,
      byCategory,
      timeline,
    });
  } catch (err) {
    console.error('stats error:', err.message);
    res.status(500).json({ error: 'Could not load stats' });
  }
});

/**
 * GET /api/dashboard/blocked-ips
 * Admin-only: the current block list. Viewers don't get this
 * endpoint at all (403), not just a hidden button in the UI —
 * the frontend hiding a button is a UX nicety, not a security
 * boundary, so the real check lives here in the middleware.
 */
router.get('/blocked-ips', requireRole('admin'), async (req, res) => {
  try {
    const [rows] = await getPool().query(
      `SELECT id, ip_address, reason, blocked_at, expires_at
       FROM blocked_ips
       WHERE org_id = ?
       ORDER BY blocked_at DESC`,
      [req.user.orgId]
    );
    res.json({ blockedIps: rows });
  } catch (err) {
    console.error('blocked-ips error:', err.message);
    res.status(500).json({ error: 'Could not load blocked IPs' });
  }
});

/**
 * DELETE /api/dashboard/blocked-ips/:id
 * Admin-only: manually lift a block early. This is the clearest
 * example in Track C of a role check gating a real action instead
 * of just a read — a viewer hitting this route gets a 403 even if
 * they craft the request by hand.
 */
router.delete('/blocked-ips/:id', requireRole('admin'), async (req, res) => {
  try {
    const [result] = await getPool().query(
      'DELETE FROM blocked_ips WHERE id = ? AND org_id = ?',
      [req.params.id, req.user.orgId]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Block not found' });
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('unblock error:', err.message);
    res.status(500).json({ error: 'Could not remove block' });
  }
});

module.exports = router;
