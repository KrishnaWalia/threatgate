const express = require('express');
const { requireAuth, requireRole } = require('../middleware/auth');
const logStore = require('../store/logStore');
const rulesStore = require('../waf/rulesStore');

/**
 * Dashboard REST API (Track C reads, Track B's data).
 *
 * Built as a factory so the routes can reach the live brute-force
 * module and the Socket.io server — needed when an admin unblocks
 * an IP (clear its counters + tell other dashboards to refresh).
 *
 * Every route runs requireAuth first, and every query is scoped by
 * req.user.orgId (from the signed JWT) — org A never sees org B.
 * Works with or without MySQL: logStore picks memory vs DB by USE_DB.
 */
function createDashboardRouter({ bruteforce, pipeline }) {
  const router = express.Router();
  router.use(requireAuth);

  // GET /api/dashboard/logs?limit=50 — viewers and admins both
  router.get('/logs', async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
    try {
      res.json({ logs: await logStore.listLogs(req.user.orgId, limit) });
    } catch (err) {
      console.error('logs error:', err.message);
      res.status(500).json({ error: 'Could not load logs' });
    }
  });

  // GET /api/dashboard/stats — stat cards + charts
  router.get('/stats', async (req, res) => {
    try {
      res.json(await logStore.getStats(req.user.orgId));
    } catch (err) {
      console.error('stats error:', err.message);
      res.status(500).json({ error: 'Could not load stats' });
    }
  });

  // GET /api/dashboard/blocked-ips — ADMIN ONLY (real gate is here, not the hidden link)
  router.get('/blocked-ips', requireRole('admin'), async (req, res) => {
    try {
      res.json({ blockedIps: await logStore.listBlocked(req.user.orgId) });
    } catch (err) {
      console.error('blocked-ips error:', err.message);
      res.status(500).json({ error: 'Could not load blocked IPs' });
    }
  });

  // DELETE /api/dashboard/blocked-ips/:id — ADMIN ONLY: lift a block early
  router.delete('/blocked-ips/:id', requireRole('admin'), async (req, res) => {
    try {
      const removed = await logStore.removeBlock(req.user.orgId, req.params.id);
      if (!removed) return res.status(404).json({ error: 'Block not found' });
      bruteforce.clearAll(req.user.orgId, removed.ip_address);
      pipeline.blocksChanged(req.user.orgId);
      res.json({ ok: true });
    } catch (err) {
      console.error('unblock error:', err.message);
      res.status(500).json({ error: 'Could not remove block' });
    }
  });

  // GET /api/dashboard/rules — everyone can read the active ruleset
  router.get('/rules', (req, res) => res.json({ rules: rulesStore.list() }));

  // PATCH /api/dashboard/rules/:id — ADMIN ONLY: enable/disable or re-weight a rule.
  // Takes effect on the very next proxied request (rules are data).
  router.patch('/rules/:id', requireRole('admin'), async (req, res) => {
    try {
      const { is_active, weight } = req.body || {};
      const updated = await rulesStore.update(req.params.id, { is_active, weight }, req.user.orgId);
      if (!updated) return res.status(404).json({ error: 'Rule not found' });
      res.json({ rule: updated });
    } catch (err) {
      console.error('rule update error:', err.message);
      res.status(500).json({ error: 'Could not update rule' });
    }
  });

  return router;
}

module.exports = { createDashboardRouter };
