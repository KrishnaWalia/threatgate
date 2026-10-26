/**
 * REAL-TIME PIPELINE — Track B.
 *
 * Every request decision flows through record():
 *     decision --> INSERT into attack_logs --> emit 'attack:new'
 * The socket emit happens AFTER the write succeeds and carries the
 * row exactly as stored (id + created_at included), so the dashboard
 * never shows an event the database doesn't have. It goes to the
 * org's room only (see socket.js), so tenants never see each other.
 *
 * record() never throws: logging trouble must not take down the
 * proxy, so errors are reported and swallowed.
 */
const { emitAttackLog, emitBlockedIpsChanged } = require('../socket');

function createPipeline({ io, store }) {
  async function record(orgId, entry) {
    try {
      const row = await store.insertLog({ orgId, ...entry });
      emitAttackLog(io, orgId, row);
      return row;
    } catch (err) {
      console.error('[pipeline] could not log decision:', err.message);
      return null;
    }
  }

  return {
    record,
    blocksChanged: (orgId) => emitBlockedIpsChanged(io, orgId),
  };
}

module.exports = { createPipeline };
