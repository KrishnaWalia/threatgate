/**
 * rulesStore — where the detector gets its rules from.
 *
 *   USE_DB=false -> the DEFAULT_RULES array, held in memory.
 *   USE_DB=true  -> the `rules` table (falls back to defaults if the
 *                   org has no rows yet).
 *
 * Either way the detector only ever sees compiled rule objects, so
 * "rules as data" holds: an admin can toggle a rule from the
 * dashboard and the very next request is judged by the new set —
 * no restart, no code change.
 */
const { DEFAULT_RULES } = require('./rules');
const { compileRules } = require('./detector');

const USE_DB = process.env.USE_DB === 'true';

let rules = DEFAULT_RULES.map((r) => ({ ...r }));
let compiled = compileRules(rules);

function recompile() {
  compiled = compileRules(rules);
}

async function loadFromDb(orgId) {
  if (!USE_DB) return;
  const pool = require('../db/pool');
  const [rows] = await pool.query(
    'SELECT id, org_id, category, pattern, weight, is_active, description FROM rules WHERE org_id = ?',
    [orgId]
  );
  if (rows.length > 0) {
    rules = rows.map((r) => ({ ...r, is_active: !!r.is_active }));
    recompile();
    console.log(`[rules] loaded ${rows.length} rules from MySQL for org ${orgId}`);
  } else {
    console.log('[rules] no rules in MySQL for this org — using built-in defaults');
  }
}

function getCompiled() {
  return compiled;
}

function list() {
  return rules.map(({ id, category, pattern, weight, is_active, description }) => ({
    id, category, pattern, weight, is_active: !!is_active, description,
  }));
}

/** patch: { is_active?: boolean, weight?: 1..100 } */
async function update(id, patch, orgId) {
  const rule = rules.find((r) => r.id === Number(id));
  if (!rule) return null;
  if (typeof patch.is_active === 'boolean') rule.is_active = patch.is_active;
  if (Number.isInteger(patch.weight) && patch.weight >= 1 && patch.weight <= 100) {
    rule.weight = patch.weight;
  }
  recompile();
  if (USE_DB) {
    try {
      const pool = require('../db/pool');
      await pool.query('UPDATE rules SET is_active = ?, weight = ? WHERE id = ? AND org_id = ?', [
        rule.is_active, rule.weight, rule.id, orgId,
      ]);
    } catch (err) {
      console.error('[rules] DB write-through failed:', err.message);
    }
  }
  return list().find((r) => r.id === rule.id);
}

module.exports = { getCompiled, list, update, loadFromDb };
