/**
 * Seeds a demo org + one admin + one viewer user + a couple of
 * sample rules, so Track C can log in and demo without waiting
 * on Track A/B to populate real data.
 *
 * Run with:  node schema/seed.js
 * (reads DB creds from backend/.env)
 */
// This file lives in schema/, but its dependencies are installed in backend/.
module.paths.unshift(require('path').join(__dirname, '..', 'backend', 'node_modules'));
require('dotenv').config({ path: require('path').join(__dirname, '..', 'backend', '.env') });
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');

const ADMIN_EMAIL = 'admin@threatgate.dev';
const ADMIN_PASSWORD = 'Admin123!';
const VIEWER_EMAIL = 'viewer@threatgate.dev';
const VIEWER_PASSWORD = 'Viewer123!';

async function main() {
  const conn = await mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'threatgate',
    multipleStatements: true,
  });

  const [orgRows] = await conn.query(
    `INSERT INTO orgs (name) VALUES ('Demo Org')`
  );
  const orgId = orgRows.insertId;

  const adminHash = await bcrypt.hash(ADMIN_PASSWORD, 12);
  const viewerHash = await bcrypt.hash(VIEWER_PASSWORD, 12);

  await conn.query(
    `INSERT INTO users (org_id, email, password_hash, role) VALUES (?, ?, ?, 'admin'), (?, ?, ?, 'viewer')`,
    [orgId, ADMIN_EMAIL, adminHash, orgId, VIEWER_EMAIL, viewerHash]
  );

  // Insert the full built-in ruleset (same rules the in-memory mode uses),
  // so the DB-backed WAF behaves identically to the demo mode.
  const { DEFAULT_RULES } = require('../backend/waf/rules');
  for (const r of DEFAULT_RULES) {
    await conn.query(
      'INSERT INTO rules (org_id, category, pattern, weight, is_active, description) VALUES (?, ?, ?, ?, TRUE, ?)',
      [orgId, r.category, r.pattern, r.weight, r.description]
    );
  }

  console.log('Seed complete.');
  console.log(`  Org: Demo Org (id=${orgId})`);
  console.log(`  Admin login:  ${ADMIN_EMAIL} / ${ADMIN_PASSWORD}`);
  console.log(`  Viewer login: ${VIEWER_EMAIL} / ${VIEWER_PASSWORD}`);
  await conn.end();
}

main().catch((err) => {
  console.error('Seed failed:', err.message);
  process.exit(1);
});
