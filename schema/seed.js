/**
 * Seeds a demo org + one admin + one viewer user + a couple of
 * sample rules, so Track C can log in and demo without waiting
 * on Track A/B to populate real data.
 *
 * Run with:  node schema/seed.js
 * (reads DB creds from backend/.env)
 */
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

  await conn.query(
    `INSERT INTO rules (org_id, category, pattern, weight, description) VALUES
      (?, 'sqli', ?, 40, 'Classic UNION SELECT injection'),
      (?, 'xss',  ?, 30, 'Inline <script> tag injection'),
      (?, 'path_traversal', ?, 25, 'Directory traversal via ../')
    `,
    [
      orgId, "(\\%27)|(\\')|(--)|(%23)|(#)|(\\bUNION\\b.+\\bSELECT\\b)",
      orgId, "<\\s*script\\b[^>]*>",
      orgId, "(\\.\\./){2,}",
    ]
  );

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
