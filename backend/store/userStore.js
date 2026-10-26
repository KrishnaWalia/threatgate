const bcrypt = require('bcrypt');

/**
 * userStore abstracts "where do users live" behind two
 * implementations, chosen by USE_DB in .env:
 *
 *   USE_DB=false (default for now) -> in-memory array, seeded
 *   with a demo admin + viewer at startup. Nothing touches MySQL.
 *   Great for building/demoing the landing page + auth flow before
 *   the database is wired up.
 *
 *   USE_DB=true -> reads/writes the real `users` table via the
 *   MySQL pool, exactly as it will work once Track A/B land.
 *
 * routes/auth.js only ever calls the functions below — it never
 * knows or cares which mode is active. That's the whole point:
 * flipping USE_DB later requires zero route changes.
 */

const USE_DB = process.env.USE_DB === 'true';

// ---------------------------------------------------------------
// In-memory implementation
// ---------------------------------------------------------------
let memoryUsers = [];
let nextId = 1;

function seedMemoryUsers() {
  const demoUsers = [
    { email: 'admin@threatgate.dev', password: 'Admin123!', role: 'admin' },
    { email: 'viewer@threatgate.dev', password: 'Viewer123!', role: 'viewer' },
  ];

  memoryUsers = demoUsers.map((u) => ({
    id: nextId++,
    orgId: 1,
    email: u.email,
    passwordHash: bcrypt.hashSync(u.password, 10),
    role: u.role,
  }));

  console.log('[store] USE_DB=false — using in-memory users. Demo logins:');
  demoUsers.forEach((u) => console.log(`  ${u.role.padEnd(6)} ${u.email} / ${u.password}`));
}

async function memoryGetUserByEmail(email) {
  return memoryUsers.find((u) => u.email === email) || null;
}

async function memoryCreateUser({ email, passwordHash, orgId, role = 'viewer' }) {
  if (memoryUsers.some((u) => u.email === email)) {
    const err = new Error('DUPLICATE_EMAIL');
    throw err;
  }
  const user = { id: nextId++, orgId, email, passwordHash, role };
  memoryUsers.push(user);
  return user;
}

// ---------------------------------------------------------------
// MySQL implementation (used once USE_DB=true)
// ---------------------------------------------------------------
async function dbGetUserByEmail(email) {
  const pool = require('../db/pool');
  const [rows] = await pool.query(
    'SELECT id, org_id AS orgId, email, password_hash AS passwordHash, role FROM users WHERE email = ?',
    [email]
  );
  return rows[0] || null;
}

async function dbCreateUser({ email, passwordHash, orgId, role = 'viewer' }) {
  const pool = require('../db/pool');
  const [existing] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
  if (existing.length > 0) {
    const err = new Error('DUPLICATE_EMAIL');
    throw err;
  }
  const [result] = await pool.query(
    'INSERT INTO users (org_id, email, password_hash, role) VALUES (?, ?, ?, ?)',
    [orgId, email, passwordHash, role]
  );
  return { id: result.insertId, orgId, email, passwordHash, role };
}

// ---------------------------------------------------------------
// Public API — same shape regardless of backing store
// ---------------------------------------------------------------
if (!USE_DB) seedMemoryUsers();

module.exports = {
  USE_DB,
  getUserByEmail: USE_DB ? dbGetUserByEmail : memoryGetUserByEmail,
  createUser: USE_DB ? dbCreateUser : memoryCreateUser,
};
