const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('../db/pool');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();
const BCRYPT_ROUNDS = 12;

/**
 * POST /api/auth/register
 * Creates a user inside an existing org. Public registration
 * always creates a "viewer" — nobody becomes admin by signing up
 * through this form; admins are promoted directly in MySQL or by
 * another admin (kept intentionally out of scope for a hackathon
 * demo, but the column is there — see schema.sql).
 */
router.post('/register', async (req, res) => {
  const { email, password, orgId } = req.body;

  if (!email || !password || !orgId) {
    return res.status(400).json({ error: 'email, password, and orgId are required' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  try {
    const [existing] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
    if (existing.length > 0) {
      return res.status(409).json({ error: 'An account with that email already exists' });
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    const [result] = await pool.query(
      `INSERT INTO users (org_id, email, password_hash, role) VALUES (?, ?, ?, 'viewer')`,
      [orgId, email, passwordHash]
    );

    return res.status(201).json({ id: result.insertId, email, role: 'viewer', orgId });
  } catch (err) {
    console.error('register error:', err.message);
    return res.status(500).json({ error: 'Could not create account' });
  }
});

/**
 * POST /api/auth/login
 * -----------------------------------------------------------
 * How a token gets issued, step by step:
 *  1. Look the user up by email.
 *  2. bcrypt.compare() the submitted password against the stored
 *     hash. bcrypt never lets you "decrypt" the hash — compare()
 *     re-hashes the candidate with the same salt baked into the
 *     stored hash and checks the two hashes match.
 *  3. If it matches, sign a JWT whose payload carries exactly what
 *     downstream middleware needs (id, orgId, role, email) and
 *     nothing sensitive like the password hash.
 *  4. Send the token back. The frontend stores it and attaches it
 *     as "Authorization: Bearer <token>" on every future request.
 * -----------------------------------------------------------
 */
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }

  try {
    const [rows] = await pool.query(
      'SELECT id, org_id, email, password_hash, role FROM users WHERE email = ?',
      [email]
    );

    // Deliberately identical error for "no such user" and "wrong
    // password" — a different message for each would let an
    // attacker enumerate which emails have accounts.
    const genericError = () => res.status(401).json({ error: 'Invalid email or password' });

    if (rows.length === 0) return genericError();

    const user = rows[0];
    const passwordMatches = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatches) return genericError();

    const payload = {
      id: user.id,
      orgId: user.org_id,
      email: user.email,
      role: user.role,
    };

    const token = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN || '8h',
    });

    return res.json({ token, user: payload });
  } catch (err) {
    console.error('login error:', err.message);
    return res.status(500).json({ error: 'Login failed' });
  }
});

/**
 * GET /api/auth/me
 * Lets the frontend restore session state (who am I, what's my
 * role) after a page refresh, using only the token it already has
 * in localStorage — no extra DB round trip needed beyond verifying
 * the signature, which requireAuth already did.
 */
router.get('/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

module.exports = router;
