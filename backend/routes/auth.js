const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const userStore = require('../store/userStore');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();
const BCRYPT_ROUNDS = 12;

/**
 * POST /api/auth/register
 * Creates a user inside an existing org. Public registration
 * always creates a "viewer" — nobody becomes admin by signing up
 * through this form; admins are promoted directly (in MySQL, or
 * in the in-memory store for now) — kept intentionally out of
 * scope here, but the field is there.
 *
 * Works identically whether userStore is backed by MySQL or the
 * in-memory demo store — see backend/store/userStore.js.
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
    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const user = await userStore.createUser({ email, passwordHash, orgId, role: 'viewer' });
    return res.status(201).json({ id: user.id, email: user.email, role: user.role, orgId: user.orgId });
  } catch (err) {
    if (err.message === 'DUPLICATE_EMAIL') {
      return res.status(409).json({ error: 'An account with that email already exists' });
    }
    console.error('register error:', err.message);
    return res.status(500).json({ error: 'Could not create account' });
  }
});

/**
 * POST /api/auth/login
 * -----------------------------------------------------------
 * How a token gets issued, step by step:
 *  1. Look the user up by email (in-memory store for now, MySQL
 *     once USE_DB=true — see backend/store/userStore.js).
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
    // Deliberately identical error for "no such user" and "wrong
    // password" — a different message for each would let an
    // attacker enumerate which emails have accounts.
    const genericError = () => res.status(401).json({ error: 'Invalid email or password' });

    const user = await userStore.getUserByEmail(email);
    if (!user) return genericError();

    const passwordMatches = await bcrypt.compare(password, user.passwordHash);
    if (!passwordMatches) return genericError();

    const payload = {
      id: user.id,
      orgId: user.orgId,
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
 * in localStorage — no extra store round trip needed beyond
 * verifying the signature, which requireAuth already did.
 */
router.get('/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

module.exports = router;
