const jwt = require('jsonwebtoken');

/**
 * requireAuth
 * ------------
 * Reads "Authorization: Bearer <token>", verifies the signature
 * and expiry with the server's JWT_SECRET, and — if valid —
 * attaches the decoded payload to req.user. Every route past this
 * point can trust req.user.id / req.user.role / req.user.orgId
 * without re-checking the database, because the signature already
 * proves the token wasn't tampered with after we issued it.
 *
 * This does NOT check what the user is allowed to do — that's
 * requireRole's job, deliberately kept separate so "are you who
 * you say you are" and "are you allowed to do this" don't get
 * tangled into one check.
 */
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Missing or malformed Authorization header' });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload; // { id, orgId, role, email, iat, exp }
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired, please log in again' });
    }
    return res.status(401).json({ error: 'Invalid token' });
  }
}

/**
 * requireRole(...allowedRoles)
 * -----------------------------
 * A role check is just: does req.user.role appear in the list of
 * roles this route allows? No lookups, no cleverness — the JWT
 * payload already carries the role, so this is an O(1) membership
 * check that runs on every protected admin route (e.g. unblocking
 * an IP, managing rules). Must run AFTER requireAuth, since it
 * reads req.user.
 */
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: `This action requires one of these roles: ${allowedRoles.join(', ')}`,
      });
    }
    next();
  };
}

module.exports = { requireAuth, requireRole };
