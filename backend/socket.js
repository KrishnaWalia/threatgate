const jwt = require('jsonwebtoken');

/**
 * Wires Socket.io onto the existing HTTP server.
 *
 * Auth model: the client connects with `{ auth: { token } }` (the
 * same JWT it already has from /api/auth/login). We verify it in
 * the middleware below, BEFORE the connection is accepted, and
 * join the socket to a room named after its orgId. That's the
 * whole multi-tenancy story for real-time: Track B (or, for now,
 * the demo simulator) emits into `io.to('org:<id>')`, so a socket
 * only ever receives events for its own org, symmetric with how
 * the REST routes scope every query by orgId.
 */
function attachSocket(io) {
  io.use((socket, next) => {
    const token = socket.handshake.auth?.token;
    if (!token) return next(new Error('No token provided'));

    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      socket.user = payload;
      next();
    } catch (err) {
      next(new Error('Invalid or expired token'));
    }
  });

  io.on('connection', (socket) => {
    const room = `org:${socket.user.orgId}`;
    socket.join(room);
    console.log(`[socket] ${socket.user.email} connected -> ${room}`);

    socket.on('disconnect', () => {
      console.log(`[socket] ${socket.user.email} disconnected`);
    });
  });
}

/**
 * Called by whatever writes a new attack_logs row — Track B's real
 * pipeline in production, the demo simulator for now — so every
 * connected dashboard for that org gets the event instantly instead
 * of polling.
 */
function emitAttackLog(io, orgId, logRow) {
  io.to(`org:${orgId}`).emit('attack:new', logRow);
}

/** Emitted when a block is added or lifted, to refresh admin views live. */
function emitBlockedIpsChanged(io, orgId) {
  io.to(`org:${orgId}`).emit('blocked-ips:changed');
}

module.exports = { attachSocket, emitAttackLog, emitBlockedIpsChanged };
