require('dotenv').config();
const express = require('express');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');

const authRoutes = require('./routes/auth');
const dashboardRoutes = require('./routes/dashboard');
const { attachSocket } = require('./socket');

const USE_DB = process.env.USE_DB === 'true';

const app = express();
const server = http.createServer(app);

const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || 'http://localhost:5173';

app.use(cors({ origin: CLIENT_ORIGIN, credentials: true }));
app.use(express.json());

app.get('/api/health', (req, res) => res.json({ ok: true, service: 'threatgate-track-c' }));

app.use('/api/auth', authRoutes);
app.use('/api/dashboard', dashboardRoutes);

// Central error handler — anything a route forgot to catch lands
// here instead of leaking a stack trace to the client.
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

const io = new Server(server, {
  cors: { origin: CLIENT_ORIGIN, credentials: true },
});
attachSocket(io);

const PORT = process.env.PORT || 4000;

async function start() {
  if (USE_DB) {
    // Fail fast and loud if MySQL isn't reachable, instead of the
    // server "starting" and every route silently 500ing.
    try {
      const pool = require('./db/pool');
      await pool.query('SELECT 1');
      console.log('[db] MySQL connection OK');
    } catch (err) {
      console.error('[db] Could not connect to MySQL:', err.message);
      console.error('Check backend/.env DB_* values and that MySQL is running, then re-run schema/schema.sql.');
      process.exit(1);
    }
  } else {
    console.log('[db] USE_DB=false — skipping MySQL entirely. Auth runs on the in-memory user store.');
    console.log('[db] Dashboard routes (/api/dashboard/*) will return 503 until USE_DB=true.');
  }

  server.listen(PORT, () => {
    console.log(`[server] ThreatGate Track C listening on http://localhost:${PORT}`);
  });

  // The demo simulator writes to attack_logs, so it only makes
  // sense — and is only require()'d — once a real database is
  // wired up. It's independent of DEMO_MODE=true so USE_DB=false
  // deployments never touch MySQL at all, even accidentally.
  if (USE_DB && process.env.DEMO_MODE === 'true') {
    // Demo mode fakes org_id=1 (the seed script's Demo Org) so a
    // freshly-seeded database "just works" for a presentation
    // without any extra config.
    const { startSimulator } = require('./mock/simulator');
    startSimulator(io, 1);
  }
}

start();
