require('dotenv').config();
const express = require('express');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');

const authRoutes = require('./routes/auth');
const { createDashboardRouter } = require('./routes/dashboard');
const { attachSocket } = require('./socket');
const { loadConfig } = require('./waf/config');
const logStore = require('./store/logStore');
const rulesStore = require('./waf/rulesStore');
const { createPipeline } = require('./waf/pipeline');
const { createBruteForce } = require('./waf/bruteforce');
const { createWafApp } = require('./waf/proxy');

const USE_DB = process.env.USE_DB === 'true';
const config = loadConfig();
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || 'http://localhost:5173';
const PORT = process.env.PORT || 4000;

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.startsWith('replace_this')) {
  console.warn('[security] JWT_SECRET is not set to a real value — edit backend/.env before any real use.');
}

// ---------------------------------------------------------------
// Process 1 of 2 in this file: the DASHBOARD API  (:4000)
//   auth, REST, Socket.io  — what the React app talks to (Track C)
// ---------------------------------------------------------------
const app = express();
const server = http.createServer(app);

app.use(cors({ origin: CLIENT_ORIGIN, credentials: true }));
app.use(express.json());

const io = new Server(server, { cors: { origin: CLIENT_ORIGIN, credentials: true } });
attachSocket(io);

// Shared pipeline objects (Track B) used by BOTH servers.
const pipeline = createPipeline({ io, store: logStore });
const bruteforce = createBruteForce({
  store: logStore,
  config,
  onBlock: (orgId) => pipeline.blocksChanged(orgId),
});

app.get('/api/health', (req, res) => res.json({ ok: true, service: 'threatgate-api', db: USE_DB }));
app.use('/api/auth', authRoutes);
app.use('/api/dashboard', createDashboardRouter({ bruteforce, pipeline }));

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ---------------------------------------------------------------
// Process 2 of 2: the WAF REVERSE PROXY  (:8080)
//   client -> WAF -> protected app. Same process so the proxy can
//   push decisions straight into Socket.io with no message bus.
// ---------------------------------------------------------------
const wafApp = createWafApp({ config, pipeline, bruteforce, rulesStore });
const wafServer = http.createServer(wafApp);

async function start() {
  if (USE_DB) {
    try {
      const pool = require('./db/pool');
      await pool.query('SELECT 1');
      console.log('[db] MySQL connection OK');
      await rulesStore.loadFromDb(config.wafOrgId);
    } catch (err) {
      console.error('[db] Could not connect to MySQL:', err.message);
      console.error('Set USE_DB=false in backend/.env to run without a database.');
      process.exit(1);
    }
  } else {
    console.log('[db] USE_DB=false — running fully in memory (logs and blocks reset on restart).');
  }

  server.listen(PORT, () => console.log(`[api]  Dashboard API + Socket.io  -> http://localhost:${PORT}`));
  wafServer.listen(config.wafPort, () => {
    console.log(`[waf]  Reverse proxy listening     -> http://localhost:${config.wafPort}`);
    console.log(`[waf]  Protecting upstream          -> ${config.targetUrl}`);
    console.log(`[waf]  Block threshold: risk >= ${config.blockThreshold} | trust X-Forwarded-For: ${config.trustXff}`);
  });

  // Housekeeping: free expired blocks / idle counters. Correctness does
  // NOT depend on this — expiry is checked on every request.
  setInterval(() => bruteforce.sweep().then((n) => n && pipeline.blocksChanged(config.wafOrgId)).catch(() => {}), 30_000).unref();

  if (process.env.DEMO_MODE === 'true') {
    require('./mock/simulator').startSimulator(io, config.wafOrgId);
  }
}

start();
