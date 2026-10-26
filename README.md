# ThreatGate — Reverse-Proxy Web Application Firewall

ThreatGate sits in front of a website, inspects every request, and blocks **SQL injection, XSS, path traversal and brute-force** attacks in real time — with a live dashboard that updates the instant something happens.

```
                         ┌────────────────────── ThreatGate backend (Node) ───────────────────────┐
  attacker / user ──►    │  :8080  WAF PROXY (Track A)            :4000  DASHBOARD API (Track C)   │
  http://localhost:8080  │   IP block? → rate limit? → inspect     JWT login · roles · REST        │
                         │   → risk score → 403 or forward         Socket.io (per-org rooms)       │
                         │            │                                     ▲                      │
                         │            ▼   every decision                     │ 'attack:new'         │
                         │     PIPELINE (Track B): store.insertLog() ───────┘                       │
                         │     BRUTE-FORCE (Track B): sliding windows → auto-block with expiry      │
                         └───────┬──────────────────────────────────────────────────▲──────────────┘
                                 │ clean requests                                   │ websocket + REST
                                 ▼                                                  │
                      :3000 protected demo site                          :5173 React dashboard (Track C)
```

## Run it (3 commands)

Requires **Node 18+**. No database needed — everything runs in memory by default.

```bash
npm run setup      # installs root + backend + frontend dependencies (once)
npm run dev        # starts demo site :3000, WAF :8080, API :4000, dashboard :5173
```

Then:

1. Open **http://localhost:5173** → *Sign in* → `admin@threatgate.dev` / `Admin123!`  (viewer: `viewer@threatgate.dev` / `Viewer123!`)
2. In another terminal, fire attacks through the WAF: `npm run attack` — watch the dashboard fill **live**.
3. Or attack by hand through the proxy (**:8080**, not :3000):
   ```bash
   curl "http://localhost:8080/search?q=hello"                            # 200 allowed
   curl "http://localhost:8080/api/users?id=1' OR '1'='1"                 # 403 SQLi
   curl "http://localhost:8080/search?q=<script>alert(1)</script>"        # 403 XSS
   curl "http://localhost:8080/files?name=../../../etc/passwd"            # 403 path traversal
   ```
   You can also browse the protected site at http://localhost:8080 and type attacks into its search box / login form.

`./run.sh` does the same as `npm run dev` without the root `npm install`.

### Checks

| Command | What it proves |
|---|---|
| `npm test` | 49 unit tests: every attack form is blocked, benign look-alikes (e.g. `O'Brien`) are allowed, scoring formula, sliding window, block expiry |
| `npm run attack` | Integration: normal → allowed, SQLi/XSS/traversal → 403, brute-force → 401…401 then auto-block, repeated attacks → auto-block. Exits 1 if any expectation fails |
| `npm run verify` | End-to-end across all tracks: JWT auth, socket auth, proxy→log→**Socket.io push**, REST stats, admin-vs-viewer 403s, unblock flow, toggling a rule live |

(`attack` and `verify` need the stack running.)

## What's where

```
backend/
  server.js               wires everything: API (:4000) + WAF (:8080) share one pipeline + one Socket.io
  waf/                    ── TRACK A (+B) ──
    rules.js                the 22 detection rules, as data  (id, category, pattern, weight, description)
    rulesStore.js           serves rules to the detector; admin can toggle/re-weight live
    detector.js             normalise → match → risk score (formula documented at top of file)
    proxy.js                the reverse proxy + request lifecycle (http-proxy-middleware)
    bruteforce.js           ── TRACK B ── sliding windows, auto-block + expiry
    pipeline.js             ── TRACK B ── log every decision, then emit over Socket.io
    config.js               every threshold, from .env
  store/logStore.js       attack_logs + blocked_ips (memory now, MySQL when USE_DB=true; same interface)
  store/userStore.js      users (memory / MySQL)                                  ── TRACK C ──
  middleware/auth.js      requireAuth (JWT verify) + requireRole                  ── TRACK C ──
  routes/auth.js          register / login / me                                   ── TRACK C ──
  routes/dashboard.js     logs, stats, blocked-ips, rules                         ── TRACK C ──
  socket.js               socket JWT auth, per-org rooms, emit helpers
  demo-target/server.js   the fake website being protected
  test/ scripts/          unit tests, attack demo, e2e verification
frontend/                 React + Vite + Tailwind + Recharts: Landing, Login, Dashboard, Detection Rules, Blocked IPs
schema/schema.sql         the shared MySQL contract (orgs, users, rules, attack_logs, blocked_ips)
```

## Track A — how detection works (be ready to explain this)

**Request lifecycle** (`waf/proxy.js`), cheap checks first so a flood never reaches the regex engine:
`client IP → already blocked? (403) → rate limit? (429 + block) → read body (capped) → detector → risk ≥ 50? (403) → log → forward upstream`.

**Normalisation** (`detector.normalize`) — attackers encode payloads, so we decode *before* matching: percent-encoding up to **3 rounds** (`%252e%252e%252f` is double-encoded `../`), `+`→space, `%uXXXX`, `\uXXXX`, HTML entities (`&#60;script`), then replace SQL comments with a space (`UNION/**/SELECT` → `UNION SELECT`) and collapse whitespace. Inspected: path, query string, body, `User-Agent`, `Referer`, `Cookie`.

**Scoring formula** — each rule has a weight (1–100):

```
risk = min(100,  W_max + 0.5 × Σ(weights of the other distinct matched rules))
```

The strongest signal sets the floor (a `UNION SELECT` = 80 blocks alone); other, different rules corroborate at half weight (two weak 40-point signals → 40 + 20 = 60 → blocked); a rule counts once however often it matches, so repeating a payload can't inflate the score. **Blocked when risk ≥ `BLOCK_THRESHOLD` (50).**

**The rules** (`waf/rules.js`) — each has a plain-English description; the key ones:

| Category | Rules (weight) | Idea |
|---|---|---|
| SQLi | `UNION…SELECT` (80) · `' OR '1'='1` (75) · `OR 1=1` (70) · `'--` (60) · `; DROP TABLE` (85) · `SLEEP()/BENCHMARK()` (80) · `information_schema` (70) · `extractvalue/load_file` (75) · `SELECT…FROM` (40, weak) | Break out of a string or number, force TRUE, cut off the rest of the query, stack a second statement, or probe the schema |
| XSS | `<script` (80) · `onerror=` etc. (65) · `javascript:` (70) · `<iframe/object/embed` (60) · `data:text/html` (60) · `document.cookie` (60) · `alert(`/`eval(` (40, weak) | Get script to run in a victim's browser |
| Path traversal | `../` (55) · `../../` (80) · `/etc/passwd`, `win.ini` (85) · `/.env`, `/.git/` (70) · null byte (55) · `file://`, `php://` (60) | Climb out of the web root and read files |

Weak rules (< 50) deliberately can't block alone — that is how `select the best items from our store` stays allowed (false-positive control).

**Rules are data**: the detector contains no regex. Admins can switch rules on/off or re-weight them on the *Detection Rules* page and the next request is judged by the new set (`PATCH /api/dashboard/rules/:id`).

## Track B — brute force, logging, real time

**Pipeline** (`waf/pipeline.js`): every decision (allowed *and* blocked) is written with `store.insertLog()`, and only after the write succeeds the stored row is emitted as `attack:new` to the org's Socket.io room. The dashboard therefore never shows an event the log doesn't have.

**Three counters**, all the same `SlidingWindow` (`waf/bruteforce.js`):

| Counter | Default | Trips on |
|---|---|---|
| Failed logins | 5 / 60 s | a 401/403 *response* from a path matching `LOGIN_PATH_REGEX` |
| Request rate | 100 / 10 s | any request (flood / scraping) |
| Attack strikes | 8 / 60 s | requests the detector itself blocked |

**Counting window:** per IP we keep the timestamps of its events. On each new event: drop timestamps older than `now − window`, push `now`, count = list length. It is a *sliding* window, so an attacker can't fire 5 attempts at 0:59 and 5 more at 1:01 — a fixed "reset every minute" counter would see 5 and 5, the sliding window sees 10. (Unit-tested.) A successful login clears that IP's failures.

**Expiry:** a block is a record `{ip, blocked_at, expires_at = now + BLOCK_DURATION}` (default 5 min; `NULL` = permanent). Expiry is checked **lazily** — `findActiveBlock()` compares `expires_at` with the current time on every request from that IP — so correctness never depends on a timer firing. A 30-second sweep only frees memory. When a block is created the IP's counters reset, so when it expires it starts from zero instead of being instantly re-blocked by stale history. An admin can lift a block early from the dashboard.

## Track C — auth & dashboard

1. **Issue** (`POST /api/auth/login`): look up the user, `bcrypt.compare()` (re-hashes the candidate with the salt inside the stored hash — nothing is "decrypted"), same error for unknown-user and wrong-password. On success sign a JWT `{id, orgId, email, role}` with `JWT_SECRET`.
2. **Verify** (`requireAuth`): parse `Authorization: Bearer …`, `jwt.verify` checks signature and expiry, and puts the payload in `req.user` — no DB lookup needed, the signature proves we issued it.
3. **Role check** (`requireRole('admin')`): after `requireAuth`, is `req.user.role` in the allowed list? That's all. "Who are you?" and "may you do this?" are two separate middlewares. The hidden sidebar link is cosmetic; the 403 from the API is the real gate. The same JWT authenticates the Socket.io handshake and puts the socket in its org's room, so tenants never see each other's events; every query is also scoped by `req.user.orgId`.

| | admin | viewer |
|---|---|---|
| Live feed, stats, charts, rules (read) | ✔ | ✔ |
| Blocked IPs list / unblock | ✔ | 403 |
| Toggle / re-weight rules | ✔ | 403 |

## The shared schema (`schema/schema.sql`)

`orgs` (tenant) · `users` (login + `role` enum) · `rules` (regex, weight, category, `is_active`) · `attack_logs` (one row per decision) · `blocked_ips` (`expires_at`, unique per org+ip). The in-memory stores use **exactly these column names**, so turning MySQL on changes nothing for the other tracks.

### Turning MySQL on later (optional)

```bash
mysql -u root -p < schema/schema.sql
# backend/.env:  USE_DB=true  + DB_HOST / DB_USER / DB_PASSWORD / DB_NAME
cd backend && npm run seed     # org, admin/viewer users, all 22 rules
```
Note: the MySQL code paths follow the schema but were **not exercised in the build environment** (no MySQL there) — treat them as untested until you run them once.

## Configuration

Everything is in `backend/.env` (see `.env.example` for comments): ports, `BLOCK_THRESHOLD`, brute-force limits/windows, `BLOCK_DURATION_MS`, `TARGET_URL` (point it at your own app to protect it), `USE_DB`.

**Security notes**
- `TRUST_XFF=true` makes the WAF believe the `X-Forwarded-For` header so the demo can pretend to be many IPs. **In real use set it to `false`** (or anyone can spoof their IP and dodge blocks).
- The shipped `.env` contains a random dev `JWT_SECRET`; generate your own for anything real.
- The in-memory demo users and `/api/auth/register` are for the demo; public registration always creates a `viewer`.
- This is a teaching-grade regex WAF: it stops common payload patterns, not a determined attacker with novel encodings.

## Troubleshooting

- **Port in use** → change `PORT` / `WAF_PORT` in `backend/.env` (and `TARGET_PORT` for the demo site).
- **Login works but dashboard says it can't reach the API** → backend not running; use `npm run dev` from the project root.
- **`npm run attack` says it can't reach the WAF** → start the stack first.
- **I got blocked testing by hand** → `TRUST_XFF=true` means your IP is `127.0.0.1`; unblock it on the *Blocked IPs* page, or wait 5 minutes, or restart (memory mode).
- **bcrypt fails to install** → needs Node 18+ and either a prebuilt binary or build tools (`python3`, `make`, `g++`).
