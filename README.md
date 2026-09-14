# ThreatGate — Track C: Dashboard & Auth

This is the Track C deliverable: a React dashboard with live traffic
streaming, plus JWT + bcrypt auth with role-based access control
(admin vs. viewer). It runs **standalone**, ahead of Track A (proxy
+ detection) and Track B (real-time pipeline + brute-force logic),
using a demo simulator that writes to the exact same `attack_logs`
table real traffic will use — so nothing in the frontend changes
when the other two tracks are wired in.

## What's in this zip

```
threatgate-track-c/
├── package.json         # root convenience scripts (run both apps at once)
├── run.sh               # bash alternative to the root package.json
├── schema/
│   ├── schema.sql       # shared MySQL contract — orgs, users, rules, attack_logs, blocked_ips
│   └── seed.js          # creates a demo org + admin/viewer login + sample rules
├── backend/             # Express API + Socket.io gateway (the Track C server)
│   ├── server.js
│   ├── db/pool.js
│   ├── store/userStore.js      # in-memory OR MySQL user store, picked by USE_DB
│   ├── middleware/auth.js     # JWT verification + role check
│   ├── routes/auth.js         # register / login / me
│   ├── routes/dashboard.js    # logs, stats, blocked-ips (admin-gated, needs USE_DB=true)
│   ├── socket.js               # Socket.io auth + emit helpers
│   ├── mock/simulator.js       # DEMO-ONLY fake traffic generator (needs USE_DB=true)
│   └── .env.example
└── frontend/             # React (Vite) dashboard
    └── src/
        ├── pages/Landing.jsx      # public landing page at "/"
        ├── pages/Login.jsx
        ├── pages/Dashboard.jsx
        ├── pages/BlockedIps.jsx   # admin-only
        ├── components/            # Sidebar, StatCard, LiveFeed, CategoryChart, TimelineChart
        ├── context/AuthContext.jsx
        └── api/                   # http.js (axios + interceptors), socket.js
```

## Run everything at once

Instead of starting the backend and frontend in two terminals, use
the root scripts (they just wrap the two `npm run dev`s):

```bash
npm install           # installs concurrently at the root, once
npm run install:all    # installs backend/ and frontend/ deps, once
cp backend/.env.example backend/.env   # edit JWT_SECRET at least
npm run dev             # starts backend (:4000) + frontend (:5173) together
```

Output from both is interleaved in one terminal, prefixed
`[backend]` / `[frontend]`. `Ctrl+C` stops both.

Prefer not to add a root `package.json` layer? `run.sh` does the
same thing with plain bash — no root `npm install` needed, just the
two `backend`/`frontend` installs:

```bash
chmod +x run.sh   # first time only
./run.sh
```

Either way this starts Stage 1 (no database, in-memory auth) by
default — see below for turning the database on.

## Quick start — Stage 1: landing page + login, no database

This is the mode `.env.example` ships with (`USE_DB=false`). No
MySQL server needed at all — auth runs on an in-memory user store
seeded with the demo admin/viewer accounts, so you can build and
present the landing page + login system before the database exists.

**Prerequisites:** Node 18+. That's it.

```bash
cd backend
cp .env.example .env
# edit .env: set JWT_SECRET to any long random string
npm install
npm run dev        # http://localhost:4000, logs "USE_DB=false — using in-memory users"
```

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173
```

Visit `http://localhost:5173` → landing page → **Sign in** → login
form. Demo logins (printed by the backend on startup too):
- **Admin:** `admin@threatgate.dev` / `Admin123!`
- **Viewer:** `viewer@threatgate.dev` / `Viewer123!`

Login, token issuance/verification, and role info all work fully
in this mode. Once logged in you'll land on `/dashboard`, which
will show a "Dashboard data requires a database connection" notice
(a 503 from `/api/dashboard/*`) — expected, since there's no
`attack_logs`/`blocked_ips` data yet. That's Stage 2.

## Quick start — Stage 2: turn the database on

When you're ready to wire up MySQL (for the full presentation, or
once Track A/B are ready to integrate):

### 1. Create the database

```bash
mysql -u root -p < schema/schema.sql
```

### 2. Flip the flag and configure DB credentials

In `backend/.env`, set:

```
USE_DB=true
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=threatgate
```

### 3. Seed and restart

```bash
cd backend
npm run seed      # creates Demo Org + admin/viewer logins + sample rules in MySQL
npm run dev        # now connects to MySQL and (with DEMO_MODE=true) starts the demo simulator
```

Nothing changes on the frontend or in how you log in — `userStore`
(see `backend/store/userStore.js`) transparently switches from the
in-memory array to real MySQL queries based on `USE_DB`, and the
dashboard routes go from 503 to actually returning data. With
`DEMO_MODE=true`, the backend also starts inserting a fake attack
log every ~2.5s and pushing it over Socket.io, so the live feed and
charts are populated immediately without waiting on Track A/B.

Only the admin account sees "Blocked IPs" in the sidebar and can
hit that route at all — a viewer gets a 403 from the API even if
they type the URL directly.

## How auth actually works here

1. **Login** (`POST /api/auth/login`): look up the user by email,
   run `bcrypt.compare(password, storedHash)`. bcrypt never
   "decrypts" — it re-hashes the candidate with the salt embedded
   in the stored hash and compares the two hashes. Same error
   message for "no such user" and "wrong password", so the API
   can't be used to enumerate valid emails.
2. **Token issuance**: on a match, sign a JWT (`jsonwebtoken`)
   whose payload is `{ id, orgId, email, role }` — never the
   password hash — and return it to the client.
3. **Storage**: the frontend keeps the token in `localStorage` and
   attaches it as `Authorization: Bearer <token>` on every request
   (see `frontend/src/api/http.js`), and in the Socket.io handshake
   (`frontend/src/api/socket.js`).
4. **Verification** (`backend/middleware/auth.js` → `requireAuth`):
   every protected route verifies the signature and expiry with
   the server's `JWT_SECRET`. If it checks out, `req.user` is the
   decoded payload — no DB round-trip needed to know who's asking.
5. **Role check** (`requireRole('admin')`): a plain membership
   check against `req.user.role`. It's deliberately separate from
   `requireAuth` — "are you who you say you are" and "are you
   allowed to do this" are two different questions. The dashboard
   also scopes every query by `req.user.orgId`, so role alone
   doesn't leak another org's data.

The frontend hiding the "Blocked IPs" link for viewers is a UX
nicety only — `routes/dashboard.js` enforces the real boundary
with `requireRole('admin')` on both the read and the unblock
action, so a viewer can't get at it by guessing the URL or calling
the API directly.

## The schema contract (shared with Track A & B)

`schema/schema.sql` is authoritative — see the comments in that
file for what each table is for and why. Short version:

| Table | Owner-in-practice | What it's for |
|---|---|---|
| `orgs` | shared | tenant boundary — everything else hangs off `org_id` |
| `users` | Track C | login + `role` enum (`admin`/`viewer`) |
| `rules` | Track A | the rules-as-data engine (regex, weight, category) |
| `attack_logs` | Track B writes, Track C reads | one row per request decision |
| `blocked_ips` | Track B writes, Track C (admin) manages | brute-force/rate-limit output, with optional `expires_at` |

Track C never writes to `rules` or `attack_logs` in the real
pipeline — it only reads them for the dashboard, and only writes
to `blocked_ips` via the admin "unblock" action. The demo
simulator (`backend/mock/simulator.js`) is the one exception: it
writes to `attack_logs` purely to make Track C demoable in
isolation, in the exact row shape Track B will produce for real.

## Turning off demo mode (integration step)

Once Track A's proxy and Track B's real pipeline are ready to
plug in:

1. Set `DEMO_MODE=false` in `backend/.env` (or delete
   `backend/mock/simulator.js` and its `require` in `server.js`
   entirely).
2. Point Track B's log-writer at the same `attack_logs` table and
   have it call the same `emitAttackLog(io, orgId, row)` helper
   from `backend/socket.js` after each insert.
3. Nothing in the frontend needs to change — it only knows about
   the `attack:new` socket event and the `/api/dashboard/*` REST
   shape, not where the data came from.

## Notes / things to be upfront about in a demo

- Auth is intentionally hand-rolled (per the project brief) rather
  than using a library like Passport — that's what "explain how a
  token is issued and verified" is testing.
- Public `/api/auth/register` always creates a `viewer`; promoting
  someone to `admin` is a direct DB update (or a future admin-only
  endpoint) — out of scope for this pass on purpose.
- The demo simulator is clearly commented as demo-only and is not
  part of the real detection pipeline; it exists so Track C has
  something real to show before integration.
