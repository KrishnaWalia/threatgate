# ThreatGate — Java CLI Web Application Firewall

ThreatGate inspects HTTP requests against a **rules-as-data detection engine**, detects and blocks **SQL injection, XSS, path traversal, and brute-force attacks**, aggregates live traffic analytics with **Java Streams**, coordinates simulated/batch traffic using **multithreaded producer-consumer pipelines**, and persists everything directly into an **embedded zero-server H2 JDBC database (`backend/data/threatgate.mv.db`)** — built as a pure Java CLI backend aligned 1-for-1 with the ThreatGate React `frontend/` and `schema/schema.sql`.

```text
+---------------------------------------------------------------------------------------------------+
|                             ThreatGate Java CLI Backend (com.threatgate)                          |
|                                                                                                   |
|   Main CLI Console (app/Main.java)                                                                |
|    |-- Auth Gate & RBAC (AuthService: admin / viewer, PasswordUtil SHA-256 + salt)                |
|    |-- Dashboard Overview & Live Feed (DashboardService & AttackLogService via Stream API)        |
|    '-- Database Explorer ([9] Extract & List Saved orgs/users/rules/attack_logs/blocked_ips)      |
|           |                                                                                       |
|           v                                                                                       |
|   TrafficPipelineService                                                                          |
|    |-- RequestBuffer<InspectionRequest>  (synchronized monitor: wait() / notifyAll())             |
|    |-- TrafficProducerWorker (Runnable) ---> TrafficConsumerWorker (Thread)                       |
|    |-- ExpirySweeperWorker (Daemon Thread, MIN_PRIORITY -> TIMED_WAITING -> purgeExpired())       |
|    '-- WAF Lifecycle: Active IP Block? -> Rate Limit? -> DetectionEngine -> Log & Track Strikes   |
|           |                                             |                                         |
|           v                                             v                                         |
|   Embedded H2 JDBC Database (Default, Zero Server)     File I/O Layer (service/)                  |
|    |-- backend/data/threatgate.mv.db                    |-- CSV Import/Export (BufferedReader/W)  |
|    |-- DatabaseConnection (DriverManager)               |-- Binary Audit Snapshot (FileIn/OutStrm)|
|    '-- Org/User/Rule/AttackLog/BlockedIp JDBC DAOs      '-- Tokenized Rule Import (StreamTokenizer|
+---------------------------------------------------------------------------------------------------+
                                   |
                                   v  Aligned Data Contract & Features
                 schema/schema.sql  <--->  frontend/ (React + Vite UI, untouched)
```

---

## Quick Start (Zero Server Setup)

Requires **JDK 8+** (built and verified on **JDK 26.0.2**). The embedded H2 JDBC driver (`backend/lib/h2-2.3.232.jar`) is bundled in the repository — **no external MySQL server or password is needed**. Every action saves directly to `backend/data/threatgate.mv.db` via JDBC, and you can extract and list any saved table inside CLI menu `[9]`.

From the repository root:

```bash
./start-backend.sh
```

Or using `run.sh`:

```bash
./run.sh
```

Run the automated verification suite (**61 assertions** running live against Embedded H2 JDBC):

```bash
./test-backend.sh
```

> **Presentation Try Mode:** At the Sign-In screen (`./start-backend.sh`), pick **`[2]` Try Mode** to auto-sign in and populate **500 realistic requests** (benign, SQLi, XSS, path traversal, login brute-force, and attack-strike bans) straight into `backend/data/threatgate.mv.db`—or trigger it anytime from console menu **`[4]`**.

From inside `backend/`:

```bash
./start-cli.sh
./test-cli.sh
```

### Demo Credentials (Matching `frontend/src/pages/Login.jsx`)

| Role | Email | Password | Capabilities |
| :--- | :--- | :--- | :--- |
| **Admin** | `admin@threatgate.dev` | `Admin123!` | Full console: Dashboard, Live Feed, Inspect/Demo, toggle/re-weight/add/delete rules, manage/unblock Blocked IPs, Simulator, File I/O, Database Explorer (all tables + CSV export) |
| **Viewer** | `viewer@threatgate.dev` | `Viewer123!` | Read-only analytics: Dashboard, Live Feed, Inspect/Demo, view Detection Rules, view `orgs`/`rules`/`attack_logs` in DB Explorer (admin mutations enforce `UnauthorizedRoleException`) |

---

## Repository & Package Structure

```text
threatgate/
├── start-backend.sh                              # Root launcher -> backend/start-cli.sh
├── test-backend.sh                               # Root test runner -> backend/test-cli.sh
├── run.sh                                        # One-command CLI backend startup
├── schema/
│   └── schema.sql                                # Shared schema contract (orgs, users, rules, attack_logs, blocked_ips)
├── frontend/                                     # React + Vite + Tailwind UI (untouched)
└── backend/
    ├── src/com/threatgate/
    │   ├── app/
    │   │   └── Main.java                         # Interactive CLI console, DB Explorer & ASCII charts
    │   ├── model/
    │   │   ├── Identifiable.java                 # Generic ID contract Identifiable<ID>
    │   │   ├── DataRepository.java               # Generic CRUD interface DataRepository<T extends Identifiable<ID>, ID>
    │   │   ├── GenericStore.java                 # Synchronized generic store with bounded wildcards & Stream helpers
    │   │   ├── CsvCodec.java                     # RFC-4180 CSV escaping & quoted-field parser
    │   │   ├── Organization.java                 # orgs entity model
    │   │   ├── User.java                         # users entity model & CSV serialization
    │   │   ├── DetectionRule.java                # rules entity model & CSV serialization
    │   │   ├── AttackLog.java                    # attack_logs entity model & CSV serialization
    │   │   ├── BlockedIp.java                    # blocked_ips entity model with lazy expiry check
    │   │   ├── InspectionRequest.java            # Request payload + headers + simulated login status
    │   │   ├── RuleMatch.java                    # Matched rule metadata & inspection target location
    │   │   ├── InspectionResult.java             # Combined risk score, category, matched rule, block flag
    │   │   ├── CategoryCount.java                # 24h category aggregation DTO
    │   │   ├── TimelineBucket.java               # 1h per-minute allowed/blocked DTO
    │   │   └── DashboardStats.java               # Dashboard overview totals, category counts & timeline
    │   ├── exception/
    │   │   ├── AuthenticationException.java      # Invalid credentials / auth errors
    │   │   ├── UnauthorizedRoleException.java    # Service-layer RBAC enforcement (admin vs viewer)
    │   │   ├── EntityNotFoundException.java      # Missing rule / blocked IP record
    │   │   ├── InvalidDataException.java         # Validation errors, duplicate email, invalid regex
    │   │   ├── DatabaseException.java            # JDBC connection & SQL error wrapper
    │   │   └── IpBlockedException.java           # Active IP block metadata exception
    │   ├── db/
    │   │   ├── RowMapper.java                    # @FunctionalInterface ResultSet -> Java object mapper
    │   │   ├── StatementBinder.java              # @FunctionalInterface PreparedStatement parameter binder
    │   │   ├── JdbcTemplateHelper.java           # Reusable JDBC query execution & cursor iteration
    │   │   ├── DatabaseConfig.java               # Loads/saves db.properties & Embedded H2 / MySQL settings
    │   │   ├── DatabaseConnection.java           # Class.forName + DriverManager connection management
    │   │   ├── SchemaInitializer.java            # DDL schema creation, table counts & default seed
    │   │   ├── OrgJdbcDao.java                   # PreparedStatement CRUD for orgs table
    │   │   ├── UserJdbcDao.java                  # PreparedStatement CRUD for users table
    │   │   ├── RuleJdbcDao.java                  # PreparedStatement CRUD for rules table
    │   │   ├── AttackLogJdbcDao.java             # PreparedStatement CRUD & SQL counts for attack_logs
    │   │   └── BlockedIpJdbcDao.java             # Upsert/query/delete/purge CRUD for blocked_ips
    │   ├── service/
    │   │   ├── PasswordUtil.java                 # Salted SHA-256 hashing & constant-time verification
    │   │   ├── RequestValidator.java             # @FunctionalInterface request validation predicate
    │   │   ├── RuleMatcher.java                  # @FunctionalInterface normalized rule matcher
    │   │   ├── AuthService.java                  # Login, viewer registration, RBAC gate
    │   │   ├── RuleService.java                  # 22 default rules-as-data + live admin updates
    │   │   ├── DetectionEngine.java              # 3-round decoding normalization & risk scoring
    │   │   ├── SlidingWindow.java                # Intrinsic-lock synchronized sliding event counter
    │   │   ├── BruteForceService.java            # 3 sliding windows (login, rate, strikes) + lazy block expiry
    │   │   ├── AttackLogService.java             # Logging + Stream filtering, pagination & distinct queries
    │   │   ├── DashboardService.java             # Stream API 24h category breakdown & 1h timeline buckets
    │   │   ├── RequestBuffer.java                # Bounded monitor using wait() / notifyAll()
    │   │   ├── TrafficProducerWorker.java        # Runnable traffic generator / batch producer
    │   │   ├── TrafficConsumerWorker.java        # Thread consumer executing WAF inspection pipeline
    │   │   ├── ExpirySweeperWorker.java          # Daemon Thread (MIN_PRIORITY) purging expired blocks
    │   │   ├── TrafficPipelineService.java       # Orchestration, demo batch, benchmark & 6-state trace
    │   │   ├── FilePersistenceService.java       # CSV, FileInputStream/FileOutputStream & StreamTokenizer
    │   │   └── ThreatGateFacade.java             # Unified facade for Embedded H2 JDBC, extraction & CSV fallback
    │   └── test/
    │       └── ThreatGateTestRunner.java         # Automated 57-assertion verification suite
    ├── data/
    │   └── sample_rules_tokens.txt               # Sample StreamTokenizer rule import file
    ├── lib/
    │   └── h2-2.3.232.jar                        # Bundled Embedded H2 JDBC driver (zero external server)
    ├── db.properties.example                     # Default Embedded H2 & optional MySQL configuration
    ├── start-cli.sh                              # Compiles src/ -> bin/ and starts Main CLI
    ├── test-cli.sh                               # Compiles src/ -> bin/ and runs ThreatGateTestRunner
    └── README.md                                 # Detailed backend reference
```

---

## Syllabus Topic Implementation Mapping

| Topic | How It Is Implemented |
| :--- | :--- |
| **Multithreading & Concurrency** | `TrafficProducerWorker` (`Runnable`), `TrafficConsumerWorker` (`Thread`), `ExpirySweeperWorker` (`Thread`), `start()`, `run()`, `sleep()`, `join()`, `interrupt()`, plus sequential vs. 4-thread concurrent benchmark in `TrafficPipelineService` |
| **Thread Lifecycle & Scheduling** | Live snapshot and deterministic trace of all 6 `Thread.State` values (`NEW`, `RUNNABLE`, `BLOCKED`, `WAITING`, `TIMED_WAITING`, `TERMINATED`), daemon sweeper (`setDaemon(true)`), and priority levels (`MIN_PRIORITY`, `NORM_PRIORITY`, `MAX_PRIORITY`) |
| **Synchronization & Intrinsic Locks** | `synchronized` methods and private `lock` monitors in `SlidingWindow`, `GenericStore`, `AttackLogService`, `BruteForceService`, `RuleService`, and `volatile` stop flags for cross-thread visibility |
| **Inter-Thread Communication** | `RequestBuffer<T>` bounded monitor with guarded `while` blocks calling `wait()` and `notifyAll()` between producer and consumer threads |
| **JDBC & Database Programming** | `Class.forName("org.h2.Driver")`, `DriverManager`, `Connection`, `Statement` DDL, `PreparedStatement` parameter binding, `ResultSet` cursor iteration, typed getters, `RowMapper`, and CRUD DAOs for all 5 tables (`orgs`, `users`, `rules`, `attack_logs`, `blocked_ips`) |
| **Lambda Expressions & Stream API** | Custom `@FunctionalInterface`s (`RowMapper`, `StatementBinder`, `RequestValidator`, `RuleMatcher`), method references (`::`), `Stream` pipelines with `filter()`, `map()`, `sorted()`, `distinct()`, `limit()`, `skip()`, `collect()`, `count()` |
| **Generics** | `Identifiable<ID>`, `DataRepository<T extends Identifiable<ID>, ID>`, `GenericStore<T, ID>`, `RequestBuffer<T>`, `CsvImportResult<T>`, diamond operator `<>`, upper/lower bounded wildcards (`? extends`, `? super`) |
| **File Handling & CSV Integration** | `FileReader`/`BufferedReader` and `FileWriter`/`BufferedWriter` for CSV import/export with malformed-row resilience, `FileInputStream`/`FileOutputStream` for binary audit snapshots and byte-by-byte backups, and `StreamTokenizer` for tokenized rule imports |

---

## Interactive CLI Features

1. **Dashboard Overview**: Displays the 4 stat cards (`Total Requests`, `Blocked`, `Allowed`, `Active IP Blocks`), an ASCII 24h bar chart by attack category, and an hourly `HH:mm` allowed-vs-blocked timeline matching `frontend/src/pages/Dashboard.jsx`.
2. **Live Request Feed**: View recent logs, filter & paginate with Streams (`category` / `action`), list distinct blocked IPs, or display top high-risk events.
3. **Inspect Single HTTP Request**: Enter IP, HTTP method, path/query, body, `User-Agent`, `Referer`, `Cookie`, and optional login response status (`200`/`401`/`403`) to test and save directly to the database.
4. **Try Mode & Automated Attack Demos**: From console menu `[4]` (or `[2]` at Sign-In), launch **Try Mode (500 requests)**, run the 20-request showcase batch, or generate a custom 50–1000 request demo dataset across benign queries (`O'Brien`, `/search?q=hello`), SQLi (`' OR '1'='1`, `UNION/**/SELECT`), XSS (`<script>alert(1)</script>`), double-encoded path traversal (`%252e%252e%252fetc/passwd`), login brute force, and repeated attack strikes — persisting every decision to `threatgate.mv.db`.
5. **Detection Rules**: View all 22 rules-as-data; Admins can toggle rules ON/OFF, re-weight (`1–100`), add custom regex rules, or delete custom rules live in the database.
6. **Blocked IPs Management *(Admin Only)***: View active blocks, manually block an IP (temporary or permanent), unblock an IP (resetting all sliding windows), or purge expired entries.
7. **Multithreaded Simulator & Thread Monitor**: Start/stop continuous background producer-consumer simulation, inspect live threads and trace all 6 `Thread.State` transitions, or run the sequential-vs-concurrent benchmark.
8. **File I/O Tools**: Export/import CSVs (`rules`, `attack_logs`, `blocked_ips`), generate/parse tokenized rules via `StreamTokenizer`, write/verify binary audit snapshots via `FileOutputStream`/`FileInputStream`, and copy CSV backups byte-by-byte.
9. **Database Explorer (Extract & List Saved DB Tables)**:
   - Displays live JDBC table row counts (`orgs`, `users`, `rules`, `attack_logs`, `blocked_ips`) and DB file size.
   - Extract and list **All Saved Tables Overview**, or inspect individual tables (`orgs`, `users`, `rules`, `attack_logs`, `blocked_ips`) straight from the database.
   - Export the entire saved database to CSV files or switch to another local `.mv.db` file / optional external MySQL JDBC server.

---

## Automated Verification (`ThreatGateTestRunner`)

Run `./test-backend.sh` to execute all **61 assertions** live against an isolated Embedded H2 JDBC database covering:
- Embedded H2 auto-initialization, `OrgJdbcDao`, `UserJdbcDao`, `RuleJdbcDao`, `AttackLogJdbcDao`, and `BlockedIpJdbcDao` CRUD + cross-restart `.mv.db` reload verification
- Admin/Viewer login, anti-enumeration error handling, viewer registration, and RBAC denial (`UnauthorizedRoleException`)
- All 22 compiled regex rules, false-positive safety (`O'Brien`, single weak signal), double-encoded path traversal, inline SQL comment bypass, HTML-encoded XSS, null-byte traversal, and `User-Agent` inspection
- Rules-as-data live toggle, re-weighting, custom rule addition, and invalid regex rejection
- `SlidingWindow` eviction, failed-login auto-block, successful-login reset, attack-strike block, short-TTL lazy expiry, and admin unblock reset
- Stream API analytics (`getStats`, `getPagedLogs`, `getDistinctBlockedIps`, `getTopHighRiskLogs`)
- `GenericStore<T, ID>` and bounded wildcards (`? super T`, `? extends Identifiable<?>`)
- Multithreaded producer-consumer batch, 8-thread concurrent stress test (200/200 logs saved into H2 with zero race-condition loss), daemon `ExpirySweeperWorker`, and all 6 `Thread.State` transitions
- CSV round-trip with malformed line skipping, `FileOutputStream`/`FileInputStream` binary audit snapshot & byte copy, `StreamTokenizer` parsing, and optional offline CSV fallback mode
