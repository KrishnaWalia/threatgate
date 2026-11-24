# ThreatGate — Java CLI Web Application Firewall

ThreatGate inspects HTTP requests against a **rules-as-data detection engine**, detects and blocks **SQL injection, XSS, path traversal, and brute-force attacks**, aggregates live traffic analytics with **Java Streams**, coordinates simulated/batch traffic using **multithreaded producer-consumer pipelines**, and persists state via **MySQL JDBC** with automatic **CSV/file fallback** — built as a pure Java CLI backend aligned 1-for-1 with the ThreatGate React `frontend/` and `schema/schema.sql`.

```text
+---------------------------------------------------------------------------------------------------+
|                             ThreatGate Java CLI Backend (com.threatgate)                          |
|                                                                                                   |
|   Main CLI Console (app/Main.java)                                                                |
|    |-- Auth Gate & RBAC (AuthService: admin / viewer, PasswordUtil SHA-256 + salt)                |
|    |-- Dashboard Overview & Live Feed (DashboardService & AttackLogService via Stream API)        |
|    '-- Interactive Request Tester & Attack Demo                                                   |
|           |                                                                                       |
|           v                                                                                       |
|   TrafficPipelineService                                                                          |
|    |-- RequestBuffer<InspectionRequest>  (synchronized monitor: wait() / notifyAll())             |
|    |-- TrafficProducerWorker (Runnable) ---> TrafficConsumerWorker (Thread)                       |
|    |-- ExpirySweeperWorker (Daemon Thread, MIN_PRIORITY -> TIMED_WAITING -> purgeExpired())       |
|    '-- WAF Lifecycle: Active IP Block? -> Rate Limit? -> DetectionEngine -> Log & Track Strikes   |
|           |                                             |                                         |
|           v                                             v                                         |
|   MySQL JDBC Layer (db/)                       Offline / File I/O Layer (service/)                |
|    |-- DatabaseConnection (DriverManager)       |-- CSV Import/Export (BufferedReader/Writer)     |
|    |-- SchemaInitializer (Statement DDL)        |-- Binary Audit Snapshot (FileInput/OutputStream)|
|    '-- User/Rule/AttackLog/BlockedIp JDBC DAOs  '-- Tokenized Rule Import (StreamTokenizer)       |
+---------------------------------------------------------------------------------------------------+
                                   |
                                   v  Aligned Data Contract & Features
                 schema/schema.sql  <--->  frontend/ (React + Vite UI, untouched)
```

---

## Quick Start (One Command via Bash)

Requires **JDK 8+** (built and verified on **JDK 26.0.2**). No external framework or build tool is needed, and MySQL is optional (automatic CSV persistence runs whenever MySQL is unreachable).

From the repository root:

```bash
./start-backend.sh
```

Or using `run.sh`:

```bash
./run.sh
```

Run the automated verification suite (53 assertions across auth, detection rules, brute-force windows, Streams, generics, multithreading, file I/O, and JDBC):

```bash
./test-backend.sh
```

From inside `backend/`:

```bash
./start-cli.sh
./test-cli.sh
```

### Demo Credentials (Matching `frontend/src/pages/Login.jsx`)

| Role | Email | Password | Capabilities |
| :--- | :--- | :--- | :--- |
| **Admin** | `admin@threatgate.dev` | `Admin123!` | Full console: Dashboard, Live Feed, Inspect/Demo, toggle/re-weight/add/delete rules, manage/unblock Blocked IPs, Simulator, File I/O, JDBC settings |
| **Viewer** | `viewer@threatgate.dev` | `Viewer123!` | Read-only analytics: Dashboard, Live Feed, Inspect/Demo, view Detection Rules (admin mutations enforce `UnauthorizedRoleException`) |

---

## Repository & Package Structure

```text
threatgate/
├── start-backend.sh                              # Root launcher -> backend/start-cli.sh
├── test-backend.sh                               # Root test runner -> backend/test-cli.sh
├── run.sh                                        # One-command CLI backend startup
├── schema/
│   └── schema.sql                                # Shared MySQL contract (orgs, users, rules, attack_logs, blocked_ips)
├── frontend/                                     # React + Vite + Tailwind UI (untouched)
└── backend/
    ├── src/com/threatgate/
    │   ├── app/
    │   │   └── Main.java                         # Interactive CLI console, ASCII charts & safe Scanner input
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
    │   │   ├── DatabaseConfig.java               # Loads/saves db.properties & WAF thresholds
    │   │   ├── DatabaseConnection.java           # Class.forName + DriverManager connection management
    │   │   ├── SchemaInitializer.java            # DDL schema creation & default seed via Statement/PreparedStatement
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
    │   │   └── ThreatGateFacade.java             # Unified facade selecting MySQL JDBC or CSV fallback
    │   └── test/
    │       └── ThreatGateTestRunner.java         # Automated 53-assertion verification suite
    ├── data/
    │   └── sample_rules_tokens.txt               # Sample StreamTokenizer rule import file
    ├── lib/                                      # Place mysql-connector-j-*.jar here
    ├── db.properties.example                     # Sample MySQL JDBC & WAF configuration
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
| **JDBC & Database Programming** | `Class.forName` driver loading, `DriverManager`, `Connection`, `Statement` DDL, `PreparedStatement` parameter binding, `ResultSet` cursor iteration, typed getters, `RowMapper`, and CRUD DAOs for `users`, `rules`, `attack_logs`, and `blocked_ips` |
| **Lambda Expressions & Stream API** | Custom `@FunctionalInterface`s (`RowMapper`, `StatementBinder`, `RequestValidator`, `RuleMatcher`), method references (`::`), `Stream` pipelines with `filter()`, `map()`, `sorted()`, `distinct()`, `limit()`, `skip()`, `collect()`, `count()` |
| **Generics** | `Identifiable<ID>`, `DataRepository<T extends Identifiable<ID>, ID>`, `GenericStore<T, ID>`, `RequestBuffer<T>`, `CsvImportResult<T>`, diamond operator `<>`, upper/lower bounded wildcards (`? extends`, `? super`) |
| **File Handling & CSV Integration** | `FileReader`/`BufferedReader` and `FileWriter`/`BufferedWriter` for CSV import/export with malformed-row resilience, `FileInputStream`/`FileOutputStream` for binary audit snapshots and byte-by-byte backups, and `StreamTokenizer` for tokenized rule imports |

---

## Interactive CLI Features

1. **Dashboard Overview**: Displays the 4 stat cards (`Total Requests`, `Blocked`, `Allowed`, `Active IP Blocks`), an ASCII 24h bar chart by attack category, and an hourly `HH:mm` allowed-vs-blocked timeline matching `frontend/src/pages/Dashboard.jsx`.
2. **Live Request Feed**: View recent logs, filter & paginate with Streams (`category` / `action`), list distinct blocked IPs, or display top high-risk events.
3. **Inspect Single HTTP Request**: Enter IP, HTTP method, path/query, body, `User-Agent`, `Referer`, `Cookie`, and optional login response status (`200`/`401`/`403`) to test the WAF pipeline interactively.
4. **Automated Attack Demo**: Runs a multithreaded producer-consumer batch across benign queries (`O'Brien`, `/search?q=hello`), SQLi (`' OR '1'='1`, `UNION/**/SELECT`), XSS (`<script>alert(1)</script>`), double-encoded path traversal (`%252e%252e%252fetc/passwd`), login brute force, and repeated attack strikes.
5. **Detection Rules**: View all 22 rules-as-data; Admins can toggle rules ON/OFF, re-weight (`1–100`), add custom regex rules, or delete custom rules live.
6. **Blocked IPs Management *(Admin Only)***: View active blocks, manually block an IP (temporary or permanent), unblock an IP (resetting all sliding windows), or purge expired entries.
7. **Multithreaded Simulator & Thread Monitor**: Start/stop continuous background producer-consumer simulation, inspect live threads and trace all 6 `Thread.State` transitions, or run the sequential-vs-concurrent benchmark.
8. **File I/O Tools**: Export/import CSVs (`rules`, `attack_logs`, `blocked_ips`), generate/parse tokenized rules via `StreamTokenizer`, write/verify binary audit snapshots via `FileOutputStream`/`FileInputStream`, and copy CSV backups byte-by-byte.
9. **Database / JDBC Settings**: Inspect JDBC driver/URL/status, test or configure MySQL credentials live, re-run `SchemaInitializer`, or save offline CSV state.

---

## Detection Rules & Brute-Force Mechanics

- **3-Pass Normalization (`DetectionEngine.normalize`)**: Caps target length at 20,000 chars, converts `+` to space, runs up to 3 rounds of decoding (`%XX`, `%uXXXX`, `\uXXXX`, `&#xHEX;`, `&#DEC;`, named entities `&lt; &gt; &quot; &apos; &amp; &sol; &bsol;`), strips inline SQL comments (`/*...*/`), and collapses whitespace across `path`, `query`, `body`, `user-agent`, `referer`, and `cookie`.
- **Risk Scoring Formula**:
  ```text
  risk = min(100, W_max + 0.5 * sum(weights of other distinct matched rules))
  ```
  Each rule counts at most once per request. Requests with `risk >= 50` (`BLOCK_THRESHOLD`) are blocked (`403`). Weak rules (weight `40`, e.g. `SELECT ... FROM` or `alert(`) do not block on their own so benign inputs like `O'Brien` or `select the best items from our store` remain allowed.
- **Brute-Force Sliding Windows (`BruteForceService`)**:
  - Failed Logins: `>= 5` (`401`/`403` on login paths) within `60s`
  - Request Rate: `> 100` requests within `10s`
  - Attack Strikes: `>= 8` blocked requests within `60s`
  - **Lazy Expiry**: `findActiveBlock()` evaluates `expires_at` on every check and immediately evicts expired blocks; `ExpirySweeperWorker` also purges expired rows on a daemon timer. Unblocking resets all counters for that IP.

---

## MySQL JDBC Configuration

1. Ensure MySQL Server 8.0 is running and `mysql-connector-j-26.10.0.jar` is present in `backend/lib/` (the startup scripts also check `D:/jdbc/mysql-connector-j-26.10.0/mysql-connector-j-26.10.0.jar` and `$MYSQL_JDBC_JAR`).
2. Copy `backend/db.properties.example` to `backend/db.properties` and set your MySQL username/password (or configure interactively via CLI option `[3]` at sign-in or `[9]` inside the console):
   ```properties
   db.driver=com.mysql.cj.jdbc.Driver
   db.url=jdbc:mysql://localhost:3306/threatgate?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC
   db.serverUrl=jdbc:mysql://localhost:3306/?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC
   db.name=threatgate
   db.user=root
   db.password=your_password
   ```
3. On startup, `SchemaInitializer` automatically creates the `threatgate` database and all 5 tables (`orgs`, `users`, `rules`, `attack_logs`, `blocked_ips`) if absent, and seeds `Demo Org`, `admin@threatgate.dev`, `viewer@threatgate.dev`, and all 22 default rules.
4. If MySQL is unavailable or rejects credentials, ThreatGate switches cleanly to **Offline CSV Fallback Mode** in `backend/data/`.

---

## Automated Verification (`ThreatGateTestRunner`)

Run `./test-backend.sh` to execute all **53 assertions** covering:
- Admin/Viewer login, anti-enumeration error handling, viewer registration, and RBAC denial (`UnauthorizedRoleException`)
- All 22 compiled regex rules, false-positive safety (`O'Brien`, single weak signal), double-encoded path traversal, inline SQL comment bypass, HTML-encoded XSS, null-byte traversal, and `User-Agent` inspection
- Rules-as-data live toggle, re-weighting, custom rule addition, and invalid regex rejection
- `SlidingWindow` eviction, failed-login auto-block, successful-login reset, attack-strike block, short-TTL lazy expiry, and admin unblock reset
- Stream API analytics (`getStats`, `getPagedLogs`, `getDistinctBlockedIps`, `getTopHighRiskLogs`)
- `GenericStore<T, ID>` and bounded wildcards (`? super T`, `? extends Identifiable<?>`)
- Multithreaded producer-consumer batch, 8-thread concurrent stress test (200/200 logs with zero loss), daemon `ExpirySweeperWorker`, and all 6 `Thread.State` transitions
- CSV round-trip with malformed line skipping, `FileOutputStream`/`FileInputStream` binary audit snapshot & byte copy, `StreamTokenizer` parsing, JDBC driver loading, and offline restart reload
