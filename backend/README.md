# ThreatGate Java CLI Backend

Pure Java CLI backend for **ThreatGate** (Reverse-Proxy Web Application Firewall), structured to match the modular multi-package architecture (`app`, `model`, `exception`, `db`, `service`, `test`) and aligned with the ThreatGate React `frontend/` and `schema/schema.sql`.

It saves every entity (`orgs`, `users`, `rules`, `attack_logs`, `blocked_ips`) directly into a **zero-server Embedded H2 JDBC database (`backend/data/threatgate.mv.db`)** out of the box and lets you extract and list all saved tables right inside the CLI (`[9] Database Explorer`).

## Directory Structure

```text
backend/
├── src/com/threatgate/
│   ├── app/
│   │   └── Main.java
│   ├── model/
│   │   ├── Identifiable.java
│   │   ├── DataRepository.java
│   │   ├── GenericStore.java
│   │   ├── CsvCodec.java
│   │   ├── Organization.java
│   │   ├── User.java
│   │   ├── DetectionRule.java
│   │   ├── AttackLog.java
│   │   ├── BlockedIp.java
│   │   ├── InspectionRequest.java
│   │   ├── RuleMatch.java
│   │   ├── InspectionResult.java
│   │   ├── CategoryCount.java
│   │   ├── TimelineBucket.java
│   │   └── DashboardStats.java
│   ├── exception/
│   │   ├── AuthenticationException.java
│   │   ├── UnauthorizedRoleException.java
│   │   ├── EntityNotFoundException.java
│   │   ├── InvalidDataException.java
│   │   ├── DatabaseException.java
│   │   └── IpBlockedException.java
│   ├── db/
│   │   ├── RowMapper.java
│   │   ├── StatementBinder.java
│   │   ├── JdbcTemplateHelper.java
│   │   ├── DatabaseConfig.java
│   │   ├── DatabaseConnection.java
│   │   ├── SchemaInitializer.java
│   │   ├── OrgJdbcDao.java
│   │   ├── UserJdbcDao.java
│   │   ├── RuleJdbcDao.java
│   │   ├── AttackLogJdbcDao.java
│   │   └── BlockedIpJdbcDao.java
│   ├── service/
│   │   ├── PasswordUtil.java
│   │   ├── RequestValidator.java
│   │   ├── RuleMatcher.java
│   │   ├── AuthService.java
│   │   ├── RuleService.java
│   │   ├── DetectionEngine.java
│   │   ├── SlidingWindow.java
│   │   ├── BruteForceService.java
│   │   ├── AttackLogService.java
│   │   ├── DashboardService.java
│   │   ├── RequestBuffer.java
│   │   ├── TrafficProducerWorker.java
│   │   ├── TrafficConsumerWorker.java
│   │   ├── ExpirySweeperWorker.java
│   │   ├── TrafficPipelineService.java
│   │   ├── FilePersistenceService.java
│   │   └── ThreatGateFacade.java
│   └── test/
│       └── ThreatGateTestRunner.java
├── bin/
├── data/
│   └── sample_rules_tokens.txt
├── lib/
│   └── h2-2.3.232.jar
├── db.properties.example
├── start-cli.sh
├── test-cli.sh
└── README.md
```

## Quick Start (One Command via Bash)

From the repository root:

```bash
./start-backend.sh
```

Or using root `run.sh`:

```bash
./run.sh
```

Run the automated verification suite (61 assertions live on Embedded H2 JDBC):

```bash
./test-backend.sh
```

> **Try Mode (500 Requests):** Pick `[2] Try Mode` at the Sign-In prompt (or `[4]` inside the console) to populate 500 realistic requests directly into `backend/data/threatgate.mv.db` for live demos.

From inside `backend/`:

```bash
./start-cli.sh
./test-cli.sh
```

## Demo Credentials (Matching Frontend)

- **Admin:** `admin@threatgate.dev` / `Admin123!`
- **Viewer:** `viewer@threatgate.dev` / `Viewer123!`

## Syllabus Topic Mapping

| Topic | Implementation |
| :--- | :--- |
| **Multithreading (`Thread` / `Runnable`)** | `TrafficProducerWorker` (`Runnable`), `TrafficConsumerWorker` (`Thread`), `ExpirySweeperWorker` (`Thread`), `start()`, `run()`, `sleep()`, `join()`, `interrupt()` |
| **Thread Lifecycle & Scheduling** | `NEW`, `RUNNABLE`, `BLOCKED`, `WAITING`, `TIMED_WAITING`, `TERMINATED` tracing in `TrafficPipelineService.captureThreadLifecycleReport()`, daemon sweeper (`setDaemon(true)`), `setPriority()` |
| **Synchronization & Intrinsic Locks** | `synchronized` methods/blocks, private `lock` monitor in `SlidingWindow`, `GenericStore`, `volatile` stop flags, race-condition safety |
| **Inter-Thread Communication** | `RequestBuffer<T>` bounded monitor with guarded `while` loops calling `wait()` and `notifyAll()` |
| **JDBC & SQL CRUD** | `Class.forName("org.h2.Driver")`, `DriverManager`, `Connection`, `Statement`, `PreparedStatement`, `ResultSet`, typed getters, `RowMapper`, `SchemaInitializer`, 5 DAOs (`orgs`, `users`, `rules`, `attack_logs`, `blocked_ips`) |
| **Lambdas & Stream API** | `@FunctionalInterface` (`RowMapper`, `StatementBinder`, `RequestValidator`, `RuleMatcher`), method references (`::`), `filter()`, `map()`, `sorted()`, `distinct()`, `limit()`, `skip()`, `collect()`, `count()` |
| **Generics** | `Identifiable<ID>`, `DataRepository<T extends Identifiable<ID>, ID>`, `GenericStore<T, ID>`, `RequestBuffer<T>`, diamond operator `<>`, `? super T` & `? extends Identifiable<?>` wildcards |
| **File I/O & CSV Integration** | `FileReader`/`BufferedReader`, `FileWriter`/`BufferedWriter` CSV import/export, `FileInputStream`/`FileOutputStream` binary audit snapshots & byte copies, `StreamTokenizer` rule parser |

## Zero-Server Embedded DB & Optional External JDBC

1. Out of the box, ThreatGate uses `backend/lib/h2-2.3.232.jar` and persists everything to `backend/data/threatgate.mv.db` via JDBC (`jdbc:h2:file:./data/threatgate;MODE=MySQL;DATABASE_TO_LOWER=TRUE;LOCK_TIMEOUT=10000`).
2. Inside the CLI, open **`[9]` Database Explorer** to see live row counts and extract/list any saved table (`orgs`, `users`, `rules`, `attack_logs`, `blocked_ips`), or export the entire DB to CSVs.
3. To switch to a different local `.mv.db` file or connect an external MySQL Server later, use menu `[9] -> [8]` or copy `backend/db.properties.example` to `backend/db.properties`.
