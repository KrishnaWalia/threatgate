# ThreatGate Java CLI Backend

Pure Java CLI backend for **ThreatGate** (Reverse-Proxy Web Application Firewall), structured to match the modular multi-package architecture (`app`, `model`, `exception`, `db`, `service`, `test`) and aligned with the ThreatGate React `frontend/` and `schema/schema.sql`.

## Directory Structure

```text
backend/
├── src/
│   └── com/
│       └── threatgate/
│           ├── app/
│           │   └── Main.java
│           ├── model/
│           │   ├── Identifiable.java
│           │   ├── DataRepository.java
│           │   ├── GenericStore.java
│           │   ├── CsvCodec.java
│           │   ├── Organization.java
│           │   ├── User.java
│           │   ├── DetectionRule.java
│           │   ├── AttackLog.java
│           │   ├── BlockedIp.java
│           │   ├── InspectionRequest.java
│           │   ├── RuleMatch.java
│           │   ├── InspectionResult.java
│           │   ├── CategoryCount.java
│           │   ├── TimelineBucket.java
│           │   └── DashboardStats.java
│           ├── exception/
│           │   ├── AuthenticationException.java
│           │   ├── UnauthorizedRoleException.java
│           │   ├── EntityNotFoundException.java
│           │   ├── InvalidDataException.java
│           │   ├── DatabaseException.java
│           │   └── IpBlockedException.java
│           ├── db/
│           │   ├── RowMapper.java
│           │   ├── StatementBinder.java
│           │   ├── JdbcTemplateHelper.java
│           │   ├── DatabaseConfig.java
│           │   ├── DatabaseConnection.java
│           │   ├── SchemaInitializer.java
│           │   ├── UserJdbcDao.java
│           │   ├── RuleJdbcDao.java
│           │   ├── AttackLogJdbcDao.java
│           │   └── BlockedIpJdbcDao.java
│           ├── service/
│           │   ├── PasswordUtil.java
│           │   ├── RequestValidator.java
│           │   ├── RuleMatcher.java
│           │   ├── AuthService.java
│           │   ├── RuleService.java
│           │   ├── DetectionEngine.java
│           │   ├── SlidingWindow.java
│           │   ├── BruteForceService.java
│           │   ├── AttackLogService.java
│           │   ├── DashboardService.java
│           │   ├── RequestBuffer.java
│           │   ├── TrafficProducerWorker.java
│           │   ├── TrafficConsumerWorker.java
│           │   ├── ExpirySweeperWorker.java
│           │   ├── TrafficPipelineService.java
│           │   ├── FilePersistenceService.java
│           │   └── ThreatGateFacade.java
│           └── test/
│               └── ThreatGateTestRunner.java
├── bin/
├── data/
│   └── sample_rules_tokens.txt
├── lib/
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

Run the automated verification suite (53 assertions):

```bash
./test-backend.sh
```

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
| **JDBC & SQL CRUD** | `Class.forName`, `DriverManager`, `Connection`, `Statement`, `PreparedStatement`, `ResultSet`, typed getters, `RowMapper`, `SchemaInitializer`, 4 DAOs (`users`, `rules`, `attack_logs`, `blocked_ips`) |
| **Lambdas & Stream API** | `@FunctionalInterface` (`RowMapper`, `StatementBinder`, `RequestValidator`, `RuleMatcher`), method references (`::`), `filter()`, `map()`, `sorted()`, `distinct()`, `limit()`, `skip()`, `collect()`, `count()` |
| **Generics** | `Identifiable<ID>`, `DataRepository<T extends Identifiable<ID>, ID>`, `GenericStore<T, ID>`, `RequestBuffer<T>`, diamond operator `<>`, `? super T` & `? extends Identifiable<?>` wildcards |
| **File I/O & CSV Integration** | `FileReader`/`BufferedReader`, `FileWriter`/`BufferedWriter` CSV import/export, `FileInputStream`/`FileOutputStream` binary audit snapshots & byte copies, `StreamTokenizer` rule parser |

## MySQL JDBC Setup

1. Copy `backend/db.properties.example` to `backend/db.properties` and set your MySQL password if required (or configure live from CLI menu `[3]` / `[9]`).
2. Place `mysql-connector-j-26.10.0.jar` inside `backend/lib/` (the startup scripts also auto-detect `D:/jdbc/mysql-connector-j-26.10.0/mysql-connector-j-26.10.0.jar` or `$MYSQL_JDBC_JAR`).
3. If MySQL Server is offline on startup, ThreatGate automatically activates **Offline CSV Fallback Mode** in `backend/data/`.
