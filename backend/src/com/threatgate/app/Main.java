package com.threatgate.app;

import com.threatgate.db.DatabaseConfig;
import com.threatgate.exception.AuthenticationException;
import com.threatgate.exception.DatabaseException;
import com.threatgate.exception.EntityNotFoundException;
import com.threatgate.exception.InvalidDataException;
import com.threatgate.exception.UnauthorizedRoleException;
import com.threatgate.model.AttackLog;
import com.threatgate.model.BlockedIp;
import com.threatgate.model.CategoryCount;
import com.threatgate.model.DashboardStats;
import com.threatgate.model.DetectionRule;
import com.threatgate.model.InspectionRequest;
import com.threatgate.model.TimelineBucket;
import com.threatgate.model.User;
import com.threatgate.service.FilePersistenceService;
import com.threatgate.service.ThreatGateFacade;
import com.threatgate.service.TrafficPipelineService;
import java.io.File;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Scanner;

public final class Main {
    private static final String LINE_WIDE =
            "==========================================================================================================";
    private static final String LINE_THIN =
            "----------------------------------------------------------------------------------------------------------";

    private final Scanner scanner;
    private final ThreatGateFacade facade;
    private User currentUser;

    private Main(Scanner scanner, ThreatGateFacade facade) {
        this.scanner = scanner;
        this.facade = facade;
    }

    public static void main(String[] args) {
        String baseDir = resolveBackendBaseDir();
        String dataDir = baseDir + File.separator + "data";
        String configPath = baseDir + File.separator + "db.properties";
        String examplePath = baseDir + File.separator + "db.properties.example";

        Scanner inputScanner = new Scanner(System.in);
        ThreatGateFacade threatGateFacade = new ThreatGateFacade(dataDir, configPath, examplePath);
        Main cli = new Main(inputScanner, threatGateFacade);
        try {
            cli.run();
        } finally {
            threatGateFacade.shutdown();
            inputScanner.close();
        }
    }

    private static String resolveBackendBaseDir() {
        File nestedExample = new File("backend" + File.separator + "db.properties.example");
        File nestedSrc = new File("backend" + File.separator + "src");
        if (nestedExample.exists() || nestedSrc.exists()) {
            return "backend";
        }
        return ".";
    }

    private void run() {
        printLandingBanner();
        boolean appRunning = true;

        while (appRunning) {
            if (currentUser == null) {
                appRunning = runAuthGate();
            } else {
                appRunning = runConsoleLoop();
            }
        }
        printGoodbyeBanner();
    }

    private boolean runAuthGate() {
        System.out.println(LINE_WIDE);
        System.out.println("                                   THREATGATE CONSOLE - SIGN IN");
        System.out.println(LINE_WIDE);
        printStorageBanner();
        System.out.println("  Demo Credentials: admin@threatgate.dev / Admin123!  |  viewer@threatgate.dev / Viewer123!");
        System.out.println(LINE_THIN);
        System.out.println("  [1] Sign In");
        System.out.println("  [2] Register New Viewer Account");
        System.out.println("  [3] Configure / Connect MySQL JDBC Database");
        System.out.println("  [4] Exit");
        System.out.println(LINE_WIDE);
        System.out.print("  Select an option [1-4]: ");

        int choice = readMenuChoice(1, 4, 4);
        System.out.println();
        switch (choice) {
            case 1 -> handleSignIn();
            case 2 -> handleRegister();
            case 3 -> handleDatabaseReconnect();
            case 4 -> {
                return false;
            }
            default -> System.out.println("  [!] Invalid option.");
        }
        return true;
    }

    private boolean runConsoleLoop() {
        while (currentUser != null) {
            printMainMenu();
            int choice = readMenuChoice(1, 11, 11);
            System.out.println();
            switch (choice) {
                case 1 -> handleDashboardOverview();
                case 2 -> handleLiveRequestFeed();
                case 3 -> handleInspectRequest();
                case 4 -> handleRunAttackDemo();
                case 5 -> handleDetectionRules();
                case 6 -> handleBlockedIps();
                case 7 -> handleMultithreadingMenu();
                case 8 -> handleFileIoMenu();
                case 9 -> handleDatabaseMenu();
                case 10 -> {
                    System.out.println("  [AUTH] Signed out: " + currentUser.getEmail());
                    currentUser = null;
                    return true;
                }
                case 11 -> {
                    return false;
                }
                default -> System.out.println("  [!] Invalid option.");
            }
            if (currentUser != null) {
                pausePrompt();
            }
        }
        return true;
    }

    private void handleSignIn() {
        System.out.println(LINE_THIN);
        System.out.println("                                          SIGN IN");
        System.out.println(LINE_THIN);
        String email = readRequiredString("Email: ");
        String password = readRequiredString("Password: ");
        if (email.isEmpty() || password.isEmpty()) {
            return;
        }
        try {
            currentUser = facade.getAuthService().login(email, password);
            System.out.printf("%n  [SUCCESS] Signed in as %s [%s] (orgId=%d)%n",
                    currentUser.getEmail(),
                    currentUser.getRole().toUpperCase(),
                    currentUser.getOrgId());
        } catch (AuthenticationException e) {
            System.err.println("\n  [AUTH ERROR] " + e.getMessage());
        } catch (DatabaseException e) {
            System.err.println("\n  [DB ERROR] " + e.getMessage());
        }
    }

    private void handleRegister() {
        System.out.println(LINE_THIN);
        System.out.println("                                   REGISTER VIEWER ACCOUNT");
        System.out.println(LINE_THIN);
        String email = readRequiredString("Email: ");
        String password = readRequiredString("Password (min 8 chars): ");
        if (email.isEmpty() || password.isEmpty()) {
            return;
        }
        try {
            User created = facade.getAuthService().register(email, password, facade.getActiveOrgId());
            System.out.printf("%n  [SUCCESS] Registered viewer account: %s (id=%d, orgId=%d)%n",
                    created.getEmail(), created.getId(), created.getOrgId());
        } catch (InvalidDataException e) {
            System.err.println("\n  [VALIDATION ERROR] " + e.getMessage());
        } catch (DatabaseException e) {
            System.err.println("\n  [DB ERROR] " + e.getMessage());
        }
    }

    private void handleDashboardOverview() {
        System.out.println(LINE_WIDE);
        System.out.println("                                 THREATGATE DASHBOARD OVERVIEW");
        System.out.println(LINE_WIDE);
        try {
            DashboardStats stats = facade.getDashboardService().getStats(currentUser.getOrgId());
            System.out.printf("  +----------------------+----------------------+----------------------+----------------------+%n");
            System.out.printf("  | TOTAL REQUESTS       | BLOCKED              | ALLOWED              | ACTIVE IP BLOCKS     |%n");
            System.out.printf("  +----------------------+----------------------+----------------------+----------------------+%n");
            System.out.printf("  | %-20d | %-20d | %-20d | %-20d |%n",
                    stats.getTotalRequests(),
                    stats.getTotalBlocked(),
                    stats.getTotalAllowed(),
                    stats.getActiveBlockedIps());
            System.out.printf("  +----------------------+----------------------+----------------------+----------------------+%n%n");

            System.out.println("  Attacks & Traffic by Category (Last 24h):");
            List<CategoryCount> categories = stats.getByCategory();
            if (categories.isEmpty()) {
                System.out.println("    (No traffic recorded in the last 24 hours yet)");
            } else {
                long maxCount = categories.stream().mapToLong(CategoryCount::getCount).max().orElse(1L);
                for (CategoryCount entry : categories) {
                    int bars = (int) Math.max(1L, Math.round((entry.getCount() * 30.0) / Math.max(1L, maxCount)));
                    System.out.printf("    %-16s | %-30s (%d)%n",
                            formatCategoryLabel(entry.getCategory()),
                            "#".repeat(bars),
                            entry.getCount());
                }
            }

            System.out.println("\n  Allowed vs. Blocked Timeline (Last Hour):");
            List<TimelineBucket> timeline = stats.getTimeline();
            if (timeline.isEmpty()) {
                System.out.println("    (No activity in the last hour)");
            } else {
                System.out.println("    +---------+----------+----------+");
                System.out.println("    | MINUTE  | ALLOWED  | BLOCKED  |");
                System.out.println("    +---------+----------+----------+");
                for (TimelineBucket bucket : timeline) {
                    System.out.printf("    | %-7s | %-8d | %-8d |%n",
                            bucket.getBucket(), bucket.getAllowed(), bucket.getBlocked());
                }
                System.out.println("    +---------+----------+----------+");
            }
        } catch (DatabaseException e) {
            System.err.println("  [DB ERROR] Could not load dashboard stats: " + e.getMessage());
        }
    }

    private void handleLiveRequestFeed() {
        System.out.println(LINE_THIN);
        System.out.println("                                      LIVE REQUEST FEED");
        System.out.println(LINE_THIN);
        System.out.println("  [1] View Recent Requests (Newest First)");
        System.out.println("  [2] Filter & Paginate Logs (Stream API)");
        System.out.println("  [3] Distinct Blocked IP Addresses");
        System.out.println("  [4] Top High-Risk Events");
        System.out.print("  Select option [1-4]: ");
        int sub = readMenuChoice(1, 4, 1);

        try {
            int orgId = currentUser.getOrgId();
            switch (sub) {
                case 1 -> {
                    int limit = readInt("Number of recent logs [1-200]: ", 1, 200);
                    printLogTable(facade.getAttackLogService().listRecentLogs(orgId, limit));
                }
                case 2 -> {
                    String cat = readOptionalString("Category filter (all/sqli/xss/path_traversal/brute_force/none) [all]: ");
                    String act = readOptionalString("Action filter (all/allowed/blocked) [all]: ");
                    int page = readInt("Page number [1-100]: ", 1, 100);
                    int size = readInt("Page size [1-50]: ", 1, 50);
                    printLogTable(facade.getAttackLogService().getPagedLogs(
                            orgId,
                            page,
                            size,
                            cat.isEmpty() ? "all" : cat,
                            act.isEmpty() ? "all" : act
                    ));
                }
                case 3 -> {
                    List<String> ips = facade.getAttackLogService().getDistinctBlockedIps(orgId);
                    System.out.println("\n  Distinct Blocked IPs (" + ips.size() + "):");
                    if (ips.isEmpty()) {
                        System.out.println("    (None)");
                    } else {
                        ips.forEach(ip -> System.out.println("    - " + ip));
                    }
                }
                case 4 -> {
                    int limit = readInt("Top N high-risk events [1-50]: ", 1, 50);
                    printLogTable(facade.getAttackLogService().getTopHighRiskLogs(orgId, limit));
                }
                default -> System.out.println("  [!] Unknown option.");
            }
        } catch (DatabaseException e) {
            System.err.println("  [DB ERROR] Failed querying logs: " + e.getMessage());
        }
    }

    private void handleInspectRequest() {
        System.out.println(LINE_THIN);
        System.out.println("                                INSPECT SINGLE HTTP REQUEST");
        System.out.println(LINE_THIN);
        String ipRaw = readOptionalString("Client IP [127.0.0.1]: ");
        String ip = ipRaw.isEmpty() ? "127.0.0.1" : ipRaw;
        String methodRaw = readOptionalString("HTTP Method [GET]: ");
        String method = methodRaw.isEmpty() ? "GET" : methodRaw.toUpperCase();
        String url = readRequiredString("Path + Query (e.g. /api/users?id=1' OR '1'='1): ");
        if (url.isEmpty()) {
            return;
        }
        String body = readOptionalString("Request Body (optional): ");
        String ua = readOptionalString("User-Agent [threatgate-cli/1.0]: ");
        if (ua.isEmpty()) {
            ua = "threatgate-cli/1.0";
        }
        String referer = readOptionalString("Referer (optional): ");
        String cookie = readOptionalString("Cookie (optional): ");
        int loginStatus = 0;
        if (facade.getBruteForceService().isLoginPath(url)) {
            loginStatus = readInt("Simulated upstream login status (0=ignore, 200=ok, 401=fail): ", 0, 599);
        }

        InspectionRequest request = new InspectionRequest(
                currentUser.getOrgId(),
                ip,
                method,
                url,
                body,
                ua,
                referer,
                cookie,
                loginStatus
        );
        TrafficPipelineService.WafDecision decision =
                facade.getTrafficPipelineService().processSingleRequest(request);

        System.out.println("\n  +----------------------------------------------------------------------+");
        System.out.printf("  | Decision Status : %-50s |%n",
                decision.isBlocked() ? "BLOCKED (HTTP " + decision.getHttpStatus() + ")" : "ALLOWED (HTTP 200)");
        System.out.printf("  | Category        : %-50s |%n", formatCategoryLabel(decision.getCategory()));
        System.out.printf("  | Risk Score      : %-50d |%n", decision.getRiskScore());
        System.out.printf("  | Reason          : %-50s |%n", truncate(decision.getReason(), 50));
        System.out.println("  +----------------------------------------------------------------------+");
    }

    private void handleRunAttackDemo() {
        System.out.println(LINE_THIN);
        System.out.println("                       RUN AUTOMATED ATTACK DEMO (PRODUCER-CONSUMER)");
        System.out.println(LINE_THIN);
        System.out.println("  Dispatching benign, SQLi, XSS, double-encoded traversal, login brute-force,");
        System.out.println("  and repeated attack-strike waves through the multithreaded WAF pipeline...");
        try {
            List<TrafficPipelineService.WafDecision> results =
                    facade.getTrafficPipelineService().runAttackDemoBatch(currentUser.getOrgId());
            long blockedCount = results.stream().filter(TrafficPipelineService.WafDecision::isBlocked).count();
            long allowedCount = results.size() - blockedCount;
            System.out.printf("%n  Processed %d requests: %d allowed, %d blocked.%n%n",
                    results.size(), allowedCount, blockedCount);
            System.out.println("  +----+-----------------+--------+------------------------------------------+-----------------+------+---------+");
            System.out.println("  | #  | IP ADDRESS      | METHOD | PATH                                     | CATEGORY        | RISK | ACTION  |");
            System.out.println("  +----+-----------------+--------+------------------------------------------+-----------------+------+---------+");
            int idx = 1;
            for (TrafficPipelineService.WafDecision d : results) {
                AttackLog log = d.getLog();
                System.out.printf("  | %-2d | %-15s | %-6s | %-40s | %-15s | %-4d | %-7s |%n",
                        idx++,
                        truncate(log.getIpAddress(), 15),
                        truncate(log.getMethod(), 6),
                        truncate(log.getPath(), 40),
                        truncate(formatCategoryLabel(log.getCategory()), 15),
                        log.getRiskScore(),
                        log.getAction().toUpperCase());
            }
            System.out.println("  +----+-----------------+--------+------------------------------------------+-----------------+------+---------+");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println("  [INTERRUPTED] Attack demo interrupted.");
        }
    }

    private void handleDetectionRules() {
        System.out.println(LINE_THIN);
        System.out.println("                                   DETECTION RULES ENGINE");
        System.out.println(LINE_THIN);
        System.out.println("  [1] View All Rules");
        System.out.println("  [2] Filter Rules by Category");
        System.out.println("  [3] Toggle Rule Active ON/OFF (Admin)");
        System.out.println("  [4] Change Rule Weight 1-100 (Admin)");
        System.out.println("  [5] Add Custom Regex Rule (Admin)");
        System.out.println("  [6] Delete Custom Rule (Admin)");
        System.out.print("  Select option [1-6]: ");
        int sub = readMenuChoice(1, 6, 1);

        int orgId = currentUser.getOrgId();
        try {
            switch (sub) {
                case 1 -> printRuleTable(facade.getRuleService().listRules(orgId));
                case 2 -> {
                    String cat = readRequiredString("Category (sqli/xss/path_traversal/other): ");
                    printRuleTable(facade.getRuleService().filterRulesByCategory(orgId, cat));
                }
                case 3 -> {
                    int ruleId = readInt("Rule ID to toggle: ", 1, Integer.MAX_VALUE);
                    DetectionRule existing = facade.getRuleService().findById(orgId, ruleId);
                    DetectionRule updated = facade.getRuleService().updateRule(
                            currentUser, ruleId, !existing.isActive(), null);
                    System.out.printf("  [SUCCESS] Rule #%d is now %s.%n",
                            updated.getId(), updated.isActive() ? "ON" : "OFF");
                }
                case 4 -> {
                    int ruleId = readInt("Rule ID to re-weight: ", 1, Integer.MAX_VALUE);
                    int weight = readInt("New weight [1-100]: ", 1, 100);
                    DetectionRule updated = facade.getRuleService().updateRule(
                            currentUser, ruleId, null, weight);
                    System.out.printf("  [SUCCESS] Rule #%d weight updated to %d.%n",
                            updated.getId(), updated.getWeight());
                }
                case 5 -> {
                    String cat = readRequiredString("Category (sqli/xss/path_traversal/other): ");
                    String pattern = readRequiredString("Java Regex Pattern: ");
                    int weight = readInt("Weight [1-100]: ", 1, 100);
                    String desc = readRequiredString("Description: ");
                    DetectionRule created = facade.getRuleService().addRule(currentUser, cat, pattern, weight, desc);
                    System.out.println("  [SUCCESS] Added rule #" + created.getId() + ": " + created.getDescription());
                }
                case 6 -> {
                    int ruleId = readInt("Rule ID to delete: ", 1, Integer.MAX_VALUE);
                    facade.getRuleService().deleteRule(currentUser, ruleId);
                    System.out.println("  [SUCCESS] Deleted rule #" + ruleId);
                }
                default -> System.out.println("  [!] Unknown option.");
            }
        } catch (UnauthorizedRoleException e) {
            System.err.println("\n  [ACCESS DENIED] " + e.getMessage());
        } catch (EntityNotFoundException | InvalidDataException | DatabaseException e) {
            System.err.println("\n  [ERROR] " + e.getMessage());
        }
    }

    private void handleBlockedIps() {
        System.out.println(LINE_THIN);
        System.out.println("                              BLOCKED IPS MANAGEMENT (ADMIN ONLY)");
        System.out.println(LINE_THIN);
        try {
            facade.getAuthService().requireRole(currentUser, "admin");
        } catch (UnauthorizedRoleException e) {
            System.err.println("  [ACCESS DENIED] " + e.getMessage());
            return;
        }

        System.out.println("  [1] View Active Blocked IPs");
        System.out.println("  [2] Manually Block an IP");
        System.out.println("  [3] Unblock IP by Record ID");
        System.out.println("  [4] Purge Expired IP Blocks Now");
        System.out.print("  Select option [1-4]: ");
        int sub = readMenuChoice(1, 4, 1);

        try {
            switch (sub) {
                case 1 -> printBlockedIpTable(facade.getBruteForceService().listBlockedIps(currentUser));
                case 2 -> {
                    String ip = readRequiredString("IP Address to block: ");
                    String reason = readOptionalString("Reason [Manual admin block]: ");
                    int mins = readInt("Duration in minutes (0 = Permanent): ", 0, 525600);
                    Long durationMs = mins > 0 ? mins * 60_000L : null;
                    BlockedIp blocked = facade.getBruteForceService().manualBlockIp(currentUser, ip, reason, durationMs);
                    System.out.println("  [SUCCESS] Blocked IP: " + blocked);
                }
                case 3 -> {
                    int blockId = readInt("Blocked IP Record ID to unblock: ", 1, Integer.MAX_VALUE);
                    BlockedIp removed = facade.getBruteForceService().unblockIp(currentUser, blockId);
                    System.out.println("  [SUCCESS] Unblocked IP " + removed.getIpAddress() + " and cleared sliding windows.");
                }
                case 4 -> {
                    int purged = facade.getBruteForceService().purgeExpired();
                    System.out.println("  [SUCCESS] Purged " + purged + " expired IP block(s).");
                }
                default -> System.out.println("  [!] Unknown option.");
            }
        } catch (UnauthorizedRoleException e) {
            System.err.println("  [ACCESS DENIED] " + e.getMessage());
        } catch (EntityNotFoundException | InvalidDataException | DatabaseException e) {
            System.err.println("  [ERROR] " + e.getMessage());
        }
    }

    private void handleMultithreadingMenu() {
        System.out.println(LINE_THIN);
        System.out.println("                    MULTITHREADED SIMULATOR & THREAD LIFECYCLE MONITOR");
        System.out.println(LINE_THIN);
        System.out.println("  [1] Start Live Producer-Consumer Traffic Simulator");
        System.out.println("  [2] Stop Live Traffic Simulator");
        System.out.println("  [3] Capture Thread Lifecycle & All 6 States Report");
        System.out.println("  [4] Run Sequential vs Concurrent Execution Benchmark");
        System.out.print("  Select option [1-4]: ");
        int sub = readMenuChoice(1, 4, 3);

        int orgId = currentUser.getOrgId();
        try {
            switch (sub) {
                case 1 -> {
                    long interval = readInt("Producer delay between requests (ms) [50-10000]: ", 50, 10000);
                    facade.getTrafficPipelineService().startLiveSimulation(orgId, interval);
                    System.out.println("  [THREAD] Live Producer-Consumer simulator started.");
                }
                case 2 -> {
                    facade.getTrafficPipelineService().stopLiveSimulation();
                    System.out.println("  [THREAD] Live simulator stopped and joined cleanly.");
                }
                case 3 -> {
                    List<String> report = facade.getTrafficPipelineService().captureThreadLifecycleReport();
                    System.out.println();
                    report.forEach(line -> System.out.println("  " + line));
                }
                case 4 -> {
                    int count = readInt("Number of requests to benchmark [10-500]: ", 10, 500);
                    TrafficPipelineService.BenchmarkReport bench =
                            facade.getTrafficPipelineService().runSequentialVsConcurrentBenchmark(orgId, count);
                    System.out.println("\n  +--------------------------------------------------------------+");
                    System.out.printf("  | Total Requests        : %-36d |%n", bench.getTotalRequests());
                    System.out.printf("  | Sequential Processed  : %-10d (%d ms)                  |%n",
                            bench.getSequentialProcessed(), bench.getSequentialMs());
                    System.out.printf("  | Concurrent (%d Threads): %-10d (%d ms)                  |%n",
                            bench.getWorkerCount(), bench.getConcurrentProcessed(), bench.getConcurrentMs());
                    System.out.println("  +--------------------------------------------------------------+");
                }
                default -> System.out.println("  [!] Unknown option.");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println("  [INTERRUPTED] Thread operation interrupted.");
        }
    }

    private void handleFileIoMenu() {
        System.out.println(LINE_THIN);
        System.out.println("                  FILE I/O: CSV, BYTE STREAMS & STREAMTOKENIZER");
        System.out.println(LINE_THIN);
        System.out.println("  [1] Export Rules, Attack Logs & Blocked IPs to CSV");
        System.out.println("  [2] Import Rules from CSV (Admin)");
        System.out.println("  [3] Generate & Parse Tokenized Rules File (StreamTokenizer)");
        System.out.println("  [4] Write & Read Binary Audit Snapshot (FileOutputStream / FileInputStream)");
        System.out.println("  [5] Copy Attack Logs CSV Byte-by-Byte (Backup)");
        System.out.print("  Select option [1-5]: ");
        int sub = readMenuChoice(1, 5, 1);

        int orgId = currentUser.getOrgId();
        FilePersistenceService fps = facade.getFilePersistenceService();
        try {
            switch (sub) {
                case 1 -> {
                    fps.exportRulesToCsv(facade.getRuleService().listRules(orgId), facade.getRulesCsvPath());
                    fps.exportAttackLogsToCsv(facade.getAttackLogService().listAllLogs(orgId), facade.getAttackLogsCsvPath());
                    fps.exportBlockedIpsToCsv(facade.getBruteForceService().listActiveBlockedIpsInternal(orgId), facade.getBlockedIpsCsvPath());
                    System.out.println("  [SUCCESS] Exported CSV files to: " + facade.getDataDirectory());
                }
                case 2 -> {
                    facade.getAuthService().requireRole(currentUser, "admin");
                    String path = readOptionalString("CSV path [" + facade.getRulesCsvPath() + "]: ");
                    String target = path.isEmpty() ? facade.getRulesCsvPath() : path;
                    FilePersistenceService.CsvImportResult<DetectionRule> result = fps.importRulesFromCsv(target);
                    facade.getRuleService().replaceRules(result.getItems());
                    System.out.printf("  [SUCCESS] Imported %d rules (skipped %d malformed lines).%n",
                            result.getItems().size(), result.getSkippedCount());
                }
                case 3 -> {
                    String tokenPath = facade.getDataDirectory() + File.separator + "sample_rules_tokens.txt";
                    File file = new File(tokenPath);
                    if (!file.exists()) {
                        fps.writeSampleTokenizedRulesFile(tokenPath);
                    }
                    FilePersistenceService.TokenizedRuleParseResult parsed =
                            fps.parseTokenizedRulesFile(orgId, tokenPath);
                    System.out.printf("  [StreamTokenizer] Parsed %d valid rule(s), skipped %d line(s) from %s:%n",
                            parsed.getRules().size(), parsed.getSkippedCount(), tokenPath);
                    for (DetectionRule rule : parsed.getRules()) {
                        System.out.printf("    -> [%s] weight=%d pattern=%s (%s)%n",
                                rule.getCategory(), rule.getWeight(), rule.getPattern(), rule.getDescription());
                    }
                    if (currentUser.isAdmin() && !parsed.getRules().isEmpty()) {
                        String apply = readOptionalString("Import these tokenized rules into active engine? (y/N): ");
                        if ("y".equalsIgnoreCase(apply) || "yes".equalsIgnoreCase(apply)) {
                            int added = 0;
                            for (DetectionRule rule : parsed.getRules()) {
                                facade.getRuleService().addRule(
                                        currentUser, rule.getCategory(), rule.getPattern(), rule.getWeight(), rule.getDescription());
                                added++;
                            }
                            System.out.println("  [SUCCESS] Added " + added + " tokenized rule(s).");
                        }
                    }
                }
                case 4 -> {
                    String binPath = facade.getDataDirectory() + File.separator + "audit_snapshot.bin";
                    DashboardStats stats = facade.getDashboardService().getStats(orgId);
                    List<AttackLog> logs = facade.getAttackLogService().listRecentLogs(orgId, 100);
                    fps.writeBinaryAuditSnapshot(stats, logs, binPath);
                    FilePersistenceService.AuditSnapshotSummary summary = fps.readBinaryAuditSnapshot(binPath);
                    System.out.println("  [FileOutputStream/FileInputStream] Binary Audit Snapshot Verified:");
                    System.out.printf("    File=%s | Total=%d | Blocked=%d | Allowed=%d | ActiveBlocks=%d | Previews=%d%n",
                            binPath,
                            summary.getTotalRequests(),
                            summary.getTotalBlocked(),
                            summary.getTotalAllowed(),
                            summary.getActiveBlockedIps(),
                            summary.getLogPreviews().size());
                }
                case 5 -> {
                    String src = facade.getAttackLogsCsvPath();
                    fps.exportAttackLogsToCsv(facade.getAttackLogService().listAllLogs(orgId), src);
                    String dst = facade.getDataDirectory() + File.separator + "attack_logs_backup.csv";
                    long bytes = fps.copyFileByteByByte(src, dst);
                    System.out.printf("  [Byte Stream Copy] Copied %d bytes to %s%n", bytes, dst);
                }
                default -> System.out.println("  [!] Unknown option.");
            }
        } catch (UnauthorizedRoleException e) {
            System.err.println("  [ACCESS DENIED] " + e.getMessage());
        } catch (InvalidDataException | DatabaseException | IOException e) {
            System.err.println("  [ERROR] " + e.getMessage());
        }
    }

    private void handleDatabaseMenu() {
        System.out.println(LINE_THIN);
        System.out.println("                               DATABASE / JDBC SETTINGS");
        System.out.println(LINE_THIN);
        DatabaseConfig cfg = facade.getDatabaseConfig();
        System.out.println("  Driver       : " + cfg.getDriver());
        System.out.println("  JDBC URL     : " + cfg.getUrl());
        System.out.println("  User         : " + cfg.getUser());
        System.out.println("  Mode         : " + (facade.isDatabaseActive() ? "MYSQL JDBC ACTIVE" : "OFFLINE CSV FALLBACK"));
        String lastErr = facade.getDatabaseConnection().getLastError();
        if (!lastErr.isEmpty()) {
            System.out.println("  Last DB Info : " + lastErr);
        }
        System.out.println(LINE_THIN);
        System.out.println("  [1] Reconnect / Configure MySQL Credentials");
        System.out.println("  [2] Re-run Schema Initializer & Default Seed");
        System.out.println("  [3] Save Offline CSV State Now");
        System.out.print("  Select option [1-3]: ");
        int sub = readMenuChoice(1, 3, 3);

        switch (sub) {
            case 1 -> handleDatabaseReconnect();
            case 2 -> {
                try {
                    facade.reinitializeSchema();
                    System.out.println("  [SUCCESS] Schema initialized and verified for orgId=" + facade.getActiveOrgId());
                } catch (DatabaseException e) {
                    System.err.println("  [DB ERROR] " + e.getMessage());
                }
            }
            case 3 -> {
                try {
                    facade.saveOfflineState();
                    System.out.println("  [SUCCESS] Saved offline CSV state into " + facade.getDataDirectory());
                } catch (IOException e) {
                    System.err.println("  [I/O ERROR] " + e.getMessage());
                }
            }
            default -> System.out.println("  [!] Unknown option.");
        }
    }

    private void handleDatabaseReconnect() {
        System.out.println(LINE_THIN);
        System.out.println("                            MYSQL JDBC CONNECTION SETUP");
        System.out.println(LINE_THIN);
        String host = readOptionalString("MySQL Host [localhost]: ");
        int port = readInt("MySQL Port [3306]: ", 1, 65535);
        String dbName = readOptionalString("Database Name [threatgate]: ");
        String user = readOptionalString("MySQL User [root]: ");
        String password = readOptionalString("MySQL Password (leave blank if empty): ");
        String saveAns = readOptionalString("Save credentials to db.properties? (y/N): ");
        boolean saveConfig = "y".equalsIgnoreCase(saveAns) || "yes".equalsIgnoreCase(saveAns);

        try {
            facade.reconnectDatabase(host, port, dbName, user, password, saveConfig);
            System.out.println("\n  [SUCCESS] Connected to MySQL JDBC and initialized ThreatGate schema!");
        } catch (DatabaseException e) {
            System.err.println("\n  [DB ERROR] " + e.getMessage());
            System.out.println("  Continuing in Offline CSV Fallback Mode.");
        }
    }

    private void printLandingBanner() {
        System.out.println(LINE_WIDE);
        System.out.println("                THREATGATE - REVERSE-PROXY WEB APPLICATION FIREWALL (JAVA CLI)");
        System.out.println("      Real-time protection against SQL injection, XSS, path traversal, and brute-force attacks.");
        System.out.println(LINE_WIDE);
    }

    private void printStorageBanner() {
        if (facade.isDatabaseActive()) {
            System.out.println("  [Storage] MySQL JDBC CONNECTED -> " + facade.getDatabaseConfig().getUrl());
        } else {
            System.out.println("  [Storage] Offline CSV Fallback Mode active -> " + facade.getDataDirectory());
        }
    }

    private void printMainMenu() {
        System.out.println(LINE_WIDE);
        System.out.printf("  THREATGATE CONSOLE | User: %s [%s] | Mode: %s | Sim: %s%n",
                currentUser.getEmail(),
                currentUser.getRole().toUpperCase(),
                facade.isDatabaseActive() ? "MYSQL-JDBC" : "OFFLINE-CSV",
                facade.getTrafficPipelineService().isSimulationRunning() ? "RUNNING" : "IDLE");
        System.out.println(LINE_WIDE);
        System.out.println("  [1]  Dashboard Overview (Stat Cards, 24h Category Chart, 1h Timeline)");
        System.out.println("  [2]  Live Request Feed (Recent, Stream Filter/Pagination, High-Risk)");
        System.out.println("  [3]  Inspect Single HTTP Request (Interactive WAF Engine)");
        System.out.println("  [4]  Run Automated Attack Demo (Multithreaded Pipeline)");
        System.out.println("  [5]  Detection Rules (View & Admin Live Controls)");
        System.out.println("  [6]  Blocked IPs Management (Admin Only)");
        System.out.println("  [7]  Multithreaded Simulator, Thread Lifecycle & Benchmark");
        System.out.println("  [8]  File I/O Tools (CSV, Byte Streams & StreamTokenizer)");
        System.out.println("  [9]  Database / JDBC Connection Settings");
        System.out.println("  [10] Sign Out");
        System.out.println("  [11] Save & Exit");
        System.out.println(LINE_WIDE);
        System.out.print("  Select an option [1-11]: ");
    }

    private void printGoodbyeBanner() {
        System.out.println(LINE_WIDE);
        System.out.println("                     ThreatGate CLI safely shut down. All state persisted.");
        System.out.println(LINE_WIDE);
    }

    private void printLogTable(List<AttackLog> logs) {
        if (logs.isEmpty()) {
            System.out.println("  No request logs matched.");
            return;
        }
        SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss");
        System.out.println("  +------+----------+-----------------+--------+----------------------------------+-----------------+------+---------+");
        System.out.println("  | ID   | TIME     | IP ADDRESS      | METHOD | PATH                             | CATEGORY        | RISK | ACTION  |");
        System.out.println("  +------+----------+-----------------+--------+----------------------------------+-----------------+------+---------+");
        for (AttackLog log : logs) {
            String timeStr = log.getCreatedAt() != null ? timeFormat.format(new Date(log.getCreatedAt().getTime())) : "--";
            System.out.printf("  | %-4d | %-8s | %-15s | %-6s | %-32s | %-15s | %-4d | %-7s |%n",
                    log.getId(),
                    timeStr,
                    truncate(log.getIpAddress(), 15),
                    truncate(log.getMethod(), 6),
                    truncate(log.getPath(), 32),
                    truncate(formatCategoryLabel(log.getCategory()), 15),
                    log.getRiskScore(),
                    log.getAction().toUpperCase());
        }
        System.out.println("  +------+----------+-----------------+--------+----------------------------------+-----------------+------+---------+");
        System.out.println("  Rows displayed: " + logs.size());
    }

    private void printRuleTable(List<DetectionRule> rules) {
        if (rules.isEmpty()) {
            System.out.println("  No detection rules found.");
            return;
        }
        System.out.println("  +----+-----------------+--------+--------+--------------------------------------+------------------------------+");
        System.out.println("  | ID | CATEGORY        | WEIGHT | ACTIVE | WHAT IT CATCHES                      | PATTERN                      |");
        System.out.println("  +----+-----------------+--------+--------+--------------------------------------+------------------------------+");
        for (DetectionRule rule : rules) {
            System.out.printf("  | %-2d | %-15s | %-6d | %-6s | %-36s | %-28s |%n",
                    rule.getId(),
                    truncate(formatCategoryLabel(rule.getCategory()), 15),
                    rule.getWeight(),
                    rule.isActive() ? "ON" : "OFF",
                    truncate(rule.getDescription(), 36),
                    truncate(rule.getPattern(), 28));
        }
        System.out.println("  +----+-----------------+--------+--------+--------------------------------------+------------------------------+");
        System.out.println("  Total rules listed: " + rules.size());
    }

    private void printBlockedIpTable(List<BlockedIp> blocks) {
        if (blocks.isEmpty()) {
            System.out.println("  No active blocked IPs right now.");
            return;
        }
        SimpleDateFormat dtFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        System.out.println("  +----+-----------------+--------------------------------------+---------------------+---------------------+");
        System.out.println("  | ID | IP ADDRESS      | REASON                               | BLOCKED AT          | EXPIRES AT          |");
        System.out.println("  +----+-----------------+--------------------------------------+---------------------+---------------------+");
        for (BlockedIp block : blocks) {
            String blockedStr = block.getBlockedAt() != null ? dtFormat.format(new Date(block.getBlockedAt().getTime())) : "-";
            String expiresStr = block.getExpiresAt() != null
                    ? dtFormat.format(new Date(block.getExpiresAt().getTime()))
                    : "Permanent";
            System.out.printf("  | %-2d | %-15s | %-36s | %-19s | %-19s |%n",
                    block.getId(),
                    truncate(block.getIpAddress(), 15),
                    truncate(block.getReason() != null ? block.getReason() : "-", 36),
                    blockedStr,
                    expiresStr);
        }
        System.out.println("  +----+-----------------+--------------------------------------+---------------------+---------------------+");
    }

    private String formatCategoryLabel(String category) {
        if (category == null) {
            return "Normal";
        }
        return switch (category.toLowerCase()) {
            case "sqli" -> "SQL Injection";
            case "xss" -> "XSS";
            case "path_traversal" -> "Path Traversal";
            case "brute_force" -> "Brute Force";
            case "other" -> "Other";
            default -> "Normal";
        };
    }

    private String truncate(String value, int maxLength) {
        if (value == null) {
            return "";
        }
        if (value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, Math.max(0, maxLength - 3)) + "...";
    }

    private void pausePrompt() {
        System.out.print("\n  Press [Enter] to continue...");
        if (scanner.hasNextLine()) {
            scanner.nextLine();
        }
        System.out.println();
    }

    private int readMenuChoice(int min, int max, int eofFallback) {
        while (true) {
            if (!scanner.hasNextLine()) {
                return eofFallback;
            }
            String input = scanner.nextLine().trim();
            try {
                int value = Integer.parseInt(input);
                if (value >= min && value <= max) {
                    return value;
                }
                System.out.printf("  [!] Please enter a number between %d and %d: ", min, max);
            } catch (NumberFormatException e) {
                System.out.printf("  [!] Invalid number. Please enter [%d-%d]: ", min, max);
            }
        }
    }

    private int readInt(String prompt, int min, int max) {
        while (true) {
            System.out.print("  " + prompt);
            if (!scanner.hasNextLine()) {
                return min;
            }
            String input = scanner.nextLine().trim();
            try {
                int value = Integer.parseInt(input);
                if (value >= min && value <= max) {
                    return value;
                }
                System.out.printf("  [!] Value must be between %d and %d.%n", min, max);
            } catch (NumberFormatException e) {
                System.out.println("  [!] Invalid integer input.");
            }
        }
    }

    private String readRequiredString(String prompt) {
        while (true) {
            System.out.print("  " + prompt);
            if (!scanner.hasNextLine()) {
                return "";
            }
            String input = scanner.nextLine().trim();
            if (!input.isEmpty()) {
                return input;
            }
            System.out.println("  [!] This field cannot be blank.");
        }
    }

    private String readOptionalString(String prompt) {
        System.out.print("  " + prompt);
        if (!scanner.hasNextLine()) {
            return "";
        }
        return scanner.nextLine().trim();
    }
}
