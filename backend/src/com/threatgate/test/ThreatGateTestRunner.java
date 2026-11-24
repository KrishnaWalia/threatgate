package com.threatgate.test;

import com.threatgate.db.DatabaseConfig;
import com.threatgate.db.DatabaseConnection;
import com.threatgate.exception.AuthenticationException;
import com.threatgate.exception.InvalidDataException;
import com.threatgate.exception.UnauthorizedRoleException;
import com.threatgate.model.AttackLog;
import com.threatgate.model.BlockedIp;
import com.threatgate.model.DashboardStats;
import com.threatgate.model.DetectionRule;
import com.threatgate.model.GenericStore;
import com.threatgate.model.InspectionRequest;
import com.threatgate.model.InspectionResult;
import com.threatgate.model.User;
import com.threatgate.service.AuthService;
import com.threatgate.service.BruteForceService;
import com.threatgate.service.DetectionEngine;
import com.threatgate.service.ExpirySweeperWorker;
import com.threatgate.service.FilePersistenceService;
import com.threatgate.service.RequestBuffer;
import com.threatgate.service.RuleService;
import com.threatgate.service.SlidingWindow;
import com.threatgate.service.ThreatGateFacade;
import com.threatgate.service.TrafficPipelineService;
import java.io.File;
import java.io.FileWriter;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public final class ThreatGateTestRunner {
    private static int passCount = 0;

    private ThreatGateTestRunner() {
    }

    public static void main(String[] args) throws Exception {
        System.out.println(">>> Starting ThreatGate Java CLI Backend Verification Suite <<<\n");

        String baseDir = resolveBackendBaseDir();
        String testDataDir = baseDir + File.separator + "data" + File.separator + "test_suite_run";
        deleteRecursive(new File(testDataDir));

        String configPath = baseDir + File.separator + "db.properties";
        String examplePath = baseDir + File.separator + "db.properties.example";

        ThreatGateFacade facade = new ThreatGateFacade(testDataDir, configPath, examplePath, false, 0L);

        try {
            User[] users = runAuthAndRbacTests(facade);
            User admin = users[0];
            User viewer = users[1];

            runDetectionEngineTests(facade);
            runRulesAsDataTests(facade, admin, viewer);
            runBruteForceAndExpiryTests(facade, admin, viewer);
            runDashboardAndStreamTests(facade);
            runGenericsTests();
            runMultithreadingTests(facade);
            runFileIoTests(facade, testDataDir);
            runJdbcAndPersistenceReloadTests(testDataDir, configPath, examplePath);

            System.out.printf("%n>>> ALL %d THREATGATE VERIFICATION ASSERTIONS PASSED SUCCESSFULLY! <<<%n", passCount);
        } finally {
            facade.shutdown();
            deleteRecursive(new File(testDataDir));
        }
    }

    private static User[] runAuthAndRbacTests(ThreatGateFacade facade) throws Exception {
        AuthService auth = facade.getAuthService();

        User admin = auth.login(AuthService.DEFAULT_ADMIN_EMAIL, AuthService.DEFAULT_ADMIN_PASSWORD);
        assertCondition(admin.isAdmin() && admin.getOrgId() == 1, "Test 1.1: Admin login succeeded with admin role");

        User viewer = auth.login(AuthService.DEFAULT_VIEWER_EMAIL, AuthService.DEFAULT_VIEWER_PASSWORD);
        assertCondition(!viewer.isAdmin() && "viewer".equals(viewer.getRole()), "Test 1.2: Viewer login succeeded");

        String wrongPassMsg = "";
        String unknownUserMsg = "";
        try {
            auth.login(AuthService.DEFAULT_ADMIN_EMAIL, "WrongPass123");
            fail("Expected AuthenticationException for wrong password");
        } catch (AuthenticationException e) {
            wrongPassMsg = e.getMessage();
        }
        try {
            auth.login("nobody@threatgate.dev", "WrongPass123");
            fail("Expected AuthenticationException for unknown email");
        } catch (AuthenticationException e) {
            unknownUserMsg = e.getMessage();
        }
        assertCondition(wrongPassMsg.equals(unknownUserMsg), "Test 1.3: Identical error message prevents email enumeration");

        User registered = auth.register("analyst@threatgate.dev", "Analyst123!", 1);
        assertCondition("viewer".equals(registered.getRole()), "Test 1.4: Public registration always creates viewer role");

        try {
            auth.register("analyst@threatgate.dev", "Analyst123!", 1);
            fail("Expected InvalidDataException on duplicate email");
        } catch (InvalidDataException e) {
            assertCondition(true, "Test 1.5: Duplicate registration rejected");
        }

        return new User[] { admin, viewer };
    }

    private static void runDetectionEngineTests(ThreatGateFacade facade) {
        DetectionEngine engine = facade.getDetectionEngine();
        RuleService ruleService = facade.getRuleService();
        List<DetectionRule> rules = ruleService.getActiveRules(1);
        Map<Integer, Pattern> compiled = ruleService.getCompiledPatternsSnapshot();

        assertCondition(rules.size() == 22 && compiled.size() == 22,
                "Test 2.1: All 22 default ThreatGate rules compiled cleanly");

        InspectionResult clean = engine.inspect(
                new InspectionRequest(1, "10.0.0.1", "GET", "/search?q=hello", "", "Mozilla/5.0"),
                rules, compiled);
        assertCondition(!clean.isBlocked() && clean.getRiskScore() == 0,
                "Test 2.2: Benign query allowed with risk=0");

        InspectionResult obrien = engine.inspect(
                new InspectionRequest(1, "10.0.0.2", "GET", "/search?q=O'Brien", "", "Mozilla/5.0"),
                rules, compiled);
        assertCondition(!obrien.isBlocked(),
                "Test 2.3: Benign apostrophe (O'Brien) allowed without false positive");

        InspectionResult selectProse = engine.inspect(
                new InspectionRequest(1, "10.0.0.3", "GET", "/search?q=select+the+best+items+from+our+store", "", "Mozilla/5.0"),
                rules, compiled);
        assertCondition(!selectProse.isBlocked() && selectProse.getRiskScore() == 40,
                "Test 2.4: Weak SQL signal alone scores 40 (<50) and stays allowed");

        InspectionResult weakCombo = engine.inspect(
                new InspectionRequest(1, "10.0.0.4", "GET", "/search?q=select+item+from+users&cb=alert(1)", "", "Mozilla/5.0"),
                rules, compiled);
        assertCondition(weakCombo.isBlocked() && weakCombo.getRiskScore() == 60,
                "Test 2.5: Two weak signals corroborate (40 + 0.5*40 = 60) and block");

        InspectionResult sqliCommentBypass = engine.inspect(
                new InspectionRequest(1, "10.0.0.5", "GET", "/api/users?id=1+UNION/**/SELECT+password+FROM+users", "", "Mozilla/5.0"),
                rules, compiled);
        assertCondition(sqliCommentBypass.isBlocked() && "sqli".equals(sqliCommentBypass.getCategory()),
                "Test 2.6: SQL inline comment bypass (UNION/**/SELECT) detected and blocked as sqli");

        InspectionResult xssEntity = engine.inspect(
                new InspectionRequest(1, "10.0.0.6", "POST", "/comments", "text=&#60;script&#62;alert(1)", "Mozilla/5.0"),
                rules, compiled);
        assertCondition(xssEntity.isBlocked() && "xss".equals(xssEntity.getCategory()),
                "Test 2.7: HTML entity encoded XSS in request body detected and blocked as xss");

        InspectionResult doubleTraversal = engine.inspect(
                new InspectionRequest(1, "10.0.0.7", "GET", "/files?name=%252e%252e%252f%252e%252e%252fetc/passwd", "", "Mozilla/5.0"),
                rules, compiled);
        assertCondition(doubleTraversal.isBlocked() && "path_traversal".equals(doubleTraversal.getCategory()),
                "Test 2.8: Double URL-encoded path traversal detected and blocked");

        InspectionResult nullByte = engine.inspect(
                new InspectionRequest(1, "10.0.0.8", "GET", "/download?file=avatar.php%00.jpg", "", "Mozilla/5.0"),
                rules, compiled);
        assertCondition(nullByte.isBlocked() && "path_traversal".equals(nullByte.getCategory()),
                "Test 2.9: Null byte (%00) path traversal payload detected and blocked");

        InspectionResult headerAttack = engine.inspect(
                new InspectionRequest(1, "10.0.0.9", "GET", "/home", "", "<script>alert(1)</script>"),
                rules, compiled);
        assertCondition(headerAttack.isBlocked() && "xss".equals(headerAttack.getCategory()),
                "Test 2.10: Attack payload in User-Agent header detected and blocked");

        InspectionResult repeatPayload = engine.inspect(
                new InspectionRequest(1, "10.0.0.10", "POST", "/q?x=alert(1)", "y=alert(1)", "alert(1)"),
                rules, compiled);
        assertCondition(!repeatPayload.isBlocked() && repeatPayload.getRiskScore() == 40,
                "Test 2.11: Repeating one weak rule across targets counts once (risk=40)");
    }

    private static void runRulesAsDataTests(ThreatGateFacade facade, User admin, User viewer) throws Exception {
        RuleService ruleService = facade.getRuleService();
        DetectionEngine engine = facade.getDetectionEngine();

        try {
            ruleService.updateRule(viewer, 10, false, null);
            fail("Expected UnauthorizedRoleException when viewer modifies a rule");
        } catch (UnauthorizedRoleException e) {
            assertCondition(true, "Test 3.1: Viewer blocked by RBAC from toggling rules");
        }

        ruleService.updateRule(admin, 10, false, null);
        InspectionResult afterDisable = engine.inspect(
                new InspectionRequest(1, "10.0.1.1", "GET", "/q?v=<script>x</script>", "", "Mozilla/5.0"),
                ruleService.getActiveRules(1),
                ruleService.getCompiledPatternsSnapshot());
        assertCondition(!afterDisable.isBlocked(), "Test 3.2: Disabling rule #10 immediately stops blocking <script>");

        ruleService.updateRule(admin, 10, true, 85);
        InspectionResult afterEnable = engine.inspect(
                new InspectionRequest(1, "10.0.1.1", "GET", "/q?v=<script>x</script>", "", "Mozilla/5.0"),
                ruleService.getActiveRules(1),
                ruleService.getCompiledPatternsSnapshot());
        assertCondition(afterEnable.isBlocked() && afterEnable.getRiskScore() == 85,
                "Test 3.3: Re-enabling rule #10 with weight 85 takes effect immediately");

        DetectionRule custom = ruleService.addRule(admin, "other", "\\bforbidden_secret\\b", 75, "Custom probe");
        InspectionResult customHit = engine.inspect(
                new InspectionRequest(1, "10.0.1.2", "GET", "/check?k=forbidden_secret", "", "Mozilla/5.0"),
                ruleService.getActiveRules(1),
                ruleService.getCompiledPatternsSnapshot());
        assertCondition(customHit.isBlocked() && customHit.getRiskScore() == 75,
                "Test 3.4: Custom dynamic regex rule matched and blocked");

        try {
            ruleService.addRule(admin, "other", "[invalid(", 60, "Bad regex");
            fail("Expected InvalidDataException on invalid regex");
        } catch (InvalidDataException e) {
            assertCondition(true, "Test 3.5: Invalid regex rejected safely");
        }

        ruleService.deleteRule(admin, custom.getId());
        assertCondition(ruleService.listRules(1).size() == 22, "Test 3.6: Custom rule deleted cleanly");
    }

    private static void runBruteForceAndExpiryTests(ThreatGateFacade facade, User admin, User viewer) throws Exception {
        SlidingWindow window = new SlidingWindow(60_000L);
        assertCondition(window.hit("k", 1000L) == 1, "Test 4.1a: SlidingWindow hit 1");
        assertCondition(window.hit("k", 59_000L) == 2, "Test 4.1b: SlidingWindow retains hits within 60s");
        assertCondition(window.hit("k", 62_000L) == 2, "Test 4.1c: SlidingWindow evicts expired hit outside 60s");

        TrafficPipelineService pipeline = facade.getTrafficPipelineService();
        BruteForceService bruteForce = facade.getBruteForceService();

        String bfIp = "198.51.100.200";
        for (int i = 0; i < bruteForce.getLoginFailMax(); i++) {
            pipeline.processSingleRequest(new InspectionRequest(1, bfIp, "POST", "/login", "u=a", "agent", "", "", 401));
        }
        TrafficPipelineService.WafDecision blockedAfterLoginFail = pipeline.processSingleRequest(
                new InspectionRequest(1, bfIp, "GET", "/home", "", "agent"));
        assertCondition(blockedAfterLoginFail.isBlocked() && "brute_force".equals(blockedAfterLoginFail.getCategory()),
                "Test 4.2: Failed login threshold auto-blocked IP");

        String okResetIp = "198.51.100.201";
        for (int i = 0; i < 3; i++) {
            pipeline.processSingleRequest(new InspectionRequest(1, okResetIp, "POST", "/login", "u=a", "agent", "", "", 401));
        }
        pipeline.processSingleRequest(new InspectionRequest(1, okResetIp, "POST", "/login", "u=a", "agent", "", "", 200));
        for (int i = 0; i < 4; i++) {
            pipeline.processSingleRequest(new InspectionRequest(1, okResetIp, "POST", "/login", "u=a", "agent", "", "", 401));
        }
        assertCondition(bruteForce.findActiveBlock(1, okResetIp).isEmpty(),
                "Test 4.3: Successful login resets failed login counter");

        String strikeIp = "192.0.2.202";
        for (int i = 0; i < bruteForce.getAttackStrikeMax(); i++) {
            pipeline.processSingleRequest(new InspectionRequest(1, strikeIp, "GET", "/search?q=<script>alert(1)</script>", "", "agent"));
        }
        assertCondition(bruteForce.findActiveBlock(1, strikeIp).isPresent(),
                "Test 4.4: Repeated attack strikes auto-blocked IP");

        try {
            bruteForce.listBlockedIps(viewer);
            fail("Expected UnauthorizedRoleException when viewer reads blocked IPs");
        } catch (UnauthorizedRoleException e) {
            assertCondition(true, "Test 4.5: Viewer denied blocked-ips list via RBAC");
        }

        List<BlockedIp> activeBlocks = bruteForce.listBlockedIps(admin);
        assertCondition(activeBlocks.size() >= 2, "Test 4.6: Admin listed active blocked IPs");

        BlockedIp bfRecord = activeBlocks.stream()
                .filter(b -> bfIp.equals(b.getIpAddress()))
                .findFirst()
                .orElseThrow();
        bruteForce.unblockIp(admin, bfRecord.getId());
        assertCondition(bruteForce.findActiveBlock(1, bfIp).isEmpty(),
                "Test 4.7: Admin unblock lifted IP block immediately");

        String shortIp = "203.0.113.210";
        bruteForce.manualBlockIp(admin, shortIp, "Short TTL test", 120L);
        assertCondition(bruteForce.findActiveBlock(1, shortIp).isPresent(),
                "Test 4.8a: Short TTL block active immediately");
        Thread.sleep(160L);
        assertCondition(bruteForce.findActiveBlock(1, shortIp).isEmpty(),
                "Test 4.8b: Short TTL block expired lazily without timer");
    }

    private static void runDashboardAndStreamTests(ThreatGateFacade facade) throws Exception {
        DashboardStats stats = facade.getDashboardService().getStats(1);
        assertCondition(
                stats.getTotalRequests() == stats.getTotalBlocked() + stats.getTotalAllowed() && stats.getTotalRequests() > 0,
                "Test 5.1: Dashboard stats totals reconcile (total == blocked + allowed)");
        assertCondition(!stats.getByCategory().isEmpty() && !stats.getTimeline().isEmpty(),
                "Test 5.2: Stream API aggregated 24h categories and 1h timeline buckets");

        List<AttackLog> sqliOnly = facade.getAttackLogService().getPagedLogs(1, 1, 5, "sqli", "blocked");
        assertCondition(sqliOnly.stream().allMatch(l -> "sqli".equals(l.getCategory()) && l.isBlocked()),
                "Test 5.3: Stream filter/skip/limit returned matching SQLi blocked logs");

        List<String> distinctIps = facade.getAttackLogService().getDistinctBlockedIps(1);
        assertCondition(!distinctIps.isEmpty() && distinctIps.stream().distinct().count() == distinctIps.size(),
                "Test 5.4: Stream distinct blocked IPs verified");

        List<AttackLog> highRisk = facade.getAttackLogService().getTopHighRiskLogs(1, 3);
        assertCondition(!highRisk.isEmpty() && highRisk.size() <= 3,
                "Test 5.5: Stream sorted top high-risk logs verified");
    }

    private static void runGenericsTests() throws Exception {
        GenericStore<DetectionRule, Integer> store = new GenericStore<>();
        Timestamp now = new Timestamp(System.currentTimeMillis());
        store.save(new DetectionRule(1, 1, "sqli", "a", 80, true, "Rule A", now));
        store.save(new DetectionRule(2, 1, "xss", "b", 40, false, "Rule B", now));

        List<String> strongCats = store.filterAndMap(
                r -> r.getWeight() >= 50,
                DetectionRule::getCategory
        );
        assertCondition(strongCats.size() == 1 && "sqli".equals(strongCats.get(0)),
                "Test 6.1: GenericStore filterAndMap with Predicate<? super T> & Function works");

        List<Object> sink = new ArrayList<>();
        store.copyTo(sink);
        assertCondition(sink.size() == 2 && GenericStore.countAll(store.findAll()) == 2,
                "Test 6.2: Upper and lower bounded wildcards verified");

        RequestBuffer<String> buffer = new RequestBuffer<>(2);
        buffer.produce("payload-1");
        assertCondition("payload-1".equals(buffer.consume()),
                "Test 6.3: Generic RequestBuffer<T> verified");
    }

    private static void runMultithreadingTests(ThreatGateFacade facade) throws Exception {
        TrafficPipelineService pipeline = facade.getTrafficPipelineService();

        List<TrafficPipelineService.WafDecision> demoResults = pipeline.runAttackDemoBatch(1);
        assertCondition(demoResults.size() >= 15,
                "Test 7.1: Multithreaded Producer-Consumer attack demo batch completed cleanly");

        long beforeCount = facade.getAttackLogService().listAllLogs(1).size();
        int threadCount = 8;
        int perThread = 25;
        List<Thread> workers = new ArrayList<>();
        for (int t = 0; t < threadCount; t++) {
            final int workerIdx = t;
            Thread worker = new Thread(() -> {
                for (int i = 0; i < perThread; i++) {
                    String ip = "172.16." + workerIdx + "." + (i + 1);
                    pipeline.processSingleRequest(
                            new InspectionRequest(1, ip, "GET", "/items?id=" + i, "", "stress-worker"));
                }
            }, "stress-worker-" + t);
            workers.add(worker);
        }
        for (Thread worker : workers) {
            worker.start();
        }
        for (Thread worker : workers) {
            worker.join();
        }
        long afterCount = facade.getAttackLogService().listAllLogs(1).size();
        assertCondition(afterCount - beforeCount == (long) threadCount * perThread,
                "Test 7.2: 8 concurrent threads recorded exact 200 logs with zero race-condition loss");

        ExpirySweeperWorker sweeper = new ExpirySweeperWorker("test-daemon-sweeper", facade.getBruteForceService(), 40L);
        assertCondition(sweeper.isDaemon() && sweeper.getPriority() == Thread.MIN_PRIORITY,
                "Test 7.3a: ExpirySweeperWorker configured as MIN_PRIORITY daemon thread");
        sweeper.start();
        Thread.sleep(150L);
        sweeper.stopWorker();
        sweeper.join(1000L);
        assertCondition(sweeper.getSweepCount() >= 1 && sweeper.getState() == Thread.State.TERMINATED,
                "Test 7.3b: Daemon sweeper executed and terminated cleanly on interrupt");

        List<String> lifecycleReport = pipeline.captureThreadLifecycleReport();
        String joinedReport = String.join("\n", lifecycleReport);
        boolean allSixStatesSeen = joinedReport.contains("state=NEW")
                && joinedReport.contains("state=RUNNABLE")
                && joinedReport.contains("state=BLOCKED")
                && joinedReport.contains("state=WAITING")
                && joinedReport.contains("state=TIMED_WAITING")
                && joinedReport.contains("state=TERMINATED");
        assertCondition(allSixStatesSeen,
                "Test 7.4: All 6 Thread lifecycle states (NEW, RUNNABLE, BLOCKED, WAITING, TIMED_WAITING, TERMINATED) observed");
    }

    private static void runFileIoTests(ThreatGateFacade facade, String testDataDir) throws Exception {
        FilePersistenceService fps = facade.getFilePersistenceService();

        String csvTestPath = testDataDir + File.separator + "rules_roundtrip.csv";
        List<DetectionRule> currentRules = facade.getRuleService().listRules(1);
        fps.exportRulesToCsv(currentRules, csvTestPath);
        try (FileWriter appendBad = new FileWriter(csvTestPath, true)) {
            appendBad.write("CORRUPT_ROW_WITHOUT_ENOUGH_FIELDS\n");
        }
        FilePersistenceService.CsvImportResult<DetectionRule> imported = fps.importRulesFromCsv(csvTestPath);
        assertCondition(imported.getItems().size() == currentRules.size() && imported.getSkippedCount() == 1,
                "Test 8.1: CSV export/import round-trip preserved all rules and skipped 1 malformed row");

        String binPath = testDataDir + File.separator + "test_snapshot.bin";
        DashboardStats stats = facade.getDashboardService().getStats(1);
        List<AttackLog> logs = facade.getAttackLogService().listRecentLogs(1, 20);
        fps.writeBinaryAuditSnapshot(stats, logs, binPath);
        FilePersistenceService.AuditSnapshotSummary summary = fps.readBinaryAuditSnapshot(binPath);
        assertCondition(summary.getTotalRequests() == stats.getTotalRequests()
                        && summary.getLogPreviews().size() == logs.size(),
                "Test 8.2: FileOutputStream/FileInputStream binary audit snapshot verified");

        String copyPath = testDataDir + File.separator + "rules_copy.csv";
        long copiedBytes = fps.copyFileByteByByte(csvTestPath, copyPath);
        assertCondition(copiedBytes == new File(csvTestPath).length() && copiedBytes > 0,
                "Test 8.3: Byte-stream copy transferred exact file size");

        String tokenPath = testDataDir + File.separator + "tokens_test.txt";
        fps.writeSampleTokenizedRulesFile(tokenPath);
        FilePersistenceService.TokenizedRuleParseResult tokenResult = fps.parseTokenizedRulesFile(1, tokenPath);
        assertCondition(tokenResult.getRules().size() == 3 && tokenResult.getSkippedCount() == 0,
                "Test 8.4: StreamTokenizer parsed 3 tokenized detection rules cleanly");
    }

    private static void runJdbcAndPersistenceReloadTests(
            String testDataDir,
            String configPath,
            String examplePath) throws Exception {
        DatabaseConfig dbConfig = DatabaseConfig.load(configPath, examplePath);
        DatabaseConnection dbConn = new DatabaseConnection(dbConfig);
        dbConn.loadDriver();
        assertCondition(true, "Test 9.1: MySQL JDBC Driver loaded via Class.forName(" + dbConfig.getDriver() + ")");

        String reloadDir = testDataDir + File.separator + "reload_verify";
        ThreatGateFacade firstSession = new ThreatGateFacade(reloadDir, configPath, examplePath, false, 0L);
        firstSession.getTrafficPipelineService().processSingleRequest(
                new InspectionRequest(1, "203.0.113.55", "GET", "/search?q=<script>alert(9)</script>", "", "reload-test"));
        firstSession.shutdown();

        ThreatGateFacade secondSession = new ThreatGateFacade(reloadDir, configPath, examplePath, false, 0L);
        List<AttackLog> reloadedLogs = secondSession.getAttackLogService().listAllLogs(1);
        secondSession.shutdown();
        assertCondition(reloadedLogs.size() == 1 && "203.0.113.55".equals(reloadedLogs.get(0).getIpAddress()),
                "Test 9.2: CSV persistence reloaded attack log cleanly across facade restart");

        boolean liveMySql = dbConn.testConnection();
        if (liveMySql) {
            ThreatGateFacade dbSession = new ThreatGateFacade(reloadDir, configPath, examplePath, true, 0L);
            assertCondition(dbSession.isDatabaseActive(),
                    "Test 9.3: Live MySQL JDBC connection and schema initialization verified");
            dbSession.shutdown();
        } else {
            assertCondition(!dbConn.getLastError().isEmpty(),
                    "Test 9.3: Offline MySQL JDBC handled gracefully without crash (" + dbConn.getLastError() + ")");
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

    private static void deleteRecursive(File target) {
        if (!target.exists()) {
            return;
        }
        if (target.isDirectory()) {
            File[] children = target.listFiles();
            if (children != null) {
                for (File child : children) {
                    deleteRecursive(child);
                }
            }
        }
        target.delete();
    }

    private static void assertCondition(boolean condition, String message) {
        if (condition) {
            passCount++;
            System.out.println("  [PASS] " + message);
        } else {
            fail(message);
        }
    }

    private static void fail(String message) {
        System.err.println("  [FAIL] " + message);
        System.exit(1);
    }
}
