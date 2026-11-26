package com.threatgate.service;

import com.threatgate.exception.DatabaseException;
import com.threatgate.model.AttackLog;
import com.threatgate.model.BlockedIp;
import com.threatgate.model.DetectionRule;
import com.threatgate.model.InspectionRequest;
import com.threatgate.model.InspectionResult;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class TrafficPipelineService {
    public static final int DEFAULT_TRY_MODE_REQUESTS = 500;

    private final DetectionEngine detectionEngine;
    private final RuleService ruleService;
    private final BruteForceService bruteForceService;
    private final AttackLogService attackLogService;

    private final RequestBuffer<InspectionRequest> liveBuffer = new RequestBuffer<>(64);
    private final Object simulationLock = new Object();
    private Thread liveProducerThread;
    private TrafficProducerWorker liveProducerWorker;
    private TrafficConsumerWorker liveConsumerWorker;
    private ExpirySweeperWorker expirySweeperWorker;

    public TrafficPipelineService(
            DetectionEngine detectionEngine,
            RuleService ruleService,
            BruteForceService bruteForceService,
            AttackLogService attackLogService) {
        this.detectionEngine = detectionEngine;
        this.ruleService = ruleService;
        this.bruteForceService = bruteForceService;
        this.attackLogService = attackLogService;
    }

    public WafDecision processSingleRequest(InspectionRequest request) {
        int orgId = request.getOrgId();
        String ip = request.getIpAddress();
        String method = request.getMethod();
        String url = request.getUrl();
        String userAgent = request.getUserAgent();

        try {
            Optional<BlockedIp> activeBlock = bruteForceService.findActiveBlock(orgId, ip);
            if (activeBlock.isPresent()) {
                AttackLog log = buildLog(orgId, ip, method, url, "brute_force", 100, "blocked", null, userAgent);
                attackLogService.recordLog(log);
                String reason = activeBlock.get().getReason();
                return new WafDecision(log, 100, "brute_force", true, 403,
                        "IP blocked: " + (reason != null ? reason : "policy"));
            }

            Optional<BlockedIp> rateLimitBlock = bruteForceService.trackRequest(orgId, ip);
            if (rateLimitBlock.isPresent()) {
                AttackLog log = buildLog(orgId, ip, method, url, "brute_force", 95, "blocked", null, userAgent);
                attackLogService.recordLog(log);
                return new WafDecision(log, 95, "brute_force", true, 429, rateLimitBlock.get().getReason());
            }

            List<DetectionRule> activeRules = ruleService.getActiveRules(orgId);
            Map<Integer, Pattern> compiled = ruleService.getCompiledPatternsSnapshot();
            InspectionResult result = detectionEngine.inspect(request, activeRules, compiled);

            if (result.isBlocked()) {
                AttackLog log = buildLog(
                        orgId,
                        ip,
                        method,
                        url,
                        result.getCategory(),
                        result.getRiskScore(),
                        "blocked",
                        result.getMatchedRuleId(),
                        userAgent
                );
                attackLogService.recordLog(log);

                Optional<BlockedIp> strikeBlock = bruteForceService.trackAttack(orgId, ip);
                if (strikeBlock.isPresent()) {
                    AttackLog strikeLog = buildLog(
                            orgId,
                            ip,
                            method,
                            url,
                            "brute_force",
                            95,
                            "blocked",
                            null,
                            userAgent
                    );
                    attackLogService.recordLog(strikeLog);
                }

                return new WafDecision(
                        log,
                        result.getRiskScore(),
                        result.getCategory(),
                        true,
                        403,
                        "Blocked as " + result.getCategory() + " (risk=" + result.getRiskScore() + ")"
                );
            }

            AttackLog allowedLog = buildLog(
                    orgId,
                    ip,
                    method,
                    url,
                    result.getCategory(),
                    result.getRiskScore(),
                    "allowed",
                    result.getMatchedRuleId(),
                    userAgent
            );
            attackLogService.recordLog(allowedLog);

            int status = request.getSimulatedLoginStatus();
            if (bruteForceService.isLoginPath(url)) {
                if (status == 401 || status == 403) {
                    Optional<BlockedIp> loginBlock = bruteForceService.trackFailedLogin(orgId, ip);
                    if (loginBlock.isPresent()) {
                        AttackLog bfLog = buildLog(orgId, ip, method, url, "brute_force", 90, "blocked", null, userAgent);
                        attackLogService.recordLog(bfLog);
                    }
                } else if (status > 0 && status < 400 && "POST".equalsIgnoreCase(method)) {
                    bruteForceService.clearFailedLogins(orgId, ip);
                }
            }

            return new WafDecision(allowedLog, result.getRiskScore(), result.getCategory(), false, 200, "Allowed");
        } catch (DatabaseException e) {
            AttackLog fallbackLog = buildLog(orgId, ip, method, url, "none", 0, "allowed", null, userAgent);
            return new WafDecision(fallbackLog, 0, "none", false, 500, "Pipeline warning: " + e.getMessage());
        }
    }

    private AttackLog buildLog(
            int orgId,
            String ip,
            String method,
            String path,
            String category,
            int riskScore,
            String action,
            Integer matchedRuleId,
            String userAgent) {
        return new AttackLog(
                0L,
                orgId,
                ip,
                method,
                path,
                category,
                riskScore,
                action,
                matchedRuleId,
                userAgent,
                new Timestamp(System.currentTimeMillis())
        );
    }

    public synchronized void startExpirySweeper(long intervalMs) {
        if (expirySweeperWorker != null && expirySweeperWorker.isAlive()) {
            return;
        }
        expirySweeperWorker = new ExpirySweeperWorker("threatgate-expiry-sweeper", bruteForceService, intervalMs);
        expirySweeperWorker.start();
    }

    public synchronized void stopExpirySweeper() {
        if (expirySweeperWorker != null) {
            expirySweeperWorker.stopWorker();
            try {
                expirySweeperWorker.join(1000L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            expirySweeperWorker = null;
        }
    }

    public synchronized void startLiveSimulation(int orgId, long intervalMs) {
        synchronized (simulationLock) {
            if (isSimulationRunning()) {
                return;
            }
            liveBuffer.reopen();
            liveProducerWorker = new TrafficProducerWorker(liveBuffer, orgId, intervalMs, 0);
            liveProducerThread = new Thread(liveProducerWorker, "threatgate-sim-producer");
            liveProducerThread.setPriority(Thread.NORM_PRIORITY);
            liveConsumerWorker = new TrafficConsumerWorker(
                    "threatgate-sim-consumer",
                    liveBuffer,
                    this,
                    Thread.MAX_PRIORITY,
                    false
            );
            liveConsumerWorker.start();
            liveProducerThread.start();
        }
    }

    public synchronized void stopLiveSimulation() {
        synchronized (simulationLock) {
            if (liveProducerWorker != null) {
                liveProducerWorker.stopWorker();
            }
            if (liveProducerThread != null) {
                liveProducerThread.interrupt();
            }
            liveBuffer.close();
            if (liveProducerThread != null) {
                try {
                    liveProducerThread.join(2000L);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            if (liveConsumerWorker != null) {
                try {
                    liveConsumerWorker.join(2000L);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            liveProducerThread = null;
            liveProducerWorker = null;
            liveConsumerWorker = null;
        }
    }

    public boolean isSimulationRunning() {
        synchronized (simulationLock) {
            return (liveProducerThread != null && liveProducerThread.isAlive())
                    || (liveConsumerWorker != null && liveConsumerWorker.isAlive());
        }
    }

    public List<WafDecision> runAttackDemoBatch(int orgId) throws InterruptedException {
        List<InspectionRequest> demoRequests = new ArrayList<>();
        demoRequests.add(new InspectionRequest(orgId, "203.0.113.10", "GET", "/search?q=hello", "", "demo-cli/1.0"));
        demoRequests.add(new InspectionRequest(orgId, "203.0.113.11", "GET", "/search?q=O'Brien", "", "demo-cli/1.0"));
        demoRequests.add(new InspectionRequest(orgId, "203.0.113.12", "GET", "/api/users?id=1' OR '1'='1", "", "demo-cli/1.0"));
        demoRequests.add(new InspectionRequest(orgId, "203.0.113.13", "GET", "/search?q=<script>alert(1)</script>", "", "demo-cli/1.0"));
        demoRequests.add(new InspectionRequest(orgId, "203.0.113.14", "GET", "/files?name=%252e%252e%252fetc/passwd", "", "demo-cli/1.0"));

        for (int i = 0; i < bruteForceService.getLoginFailMax(); i++) {
            demoRequests.add(new InspectionRequest(orgId, "198.51.100.77", "POST", "/login", "email=admin@threatgate.dev", "demo-cli/1.0", "", "", 401));
        }
        demoRequests.add(new InspectionRequest(orgId, "198.51.100.77", "GET", "/search?q=after_bruteforce", "", "demo-cli/1.0"));

        for (int i = 0; i < bruteForceService.getAttackStrikeMax(); i++) {
            demoRequests.add(new InspectionRequest(orgId, "192.0.2.88", "GET", "/api/items?id=1 UNION/**/SELECT password FROM users", "", "demo-cli/1.0"));
        }
        demoRequests.add(new InspectionRequest(orgId, "192.0.2.88", "GET", "/search?q=after_strikes", "", "demo-cli/1.0"));

        return runConcurrentBatch(demoRequests, 2, 5L, true, "attack-demo");
    }

    public TryModeReport runTryModeDemo(int orgId, int totalRequests) throws InterruptedException {
        int safeTotal = Math.max(40, Math.min(totalRequests, 2000));
        List<InspectionRequest> requests = buildTryModeRequests(orgId, safeTotal);

        long startNanos = System.nanoTime();
        List<WafDecision> decisions = runConcurrentBatch(requests, 4, 0L, true, "try-mode");
        long elapsedMs = Math.max(1L, (System.nanoTime() - startNanos) / 1_000_000L);

        long blockedCount = decisions.stream().filter(WafDecision::isBlocked).count();
        long allowedCount = decisions.size() - blockedCount;
        Map<String, Long> categoryCounts = decisions.stream()
                .collect(Collectors.groupingBy(WafDecision::getCategory, LinkedHashMap::new, Collectors.counting()));
        List<WafDecision> samples = decisions.stream()
                .limit(15)
                .collect(Collectors.toList());

        return new TryModeReport(
                requests.size(),
                decisions.size(),
                allowedCount,
                blockedCount,
                elapsedMs,
                categoryCounts,
                samples
        );
    }

    private List<WafDecision> runConcurrentBatch(
            List<InspectionRequest> requests,
            int workerCount,
            long producerDelayMs,
            boolean recordDecisions,
            String prefix) throws InterruptedException {
        RequestBuffer<InspectionRequest> batchBuffer = new RequestBuffer<>(64);
        List<TrafficConsumerWorker> consumers = new ArrayList<>();
        for (int w = 0; w < workerCount; w++) {
            consumers.add(new TrafficConsumerWorker(
                    prefix + "-consumer-" + (w + 1),
                    batchBuffer,
                    this,
                    Thread.MAX_PRIORITY,
                    recordDecisions
            ));
        }
        TrafficProducerWorker producerWorker = new TrafficProducerWorker(batchBuffer, requests, producerDelayMs);
        Thread producerThread = new Thread(producerWorker, prefix + "-producer");

        for (TrafficConsumerWorker consumer : consumers) {
            consumer.start();
        }
        producerThread.start();

        producerThread.join();
        batchBuffer.close();

        List<WafDecision> combined = new ArrayList<>();
        for (TrafficConsumerWorker consumer : consumers) {
            consumer.join();
            if (recordDecisions) {
                combined.addAll(consumer.getDecisions());
            }
        }
        return combined;
    }

    private List<InspectionRequest> buildTryModeRequests(int orgId, int totalRequests) {
        String[] benignPaths = {
                "/",
                "/api/products?id=101",
                "/search?q=hello",
                "/search?q=O'Brien",
                "/search?q=select+the+best+items+from+our+store",
                "/pricing",
                "/docs/getting-started",
                "/api/orders?page=2",
                "/catalog?category=security",
                "/health"
        };
        String[] sqliPaths = {
                "/api/users?id=1' OR '1'='1",
                "/api/products?id=1 OR 1=1",
                "/api/users?id=1 UNION/**/SELECT password FROM users",
                "/search?q='; DROP TABLE users;--",
                "/api/items?id=1 AND SLEEP(5)",
                "/api/schema?q=information_schema.tables",
                "/api/profile?id=extractvalue(1,concat(0x7e,version()))",
                "/login?user=admin'--"
        };
        String[] xssPaths = {
                "/search?q=<script>alert(1)</script>",
                "/comments?text=&#60;script&#62;alert(1)",
                "/profile?bio=<img src=x onerror=alert(1)>",
                "/redirect?next=javascript:alert(1)",
                "/embed?src=<iframe src=https://evil.example>",
                "/preview?html=data:text/html,<script>alert(1)</script>",
                "/search?q=select+title+from+posts&cb=alert(1)"
        };
        String[] traversalPaths = {
                "/files?name=../../../../etc/passwd",
                "/files?name=%252e%252e%252f%252e%252e%252fetc/passwd",
                "/download?path=/.env",
                "/static?file=/.git/config",
                "/view?doc=file:///etc/passwd",
                "/upload?img=avatar.php%00.jpg",
                "/assets?f=..\\..\\windows\\win.ini"
        };

        List<InspectionRequest> list = new ArrayList<>(totalRequests);
        int loginWave1Count = 0;
        int loginWave2Count = 0;
        int strikeWave1Count = 0;
        int strikeWave2Count = 0;
        int maxLoginEach = bruteForceService.getLoginFailMax() + 2;
        int maxStrikeEach = bruteForceService.getAttackStrikeMax() + 2;

        for (int i = 0; i < totalRequests; i++) {
            int bucket = i % 20;
            if (i >= 40 && i < 120 && loginWave1Count < maxLoginEach && bucket == 18) {
                loginWave1Count++;
                list.add(new InspectionRequest(
                        orgId, "198.51.100.77", "POST", "/login",
                        "email=admin@threatgate.dev", "hydra-cli/9.5", "", "", 401
                ));
                continue;
            }
            if (i >= 60 && i < 160 && loginWave2Count < maxLoginEach && bucket == 19) {
                loginWave2Count++;
                list.add(new InspectionRequest(
                        orgId, "198.51.100.88", "POST", "/signin",
                        "email=viewer@threatgate.dev", "burp-intruder/2.0", "", "", 401
                ));
                continue;
            }
            if (i >= 80 && i < 240 && strikeWave1Count < maxStrikeEach && bucket == 17) {
                strikeWave1Count++;
                list.add(new InspectionRequest(
                        orgId, "192.0.2.88", "GET",
                        "/api/items?id=1 UNION/**/SELECT username FROM users", "", "sqlmap/1.8"
                ));
                continue;
            }
            if (i >= 100 && i < 280 && strikeWave2Count < maxStrikeEach && bucket == 15) {
                strikeWave2Count++;
                list.add(new InspectionRequest(
                        orgId, "192.0.2.99", "POST",
                        "/comments", "body=<script>document.cookie</script>", "xsser/1.0"
                ));
                continue;
            }
            if (i >= totalRequests - 12) {
                String blockedOffender = switch (i % 4) {
                    case 0 -> "198.51.100.77";
                    case 1 -> "198.51.100.88";
                    case 2 -> "192.0.2.88";
                    default -> "192.0.2.99";
                };
                list.add(new InspectionRequest(
                        orgId, blockedOffender, "GET", "/api/dashboard", "", "scanner-probe/1.2"
                ));
                continue;
            }

            if (bucket < 10) {
                String ip = "203.0.113." + (10 + (i % 20));
                if (i % 25 == 0) {
                    list.add(new InspectionRequest(
                            orgId, ip, "POST", "/login", "email=viewer@threatgate.dev", "Mozilla/5.0", "", "", 200
                    ));
                } else {
                    String path = benignPaths[i % benignPaths.length];
                    list.add(new InspectionRequest(orgId, ip, "GET", path, "", "Mozilla/5.0"));
                }
            } else if (bucket < 14) {
                String ip = "198.51.100." + (10 + (i % 16));
                String path = sqliPaths[i % sqliPaths.length];
                list.add(new InspectionRequest(orgId, ip, "GET", path, "", "curl/8.4"));
            } else if (bucket < 17) {
                String ip = "192.0.2." + (10 + (i % 16));
                if (i % 15 == 1) {
                    list.add(new InspectionRequest(
                            orgId, ip, "GET", "/home", "", "<script>alert(1)</script>"
                    ));
                } else {
                    String path = xssPaths[i % xssPaths.length];
                    list.add(new InspectionRequest(orgId, ip, "POST", path, "note=demo", "Mozilla/5.0"));
                }
            } else {
                String ip = "203.0.113." + (100 + (i % 16));
                String path = traversalPaths[i % traversalPaths.length];
                list.add(new InspectionRequest(orgId, ip, "GET", path, "", "python-requests/2.31"));
            }
        }
        while (loginWave1Count < maxLoginEach && list.size() > 5) {
            loginWave1Count++;
            list.set(list.size() - 5 - loginWave1Count, new InspectionRequest(
                    orgId, "198.51.100.77", "POST", "/login", "email=admin@threatgate.dev", "hydra-cli/9.5", "", "", 401
            ));
        }
        return list;
    }

    public BenchmarkReport runSequentialVsConcurrentBenchmark(int orgId, int requestCount) throws InterruptedException {
        int safeCount = Math.max(4, Math.min(requestCount, 500));
        List<InspectionRequest> requests = new ArrayList<>();
        for (int i = 0; i < safeCount; i++) {
            String ip = "10.20.0." + ((i % 200) + 1);
            String path = (i % 4 == 0) ? "/api/users?id=1 OR 1=1" : "/api/products?page=" + i;
            requests.add(new InspectionRequest(orgId, ip, "GET", path, "", "benchmark-client/1.0"));
        }

        long seqStart = System.nanoTime();
        int seqProcessed = 0;
        for (InspectionRequest req : requests) {
            processSingleRequest(req);
            seqProcessed++;
        }
        long seqElapsedMs = Math.max(1L, (System.nanoTime() - seqStart) / 1_000_000L);

        int workerCount = 4;
        RequestBuffer<InspectionRequest> benchBuffer = new RequestBuffer<>(32);
        List<TrafficConsumerWorker> consumers = new ArrayList<>();
        for (int w = 0; w < workerCount; w++) {
            consumers.add(new TrafficConsumerWorker("bench-consumer-" + (w + 1), benchBuffer, this, Thread.NORM_PRIORITY, false));
        }
        TrafficProducerWorker producerWorker = new TrafficProducerWorker(benchBuffer, requests, 0L);
        Thread producerThread = new Thread(producerWorker, "bench-producer");

        long conStart = System.nanoTime();
        for (TrafficConsumerWorker consumer : consumers) {
            consumer.start();
        }
        producerThread.start();
        producerThread.join();
        benchBuffer.close();

        int conProcessed = 0;
        for (TrafficConsumerWorker consumer : consumers) {
            consumer.join();
            conProcessed += consumer.getConsumedCount();
        }
        long conElapsedMs = Math.max(1L, (System.nanoTime() - conStart) / 1_000_000L);

        return new BenchmarkReport(safeCount, seqProcessed, seqElapsedMs, conProcessed, conElapsedMs, workerCount);
    }

    public List<String> captureThreadLifecycleReport() throws InterruptedException {
        List<String> lines = new ArrayList<>();
        lines.add("=== Active Pipeline Threads ===");
        if (expirySweeperWorker != null) {
            lines.add(formatThreadLine(expirySweeperWorker)
                    + String.format(" [sweeps=%d, purged=%d]", expirySweeperWorker.getSweepCount(), expirySweeperWorker.getTotalPurged()));
        } else {
            lines.add("threatgate-expiry-sweeper: NOT STARTED");
        }
        synchronized (simulationLock) {
            if (liveProducerThread != null) {
                lines.add(formatThreadLine(liveProducerThread));
            }
            if (liveConsumerWorker != null) {
                lines.add(formatThreadLine(liveConsumerWorker));
            }
            if (liveProducerThread == null && liveConsumerWorker == null) {
                lines.add("Simulation threads: IDLE (not running)");
            }
        }

        lines.add("");
        lines.add("=== Thread Lifecycle State Trace (All 6 States) ===");

        final class SignalHolder {
            volatile boolean entered;
            volatile boolean stop;
        }
        final SignalHolder runnableSignal = new SignalHolder();
        Thread runnableProbe = new Thread(() -> {
            runnableSignal.entered = true;
            double acc = 1.0;
            while (!runnableSignal.stop) {
                acc = Math.sin(acc + 1.0);
            }
        }, "probe-runnable");
        lines.add("1. Before start()       -> " + runnableProbe.getName() + " state=" + runnableProbe.getState());

        runnableProbe.start();
        long waitLimit = System.currentTimeMillis() + 300L;
        while (!runnableSignal.entered && System.currentTimeMillis() < waitLimit) {
            Thread.sleep(2L);
        }
        lines.add("2. Inside active loop   -> " + runnableProbe.getName() + " state=" + runnableProbe.getState());
        runnableSignal.stop = true;
        runnableProbe.join();
        lines.add("6. After join()         -> " + runnableProbe.getName() + " state=" + runnableProbe.getState());

        final Object blockMonitor = new Object();
        Thread blockedProbe = new Thread(() -> {
            synchronized (blockMonitor) {
                runnableSignal.entered = false;
            }
        }, "probe-blocked");
        Thread.State observedBlocked = Thread.State.RUNNABLE;
        synchronized (blockMonitor) {
            blockedProbe.start();
            long deadline = System.currentTimeMillis() + 300L;
            while (System.currentTimeMillis() < deadline) {
                observedBlocked = blockedProbe.getState();
                if (observedBlocked == Thread.State.BLOCKED) {
                    break;
                }
                Thread.sleep(2L);
            }
        }
        blockedProbe.join();
        lines.add("3. Contending on lock   -> " + blockedProbe.getName() + " state=" + observedBlocked);

        final Object waitMonitor = new Object();
        final boolean[] releaseWait = { false };
        Thread waitingProbe = new Thread(() -> {
            synchronized (waitMonitor) {
                while (!releaseWait[0]) {
                    try {
                        waitMonitor.wait();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
            }
        }, "probe-waiting");
        waitingProbe.start();
        Thread.State observedWaiting = Thread.State.RUNNABLE;
        long waitDeadline = System.currentTimeMillis() + 300L;
        while (System.currentTimeMillis() < waitDeadline) {
            observedWaiting = waitingProbe.getState();
            if (observedWaiting == Thread.State.WAITING) {
                break;
            }
            Thread.sleep(2L);
        }
        synchronized (waitMonitor) {
            releaseWait[0] = true;
            waitMonitor.notifyAll();
        }
        waitingProbe.join();
        lines.add("4. Guarded wait() block -> " + waitingProbe.getName() + " state=" + observedWaiting);

        Thread timedWaitingProbe = new Thread(() -> {
            try {
                Thread.sleep(200L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }, "probe-timed-waiting");
        timedWaitingProbe.start();
        Thread.State observedTimed = Thread.State.RUNNABLE;
        long timedDeadline = System.currentTimeMillis() + 300L;
        while (System.currentTimeMillis() < timedDeadline) {
            observedTimed = timedWaitingProbe.getState();
            if (observedTimed == Thread.State.TIMED_WAITING) {
                break;
            }
            Thread.sleep(2L);
        }
        timedWaitingProbe.interrupt();
        timedWaitingProbe.join();
        lines.add("5. Inside sleep(ms)     -> " + timedWaitingProbe.getName() + " state=" + observedTimed);

        return lines;
    }

    private String formatThreadLine(Thread thread) {
        return String.format(
                "%s | state=%s | priority=%d | daemon=%s | alive=%s",
                thread.getName(),
                thread.getState(),
                thread.getPriority(),
                thread.isDaemon(),
                thread.isAlive()
        );
    }

    public static final class WafDecision {
        private final AttackLog log;
        private final int riskScore;
        private final String category;
        private final boolean blocked;
        private final int httpStatus;
        private final String reason;

        public WafDecision(
                AttackLog log,
                int riskScore,
                String category,
                boolean blocked,
                int httpStatus,
                String reason) {
            this.log = log;
            this.riskScore = riskScore;
            this.category = category;
            this.blocked = blocked;
            this.httpStatus = httpStatus;
            this.reason = reason;
        }

        public AttackLog getLog() {
            return log;
        }

        public int getRiskScore() {
            return riskScore;
        }

        public String getCategory() {
            return category;
        }

        public boolean isBlocked() {
            return blocked;
        }

        public int getHttpStatus() {
            return httpStatus;
        }

        public String getReason() {
            return reason;
        }
    }

    public static final class BenchmarkReport {
        private final int totalRequests;
        private final int sequentialProcessed;
        private final long sequentialMs;
        private final int concurrentProcessed;
        private final long concurrentMs;
        private final int workerCount;

        public BenchmarkReport(
                int totalRequests,
                int sequentialProcessed,
                long sequentialMs,
                int concurrentProcessed,
                long concurrentMs,
                int workerCount) {
            this.totalRequests = totalRequests;
            this.sequentialProcessed = sequentialProcessed;
            this.sequentialMs = sequentialMs;
            this.concurrentProcessed = concurrentProcessed;
            this.concurrentMs = concurrentMs;
            this.workerCount = workerCount;
        }

        public int getTotalRequests() {
            return totalRequests;
        }

        public int getSequentialProcessed() {
            return sequentialProcessed;
        }

        public long getSequentialMs() {
            return sequentialMs;
        }

        public int getConcurrentProcessed() {
            return concurrentProcessed;
        }

        public long getConcurrentMs() {
            return concurrentMs;
        }

        public int getWorkerCount() {
            return workerCount;
        }
    }

    public static final class TryModeReport {
        private final int submittedCount;
        private final int processedCount;
        private final long allowedCount;
        private final long blockedCount;
        private final long elapsedMs;
        private final LinkedHashMap<String, Long> categoryBreakdown;
        private final ArrayList<WafDecision> sampleDecisions;

        public TryModeReport(
                int submittedCount,
                int processedCount,
                long allowedCount,
                long blockedCount,
                long elapsedMs,
                Map<String, Long> categoryBreakdown,
                List<WafDecision> sampleDecisions) {
            this.submittedCount = submittedCount;
            this.processedCount = processedCount;
            this.allowedCount = allowedCount;
            this.blockedCount = blockedCount;
            this.elapsedMs = elapsedMs;
            this.categoryBreakdown = categoryBreakdown != null
                    ? new LinkedHashMap<>(categoryBreakdown)
                    : new LinkedHashMap<>();
            this.sampleDecisions = sampleDecisions != null
                    ? new ArrayList<>(sampleDecisions)
                    : new ArrayList<>();
        }

        public int getSubmittedCount() {
            return submittedCount;
        }

        public int getProcessedCount() {
            return processedCount;
        }

        public long getAllowedCount() {
            return allowedCount;
        }

        public long getBlockedCount() {
            return blockedCount;
        }

        public long getElapsedMs() {
            return elapsedMs;
        }

        public Map<String, Long> getCategoryBreakdown() {
            return Collections.unmodifiableMap(categoryBreakdown);
        }

        public List<WafDecision> getSampleDecisions() {
            return Collections.unmodifiableList(sampleDecisions);
        }
    }
}
