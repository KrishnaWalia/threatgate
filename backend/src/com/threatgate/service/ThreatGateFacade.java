package com.threatgate.service;

import com.threatgate.db.AttackLogJdbcDao;
import com.threatgate.db.BlockedIpJdbcDao;
import com.threatgate.db.DatabaseConfig;
import com.threatgate.db.DatabaseConnection;
import com.threatgate.db.OrgJdbcDao;
import com.threatgate.db.RuleJdbcDao;
import com.threatgate.db.SchemaInitializer;
import com.threatgate.db.UserJdbcDao;
import com.threatgate.exception.DatabaseException;
import com.threatgate.exception.UnauthorizedRoleException;
import com.threatgate.model.AttackLog;
import com.threatgate.model.BlockedIp;
import com.threatgate.model.DetectionRule;
import com.threatgate.model.Organization;
import com.threatgate.model.User;
import java.io.File;
import java.io.IOException;
import java.sql.Timestamp;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class ThreatGateFacade {
    private static final long DEFAULT_SWEEPER_INTERVAL_MS = 30_000L;

    private final String dataDirectory;
    private final String configFilePath;
    private final DatabaseConfig databaseConfig;
    private final DatabaseConnection databaseConnection;
    private final SchemaInitializer schemaInitializer;
    private final OrgJdbcDao orgJdbcDao;
    private final RuleJdbcDao ruleJdbcDao;
    private final FilePersistenceService filePersistenceService;

    private final AuthService authService;
    private final RuleService ruleService;
    private final DetectionEngine detectionEngine;
    private final BruteForceService bruteForceService;
    private final AttackLogService attackLogService;
    private final DashboardService dashboardService;
    private final TrafficPipelineService trafficPipelineService;

    private boolean databaseActive;
    private int activeOrgId;

    public ThreatGateFacade(String dataDirectory, String configFilePath, String exampleConfigPath) {
        this(dataDirectory, configFilePath, exampleConfigPath, true, DEFAULT_SWEEPER_INTERVAL_MS);
    }

    public ThreatGateFacade(
            String dataDirectory,
            String configFilePath,
            String exampleConfigPath,
            boolean attemptDatabaseConnection,
            long sweeperIntervalMs) {
        this.dataDirectory = dataDirectory;
        this.configFilePath = configFilePath;
        this.databaseConfig = DatabaseConfig.forEmbeddedDirectory(dataDirectory, configFilePath, exampleConfigPath);
        this.databaseConnection = new DatabaseConnection(databaseConfig);
        this.schemaInitializer = new SchemaInitializer(databaseConnection);
        this.orgJdbcDao = new OrgJdbcDao(databaseConnection);
        this.ruleJdbcDao = new RuleJdbcDao(databaseConnection);
        this.filePersistenceService = new FilePersistenceService();
        this.activeOrgId = databaseConfig.getWafOrgId();

        UserJdbcDao userJdbcDao = new UserJdbcDao(databaseConnection);
        AttackLogJdbcDao attackLogJdbcDao = new AttackLogJdbcDao(databaseConnection);
        BlockedIpJdbcDao blockedIpJdbcDao = new BlockedIpJdbcDao(databaseConnection);

        this.authService = new AuthService(userJdbcDao, false);
        this.ruleService = new RuleService(ruleJdbcDao, authService, false);
        this.detectionEngine = new DetectionEngine(databaseConfig.getBlockThreshold());
        this.bruteForceService = new BruteForceService(
                blockedIpJdbcDao,
                authService,
                false,
                databaseConfig.getLoginFailMax(),
                databaseConfig.getLoginFailWindowMs(),
                databaseConfig.getRateLimitMax(),
                databaseConfig.getRateLimitWindowMs(),
                databaseConfig.getAttackStrikeMax(),
                databaseConfig.getAttackStrikeWindowMs(),
                databaseConfig.getBlockDurationMs()
        );
        this.attackLogService = new AttackLogService(attackLogJdbcDao, false);
        this.dashboardService = new DashboardService(attackLogService, bruteForceService);
        this.trafficPipelineService = new TrafficPipelineService(
                detectionEngine,
                ruleService,
                bruteForceService,
                attackLogService
        );

        initializeStorage(attemptDatabaseConnection);
        if (sweeperIntervalMs > 0) {
            this.trafficPipelineService.startExpirySweeper(sweeperIntervalMs);
        }
    }

    private void initializeStorage(boolean attemptDatabaseConnection) {
        if (attemptDatabaseConnection && tryActivateDatabase()) {
            return;
        }
        activateOfflineCsvMode();
    }

    private boolean tryActivateDatabase() {
        if (!databaseConnection.testConnection()) {
            return false;
        }
        try {
            schemaInitializer.initializeTables();
            String adminHash = PasswordUtil.hashPassword(AuthService.DEFAULT_ADMIN_PASSWORD);
            String viewerHash = PasswordUtil.hashPassword(AuthService.DEFAULT_VIEWER_PASSWORD);
            int seededOrgId = schemaInitializer.seedDefaultsIfEmpty(
                    RuleService.createDefaultRules(activeOrgId),
                    AuthService.DEFAULT_ADMIN_EMAIL,
                    adminHash,
                    AuthService.DEFAULT_VIEWER_EMAIL,
                    viewerHash
            );
            this.activeOrgId = seededOrgId;
            applyStorageMode(true);
            ruleService.loadFromDatabase(activeOrgId);
            return true;
        } catch (DatabaseException e) {
            applyStorageMode(false);
            return false;
        }
    }

    private void applyStorageMode(boolean useDatabase) {
        this.databaseActive = useDatabase;
        authService.setUseDatabase(useDatabase);
        ruleService.setUseDatabase(useDatabase);
        bruteForceService.setUseDatabase(useDatabase);
        attackLogService.setUseDatabase(useDatabase);
    }

    private void activateOfflineCsvMode() {
        applyStorageMode(false);
        File dir = new File(dataDirectory);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        loadOfflineCsvFiles();
    }

    private void loadOfflineCsvFiles() {
        try {
            File usersFile = new File(getUsersCsvPath());
            if (usersFile.exists() && usersFile.length() > 0) {
                List<User> loadedUsers = filePersistenceService.importUsersFromCsv(getUsersCsvPath()).getItems();
                authService.replaceOfflineUsers(loadedUsers);
            } else {
                authService.seedDefaultOfflineUsers();
                filePersistenceService.exportUsersToCsv(authService.getAllOfflineUsers(), getUsersCsvPath());
            }

            File rulesFile = new File(getRulesCsvPath());
            if (rulesFile.exists() && rulesFile.length() > 0) {
                List<DetectionRule> loadedRules = filePersistenceService.importRulesFromCsv(getRulesCsvPath()).getItems();
                if (!loadedRules.isEmpty()) {
                    ruleService.replaceRules(loadedRules);
                }
            } else {
                ruleService.seedDefaultRules(activeOrgId);
                filePersistenceService.exportRulesToCsv(ruleService.listRules(activeOrgId), getRulesCsvPath());
            }

            File logsFile = new File(getAttackLogsCsvPath());
            if (logsFile.exists() && logsFile.length() > 0) {
                List<AttackLog> loadedLogs = filePersistenceService.importAttackLogsFromCsv(getAttackLogsCsvPath()).getItems();
                attackLogService.replaceOfflineLogs(loadedLogs);
            }

            File blocksFile = new File(getBlockedIpsCsvPath());
            if (blocksFile.exists() && blocksFile.length() > 0) {
                List<BlockedIp> loadedBlocks = filePersistenceService.importBlockedIpsFromCsv(getBlockedIpsCsvPath()).getItems();
                bruteForceService.replaceOfflineBlocks(loadedBlocks);
            }
        } catch (IOException ignored) {
        }
    }

    public boolean switchToEmbeddedDatabase(String dbFilePath, boolean saveProperties) throws DatabaseException {
        String effectivePath = dbFilePath != null && !dbFilePath.trim().isEmpty()
                ? dbFilePath.trim()
                : new File(dataDirectory, "threatgate").getAbsolutePath();
        databaseConfig.setDriver("org.h2.Driver");
        databaseConfig.setUrl(DatabaseConfig.buildH2Url(effectivePath));
        databaseConfig.setServerUrl("");
        databaseConfig.setUser("sa");
        databaseConfig.setPassword("");

        if (!tryActivateDatabase()) {
            throw new DatabaseException("Could not open Embedded H2 database: " + databaseConnection.getLastError());
        }
        if (saveProperties && configFilePath != null) {
            try {
                databaseConfig.saveToFile(configFilePath);
            } catch (IOException e) {
                throw new DatabaseException("Opened H2 database, but failed saving db.properties: " + e.getMessage(), e);
            }
        }
        return true;
    }

    public boolean reconnectDatabase(
            String host,
            int port,
            String databaseName,
            String user,
            String password,
            boolean saveProperties) throws DatabaseException {
        String safeDb = databaseName != null && !databaseName.trim().isEmpty() ? databaseName.trim() : "threatgate";
        String safeHost = host != null && !host.trim().isEmpty() ? host.trim() : "localhost";
        int safePort = port > 0 ? port : 3306;
        String params = "?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC";
        databaseConfig.setDriver("com.mysql.cj.jdbc.Driver");
        databaseConfig.setDatabaseName(safeDb);
        databaseConfig.setServerUrl("jdbc:mysql://" + safeHost + ":" + safePort + "/" + params);
        databaseConfig.setUrl("jdbc:mysql://" + safeHost + ":" + safePort + "/" + safeDb + params);
        databaseConfig.setUser(user != null && !user.trim().isEmpty() ? user.trim() : "root");
        databaseConfig.setPassword(password != null ? password : "");

        if (!tryActivateDatabase()) {
            throw new DatabaseException("Could not connect to MySQL JDBC: " + databaseConnection.getLastError());
        }
        if (saveProperties && configFilePath != null) {
            try {
                databaseConfig.saveToFile(configFilePath);
            } catch (IOException e) {
                throw new DatabaseException("Connected to MySQL, but failed saving db.properties: " + e.getMessage(), e);
            }
        }
        return true;
    }

    public void reinitializeSchema() throws DatabaseException {
        if (!databaseActive) {
            throw new DatabaseException("Database connection is not active.");
        }
        schemaInitializer.initializeTables();
        String adminHash = PasswordUtil.hashPassword(AuthService.DEFAULT_ADMIN_PASSWORD);
        String viewerHash = PasswordUtil.hashPassword(AuthService.DEFAULT_VIEWER_PASSWORD);
        this.activeOrgId = schemaInitializer.seedDefaultsIfEmpty(
                RuleService.createDefaultRules(activeOrgId),
                AuthService.DEFAULT_ADMIN_EMAIL,
                adminHash,
                AuthService.DEFAULT_VIEWER_EMAIL,
                viewerHash
        );
        ruleService.loadFromDatabase(activeOrgId);
    }

    public Map<String, Long> getDatabaseTableCounts() throws DatabaseException {
        if (databaseActive) {
            return schemaInitializer.countAllTables();
        }
        Map<String, Long> counts = new LinkedHashMap<>();
        counts.put("orgs", 1L);
        counts.put("users", (long) authService.getAllOfflineUsers().size());
        counts.put("rules", (long) ruleService.listRules(activeOrgId).size());
        counts.put("attack_logs", (long) attackLogService.getAllOfflineLogs().size());
        counts.put("blocked_ips", (long) bruteForceService.getAllOfflineBlocks().size());
        return counts;
    }

    public List<Organization> extractAllOrganizations() throws DatabaseException {
        if (databaseActive) {
            return orgJdbcDao.findAll();
        }
        return Collections.singletonList(new Organization(activeOrgId, "Demo Org", new Timestamp(System.currentTimeMillis())));
    }

    public List<User> extractAllUsers(User actor) throws UnauthorizedRoleException, DatabaseException {
        return authService.listUsers(actor);
    }

    public List<DetectionRule> extractAllRules(int orgId) throws DatabaseException {
        if (databaseActive) {
            return ruleJdbcDao.findAllByOrg(orgId);
        }
        return ruleService.listRules(orgId);
    }

    public List<AttackLog> extractAllAttackLogs(int orgId) throws DatabaseException {
        return attackLogService.listAllLogs(orgId);
    }

    public List<BlockedIp> extractActiveBlockedIps(User actor) throws UnauthorizedRoleException, DatabaseException {
        return bruteForceService.listBlockedIps(actor);
    }

    public void exportEntireDatabaseToCsv(int orgId, User actor)
            throws UnauthorizedRoleException, DatabaseException, IOException {
        authService.requireRole(actor, "admin");
        filePersistenceService.exportUsersToCsv(extractAllUsers(actor), getUsersCsvPath());
        filePersistenceService.exportRulesToCsv(extractAllRules(orgId), getRulesCsvPath());
        filePersistenceService.exportAttackLogsToCsv(extractAllAttackLogs(orgId), getAttackLogsCsvPath());
        filePersistenceService.exportBlockedIpsToCsv(extractActiveBlockedIps(actor), getBlockedIpsCsvPath());
    }

    public void saveOfflineState() throws IOException {
        if (databaseActive) {
            return;
        }
        filePersistenceService.exportUsersToCsv(authService.getAllOfflineUsers(), getUsersCsvPath());
        filePersistenceService.exportRulesToCsv(ruleService.listRules(activeOrgId), getRulesCsvPath());
        filePersistenceService.exportAttackLogsToCsv(attackLogService.getAllOfflineLogs(), getAttackLogsCsvPath());
        filePersistenceService.exportBlockedIpsToCsv(bruteForceService.getAllOfflineBlocks(), getBlockedIpsCsvPath());
    }

    public void shutdown() {
        trafficPipelineService.stopLiveSimulation();
        trafficPipelineService.stopExpirySweeper();
        if (!databaseActive) {
            try {
                saveOfflineState();
            } catch (IOException ignored) {
            }
        }
    }

    public String getUsersCsvPath() {
        return dataDirectory + File.separator + "users_data.csv";
    }

    public String getRulesCsvPath() {
        return dataDirectory + File.separator + "rules_data.csv";
    }

    public String getAttackLogsCsvPath() {
        return dataDirectory + File.separator + "attack_logs_data.csv";
    }

    public String getBlockedIpsCsvPath() {
        return dataDirectory + File.separator + "blocked_ips_data.csv";
    }

    public String getDataDirectory() {
        return dataDirectory;
    }

    public DatabaseConfig getDatabaseConfig() {
        return databaseConfig;
    }

    public DatabaseConnection getDatabaseConnection() {
        return databaseConnection;
    }

    public OrgJdbcDao getOrgJdbcDao() {
        return orgJdbcDao;
    }

    public FilePersistenceService getFilePersistenceService() {
        return filePersistenceService;
    }

    public AuthService getAuthService() {
        return authService;
    }

    public RuleService getRuleService() {
        return ruleService;
    }

    public DetectionEngine getDetectionEngine() {
        return detectionEngine;
    }

    public BruteForceService getBruteForceService() {
        return bruteForceService;
    }

    public AttackLogService getAttackLogService() {
        return attackLogService;
    }

    public DashboardService getDashboardService() {
        return dashboardService;
    }

    public TrafficPipelineService getTrafficPipelineService() {
        return trafficPipelineService;
    }

    public boolean isDatabaseActive() {
        return databaseActive;
    }

    public int getActiveOrgId() {
        return activeOrgId;
    }
}
