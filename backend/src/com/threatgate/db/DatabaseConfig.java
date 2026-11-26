package com.threatgate.db;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;

public class DatabaseConfig {
    private static final String H2_PREFIX = "jdbc:h2:file:";
    private static final String H2_OPTIONS = ";MODE=MySQL;DATABASE_TO_LOWER=TRUE;LOCK_TIMEOUT=10000";

    private String driver;
    private String url;
    private String serverUrl;
    private String databaseName;
    private String user;
    private String password;
    private int wafOrgId;
    private int blockThreshold;
    private int loginFailMax;
    private long loginFailWindowMs;
    private int rateLimitMax;
    private long rateLimitWindowMs;
    private int attackStrikeMax;
    private long attackStrikeWindowMs;
    private long blockDurationMs;

    public DatabaseConfig() {
        this.driver = "org.h2.Driver";
        this.url = buildH2Url(new File("data", "threatgate").getAbsolutePath());
        this.serverUrl = "";
        this.databaseName = "threatgate";
        this.user = "sa";
        this.password = "";
        this.wafOrgId = 1;
        this.blockThreshold = 50;
        this.loginFailMax = 5;
        this.loginFailWindowMs = 60_000L;
        this.rateLimitMax = 100;
        this.rateLimitWindowMs = 10_000L;
        this.attackStrikeMax = 8;
        this.attackStrikeWindowMs = 60_000L;
        this.blockDurationMs = 300_000L;
    }

    public static String buildH2Url(String fileBasePath) {
        String raw = fileBasePath != null ? fileBasePath.trim() : new File("data", "threatgate").getAbsolutePath();
        if (raw.endsWith(".mv.db")) {
            raw = raw.substring(0, raw.length() - 6);
        }
        String normalized = raw.replace('\\', '/');
        return H2_PREFIX + normalized + H2_OPTIONS;
    }

    public static DatabaseConfig forEmbeddedDirectory(
            String dataDirectory,
            String primaryPath,
            String fallbackPath) {
        DatabaseConfig config = load(primaryPath, fallbackPath);
        File primary = primaryPath != null ? new File(primaryPath) : null;
        boolean hasPrimaryOverride = primary != null && primary.exists() && primary.isFile();
        if (!hasPrimaryOverride || (config.isEmbeddedH2() && config.getUrl().contains("./data/threatgate"))) {
            File dbBase = new File(dataDirectory, "threatgate");
            config.setDriver("org.h2.Driver");
            config.setUrl(buildH2Url(dbBase.getAbsolutePath()));
            config.setServerUrl("");
            if (!hasPrimaryOverride) {
                config.setUser("sa");
                config.setPassword("");
            }
        }
        return config;
    }

    public static DatabaseConfig load(String primaryPath, String fallbackPath) {
        DatabaseConfig config = new DatabaseConfig();
        File primary = primaryPath != null ? new File(primaryPath) : null;
        File fallback = fallbackPath != null ? new File(fallbackPath) : null;
        File target = null;

        if (primary != null && primary.exists() && primary.isFile()) {
            target = primary;
        } else if (fallback != null && fallback.exists() && fallback.isFile()) {
            target = fallback;
        }

        if (target != null) {
            Properties properties = new Properties();
            try (FileInputStream input = new FileInputStream(target)) {
                properties.load(input);
                config.applyProperties(properties);
            } catch (IOException ignored) {
            }
        }
        return config;
    }

    private void applyProperties(Properties properties) {
        this.driver = readString(properties, "db.driver", driver);
        this.url = readString(properties, "db.url", url);
        if (properties.containsKey("db.serverUrl")) {
            this.serverUrl = properties.getProperty("db.serverUrl", "").trim();
        }
        this.databaseName = sanitizeDatabaseName(readString(properties, "db.name", databaseName));
        this.user = readString(properties, "db.user", user);
        this.password = properties.getProperty("db.password", password);
        this.wafOrgId = readInt(properties, "waf.orgId", wafOrgId);
        this.blockThreshold = readInt(properties, "waf.blockThreshold", blockThreshold);
        this.loginFailMax = readInt(properties, "waf.loginFailMax", loginFailMax);
        this.loginFailWindowMs = readLong(properties, "waf.loginFailWindowMs", loginFailWindowMs);
        this.rateLimitMax = readInt(properties, "waf.rateLimitMax", rateLimitMax);
        this.rateLimitWindowMs = readLong(properties, "waf.rateLimitWindowMs", rateLimitWindowMs);
        this.attackStrikeMax = readInt(properties, "waf.attackStrikeMax", attackStrikeMax);
        this.attackStrikeWindowMs = readLong(properties, "waf.attackStrikeWindowMs", attackStrikeWindowMs);
        this.blockDurationMs = readLong(properties, "waf.blockDurationMs", blockDurationMs);
    }

    public void saveToFile(String filePath) throws IOException {
        File file = new File(filePath);
        File parent = file.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }
        Properties properties = new Properties();
        properties.setProperty("db.driver", driver);
        properties.setProperty("db.url", url);
        properties.setProperty("db.serverUrl", serverUrl != null ? serverUrl : "");
        properties.setProperty("db.name", databaseName);
        properties.setProperty("db.user", user);
        properties.setProperty("db.password", password != null ? password : "");
        properties.setProperty("waf.orgId", String.valueOf(wafOrgId));
        properties.setProperty("waf.blockThreshold", String.valueOf(blockThreshold));
        properties.setProperty("waf.loginFailMax", String.valueOf(loginFailMax));
        properties.setProperty("waf.loginFailWindowMs", String.valueOf(loginFailWindowMs));
        properties.setProperty("waf.rateLimitMax", String.valueOf(rateLimitMax));
        properties.setProperty("waf.rateLimitWindowMs", String.valueOf(rateLimitWindowMs));
        properties.setProperty("waf.attackStrikeMax", String.valueOf(attackStrikeMax));
        properties.setProperty("waf.attackStrikeWindowMs", String.valueOf(attackStrikeWindowMs));
        properties.setProperty("waf.blockDurationMs", String.valueOf(blockDurationMs));

        try (FileOutputStream output = new FileOutputStream(file)) {
            properties.store(output, null);
        }
    }

    public boolean isEmbeddedH2() {
        return url != null && url.toLowerCase().startsWith("jdbc:h2:");
    }

    public String getDatabaseFilePath() {
        if (url != null && url.toLowerCase().startsWith(H2_PREFIX)) {
            String remainder = url.substring(H2_PREFIX.length());
            int semi = remainder.indexOf(';');
            String base = semi >= 0 ? remainder.substring(0, semi) : remainder;
            return base + ".mv.db";
        }
        return url != null ? url : "";
    }

    private static String sanitizeDatabaseName(String candidate) {
        if (candidate == null || !candidate.matches("[a-zA-Z0-9_]+")) {
            return "threatgate";
        }
        return candidate;
    }

    private static String readString(Properties properties, String key, String defaultValue) {
        String value = properties.getProperty(key);
        return value != null && !value.trim().isEmpty() ? value.trim() : defaultValue;
    }

    private static int readInt(Properties properties, String key, int defaultValue) {
        String value = properties.getProperty(key);
        if (value == null || value.trim().isEmpty()) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private static long readLong(Properties properties, String key, long defaultValue) {
        String value = properties.getProperty(key);
        if (value == null || value.trim().isEmpty()) {
            return defaultValue;
        }
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    public String getDriver() {
        return driver;
    }

    public void setDriver(String driver) {
        this.driver = driver;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getServerUrl() {
        return serverUrl;
    }

    public void setServerUrl(String serverUrl) {
        this.serverUrl = serverUrl;
    }

    public String getDatabaseName() {
        return databaseName;
    }

    public void setDatabaseName(String databaseName) {
        this.databaseName = sanitizeDatabaseName(databaseName);
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password != null ? password : "";
    }

    public int getWafOrgId() {
        return wafOrgId;
    }

    public int getBlockThreshold() {
        return blockThreshold;
    }

    public int getLoginFailMax() {
        return loginFailMax;
    }

    public long getLoginFailWindowMs() {
        return loginFailWindowMs;
    }

    public int getRateLimitMax() {
        return rateLimitMax;
    }

    public long getRateLimitWindowMs() {
        return rateLimitWindowMs;
    }

    public int getAttackStrikeMax() {
        return attackStrikeMax;
    }

    public long getAttackStrikeWindowMs() {
        return attackStrikeWindowMs;
    }

    public long getBlockDurationMs() {
        return blockDurationMs;
    }
}
