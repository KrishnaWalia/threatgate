package com.threatgate.db;

import com.threatgate.exception.DatabaseException;
import com.threatgate.model.DetectionRule;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class SchemaInitializer {
    private static final List<String> TABLE_NAMES = List.of(
            "orgs", "users", "rules", "attack_logs", "blocked_ips"
    );

    private static final String CREATE_ORGS_SQL =
            "CREATE TABLE IF NOT EXISTS orgs ("
                    + "id INT AUTO_INCREMENT PRIMARY KEY, "
                    + "name VARCHAR(120) NOT NULL, "
                    + "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
                    + ")";

    private static final String CREATE_USERS_SQL =
            "CREATE TABLE IF NOT EXISTS users ("
                    + "id INT AUTO_INCREMENT PRIMARY KEY, "
                    + "org_id INT NOT NULL, "
                    + "email VARCHAR(190) NOT NULL UNIQUE, "
                    + "password_hash VARCHAR(100) NOT NULL, "
                    + "role VARCHAR(20) NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin', 'viewer')), "
                    + "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, "
                    + "CONSTRAINT fk_users_org FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE"
                    + ")";

    private static final String CREATE_RULES_SQL =
            "CREATE TABLE IF NOT EXISTS rules ("
                    + "id INT AUTO_INCREMENT PRIMARY KEY, "
                    + "org_id INT NOT NULL, "
                    + "category VARCHAR(32) NOT NULL CHECK (category IN ('sqli', 'xss', 'path_traversal', 'other')), "
                    + "pattern TEXT NOT NULL, "
                    + "weight INT NOT NULL DEFAULT 10, "
                    + "is_active BOOLEAN NOT NULL DEFAULT TRUE, "
                    + "description VARCHAR(255), "
                    + "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, "
                    + "CONSTRAINT fk_rules_org FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE"
                    + ")";

    private static final String CREATE_ATTACK_LOGS_SQL =
            "CREATE TABLE IF NOT EXISTS attack_logs ("
                    + "id BIGINT AUTO_INCREMENT PRIMARY KEY, "
                    + "org_id INT NOT NULL, "
                    + "ip_address VARCHAR(45) NOT NULL, "
                    + "method VARCHAR(10) NOT NULL, "
                    + "path VARCHAR(2048) NOT NULL, "
                    + "category VARCHAR(32) NOT NULL CHECK (category IN ('sqli', 'xss', 'path_traversal', 'brute_force', 'none')), "
                    + "risk_score INT NOT NULL DEFAULT 0, "
                    + "action VARCHAR(16) NOT NULL CHECK (action IN ('allowed', 'blocked')), "
                    + "matched_rule_id INT NULL, "
                    + "user_agent VARCHAR(512), "
                    + "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, "
                    + "CONSTRAINT fk_logs_org FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE, "
                    + "CONSTRAINT fk_logs_rule FOREIGN KEY (matched_rule_id) REFERENCES rules(id) ON DELETE SET NULL"
                    + ")";

    private static final String CREATE_BLOCKED_IPS_SQL =
            "CREATE TABLE IF NOT EXISTS blocked_ips ("
                    + "id INT AUTO_INCREMENT PRIMARY KEY, "
                    + "org_id INT NOT NULL, "
                    + "ip_address VARCHAR(45) NOT NULL, "
                    + "reason VARCHAR(255), "
                    + "blocked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, "
                    + "expires_at TIMESTAMP NULL, "
                    + "CONSTRAINT fk_blocked_org FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE, "
                    + "CONSTRAINT uniq_org_ip UNIQUE (org_id, ip_address)"
                    + ")";

    private final DatabaseConnection databaseConnection;

    public SchemaInitializer(DatabaseConnection databaseConnection) {
        this.databaseConnection = databaseConnection;
    }

    public void initializeTables() throws DatabaseException {
        databaseConnection.ensureDatabaseExists();
        try (Connection connection = databaseConnection.getConnection();
             Statement statement = connection.createStatement()) {
            statement.executeUpdate(CREATE_ORGS_SQL);
            statement.executeUpdate(CREATE_USERS_SQL);
            statement.executeUpdate(CREATE_RULES_SQL);
            statement.executeUpdate(CREATE_ATTACK_LOGS_SQL);
            statement.executeUpdate(CREATE_BLOCKED_IPS_SQL);
            if (databaseConnection.getConfig().isEmbeddedH2()) {
                statement.executeUpdate("CREATE INDEX IF NOT EXISTS idx_logs_org_created ON attack_logs (org_id, created_at)");
                statement.executeUpdate("CREATE INDEX IF NOT EXISTS idx_logs_ip ON attack_logs (ip_address)");
            }
        } catch (SQLException e) {
            throw new DatabaseException("Failed to initialize database schema: " + e.getMessage(), e);
        }
    }

    public int seedDefaultsIfEmpty(
            List<DetectionRule> defaultRules,
            String adminEmail,
            String adminHash,
            String viewerEmail,
            String viewerHash) throws DatabaseException {
        try (Connection connection = databaseConnection.getConnection()) {
            int orgId = ensureDefaultOrg(connection);
            ensureDefaultUsers(connection, orgId, adminEmail, adminHash, viewerEmail, viewerHash);
            ensureDefaultRules(connection, orgId, defaultRules);
            return orgId;
        } catch (SQLException e) {
            throw new DatabaseException("Failed to seed database defaults: " + e.getMessage(), e);
        }
    }

    public Map<String, Long> countAllTables() throws DatabaseException {
        Map<String, Long> counts = new LinkedHashMap<>();
        try (Connection connection = databaseConnection.getConnection();
             Statement statement = connection.createStatement()) {
            for (String table : TABLE_NAMES) {
                try (ResultSet resultSet = statement.executeQuery("SELECT COUNT(*) FROM " + table)) {
                    counts.put(table, resultSet.next() ? resultSet.getLong(1) : 0L);
                }
            }
            return counts;
        } catch (SQLException e) {
            throw new DatabaseException("Failed to count database tables: " + e.getMessage(), e);
        }
    }

    private int ensureDefaultOrg(Connection connection) throws SQLException {
        String selectSql = "SELECT id FROM orgs ORDER BY id ASC LIMIT 1";
        try (Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(selectSql)) {
            if (resultSet.next()) {
                return resultSet.getInt("id");
            }
        }
        String insertSql = "INSERT INTO orgs (name) VALUES (?)";
        try (PreparedStatement statement = connection.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
            statement.setString(1, "Demo Org");
            statement.executeUpdate();
            try (ResultSet keys = statement.getGeneratedKeys()) {
                if (keys.next()) {
                    return keys.getInt(1);
                }
            }
        }
        return 1;
    }

    private void ensureDefaultUsers(
            Connection connection,
            int orgId,
            String adminEmail,
            String adminHash,
            String viewerEmail,
            String viewerHash) throws SQLException {
        if (countRowsForOrg(connection, "SELECT COUNT(*) FROM users WHERE org_id = ?", orgId) > 0) {
            return;
        }
        String insertSql = "INSERT INTO users (org_id, email, password_hash, role) VALUES (?, ?, ?, ?)";
        try (PreparedStatement statement = connection.prepareStatement(insertSql)) {
            statement.setInt(1, orgId);
            statement.setString(2, adminEmail);
            statement.setString(3, adminHash);
            statement.setString(4, "admin");
            statement.executeUpdate();

            statement.setInt(1, orgId);
            statement.setString(2, viewerEmail);
            statement.setString(3, viewerHash);
            statement.setString(4, "viewer");
            statement.executeUpdate();
        }
    }

    private void ensureDefaultRules(
            Connection connection,
            int orgId,
            List<DetectionRule> defaultRules) throws SQLException {
        if (defaultRules == null || defaultRules.isEmpty()) {
            return;
        }
        if (countRowsForOrg(connection, "SELECT COUNT(*) FROM rules WHERE org_id = ?", orgId) > 0) {
            return;
        }
        String insertSql = "INSERT INTO rules (org_id, category, pattern, weight, is_active, description) VALUES (?, ?, ?, ?, ?, ?)";
        try (PreparedStatement statement = connection.prepareStatement(insertSql)) {
            for (DetectionRule rule : defaultRules) {
                statement.setInt(1, orgId);
                statement.setString(2, rule.getCategory());
                statement.setString(3, rule.getPattern());
                statement.setInt(4, rule.getWeight());
                statement.setBoolean(5, rule.isActive());
                statement.setString(6, rule.getDescription());
                statement.executeUpdate();
            }
        }
    }

    private long countRowsForOrg(Connection connection, String sql, int orgId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setInt(1, orgId);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    return resultSet.getLong(1);
                }
            }
        }
        return 0L;
    }
}
