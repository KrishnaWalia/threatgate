package com.threatgate.db;

import com.threatgate.exception.DatabaseException;
import com.threatgate.model.DetectionRule;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

public class SchemaInitializer {
    private static final String CREATE_ORGS_SQL =
            "CREATE TABLE IF NOT EXISTS orgs ("
                    + "id INT AUTO_INCREMENT PRIMARY KEY, "
                    + "name VARCHAR(120) NOT NULL, "
                    + "created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP"
                    + ") ENGINE=InnoDB";

    private static final String CREATE_USERS_SQL =
            "CREATE TABLE IF NOT EXISTS users ("
                    + "id INT AUTO_INCREMENT PRIMARY KEY, "
                    + "org_id INT NOT NULL, "
                    + "email VARCHAR(190) NOT NULL UNIQUE, "
                    + "password_hash VARCHAR(100) NOT NULL, "
                    + "role ENUM('admin', 'viewer') NOT NULL DEFAULT 'viewer', "
                    + "created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, "
                    + "CONSTRAINT fk_users_org FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE"
                    + ") ENGINE=InnoDB";

    private static final String CREATE_RULES_SQL =
            "CREATE TABLE IF NOT EXISTS rules ("
                    + "id INT AUTO_INCREMENT PRIMARY KEY, "
                    + "org_id INT NOT NULL, "
                    + "category ENUM('sqli', 'xss', 'path_traversal', 'other') NOT NULL, "
                    + "pattern TEXT NOT NULL, "
                    + "weight INT NOT NULL DEFAULT 10, "
                    + "is_active BOOLEAN NOT NULL DEFAULT TRUE, "
                    + "description VARCHAR(255), "
                    + "created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, "
                    + "CONSTRAINT fk_rules_org FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE"
                    + ") ENGINE=InnoDB";

    private static final String CREATE_ATTACK_LOGS_SQL =
            "CREATE TABLE IF NOT EXISTS attack_logs ("
                    + "id BIGINT AUTO_INCREMENT PRIMARY KEY, "
                    + "org_id INT NOT NULL, "
                    + "ip_address VARCHAR(45) NOT NULL, "
                    + "method VARCHAR(10) NOT NULL, "
                    + "path VARCHAR(2048) NOT NULL, "
                    + "category ENUM('sqli', 'xss', 'path_traversal', 'brute_force', 'none') NOT NULL, "
                    + "risk_score INT NOT NULL DEFAULT 0, "
                    + "action ENUM('allowed', 'blocked') NOT NULL, "
                    + "matched_rule_id INT NULL, "
                    + "user_agent VARCHAR(512), "
                    + "created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, "
                    + "CONSTRAINT fk_logs_org FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE, "
                    + "CONSTRAINT fk_logs_rule FOREIGN KEY (matched_rule_id) REFERENCES rules(id) ON DELETE SET NULL, "
                    + "INDEX idx_logs_org_created (org_id, created_at), "
                    + "INDEX idx_logs_ip (ip_address)"
                    + ") ENGINE=InnoDB";

    private static final String CREATE_BLOCKED_IPS_SQL =
            "CREATE TABLE IF NOT EXISTS blocked_ips ("
                    + "id INT AUTO_INCREMENT PRIMARY KEY, "
                    + "org_id INT NOT NULL, "
                    + "ip_address VARCHAR(45) NOT NULL, "
                    + "reason VARCHAR(255), "
                    + "blocked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, "
                    + "expires_at DATETIME NULL, "
                    + "CONSTRAINT fk_blocked_org FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE, "
                    + "UNIQUE KEY uniq_org_ip (org_id, ip_address)"
                    + ") ENGINE=InnoDB";

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
