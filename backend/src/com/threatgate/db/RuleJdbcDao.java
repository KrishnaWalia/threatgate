package com.threatgate.db;

import com.threatgate.exception.DatabaseException;
import com.threatgate.model.DetectionRule;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Optional;

public class RuleJdbcDao {
    private static final String SELECT_COLUMNS =
            "SELECT id, org_id, category, pattern, weight, is_active, description, created_at FROM rules ";

    private final DatabaseConnection databaseConnection;

    public RuleJdbcDao(DatabaseConnection databaseConnection) {
        this.databaseConnection = databaseConnection;
    }

    public List<DetectionRule> findAllByOrg(int orgId) throws DatabaseException {
        String sql = SELECT_COLUMNS + "WHERE org_id = ? ORDER BY id ASC";
        try (Connection connection = databaseConnection.getConnection()) {
            return JdbcTemplateHelper.queryForList(
                    connection,
                    sql,
                    statement -> statement.setInt(1, orgId),
                    RuleJdbcDao::mapRow
            );
        } catch (SQLException e) {
            throw new DatabaseException("Failed to load detection rules: " + e.getMessage(), e);
        }
    }

    public Optional<DetectionRule> findById(int orgId, int ruleId) throws DatabaseException {
        String sql = SELECT_COLUMNS + "WHERE org_id = ? AND id = ?";
        try (Connection connection = databaseConnection.getConnection()) {
            return JdbcTemplateHelper.queryForOptional(
                    connection,
                    sql,
                    statement -> {
                        statement.setInt(1, orgId);
                        statement.setInt(2, ruleId);
                    },
                    RuleJdbcDao::mapRow
            );
        } catch (SQLException e) {
            throw new DatabaseException("Failed to find detection rule: " + e.getMessage(), e);
        }
    }

    public DetectionRule create(DetectionRule rule) throws DatabaseException {
        String sql = "INSERT INTO rules (org_id, category, pattern, weight, is_active, description) VALUES (?, ?, ?, ?, ?, ?)";
        try (Connection connection = databaseConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            statement.setInt(1, rule.getOrgId());
            statement.setString(2, rule.getCategory());
            statement.setString(3, rule.getPattern());
            statement.setInt(4, rule.getWeight());
            statement.setBoolean(5, rule.isActive());
            statement.setString(6, rule.getDescription());
            statement.executeUpdate();
            try (ResultSet keys = statement.getGeneratedKeys()) {
                if (keys.next()) {
                    rule.setId(keys.getInt(1));
                }
            }
            return rule;
        } catch (SQLException e) {
            throw new DatabaseException("Failed to insert detection rule: " + e.getMessage(), e);
        }
    }

    public boolean update(int orgId, int ruleId, boolean active, int weight) throws DatabaseException {
        String sql = "UPDATE rules SET is_active = ?, weight = ? WHERE id = ? AND org_id = ?";
        try (Connection connection = databaseConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setBoolean(1, active);
            statement.setInt(2, weight);
            statement.setInt(3, ruleId);
            statement.setInt(4, orgId);
            return statement.executeUpdate() > 0;
        } catch (SQLException e) {
            throw new DatabaseException("Failed to update detection rule: " + e.getMessage(), e);
        }
    }

    public boolean updateFull(DetectionRule rule) throws DatabaseException {
        String sql = "UPDATE rules SET category = ?, pattern = ?, weight = ?, is_active = ?, description = ? WHERE id = ? AND org_id = ?";
        try (Connection connection = databaseConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, rule.getCategory());
            statement.setString(2, rule.getPattern());
            statement.setInt(3, rule.getWeight());
            statement.setBoolean(4, rule.isActive());
            statement.setString(5, rule.getDescription());
            statement.setInt(6, rule.getId());
            statement.setInt(7, rule.getOrgId());
            return statement.executeUpdate() > 0;
        } catch (SQLException e) {
            throw new DatabaseException("Failed to update detection rule details: " + e.getMessage(), e);
        }
    }

    public boolean deleteById(int orgId, int ruleId) throws DatabaseException {
        String sql = "DELETE FROM rules WHERE id = ? AND org_id = ?";
        try (Connection connection = databaseConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setInt(1, ruleId);
            statement.setInt(2, orgId);
            return statement.executeUpdate() > 0;
        } catch (SQLException e) {
            throw new DatabaseException("Failed to delete detection rule: " + e.getMessage(), e);
        }
    }

    private static DetectionRule mapRow(ResultSet resultSet) throws SQLException {
        return new DetectionRule(
                resultSet.getInt("id"),
                resultSet.getInt("org_id"),
                resultSet.getString("category"),
                resultSet.getString("pattern"),
                resultSet.getInt("weight"),
                resultSet.getBoolean("is_active"),
                resultSet.getString("description"),
                resultSet.getTimestamp("created_at")
        );
    }
}
