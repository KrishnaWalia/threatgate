package com.threatgate.db;

import com.threatgate.exception.DatabaseException;
import com.threatgate.model.AttackLog;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.List;

public class AttackLogJdbcDao {
    private static final String SELECT_COLUMNS =
            "SELECT id, org_id, ip_address, method, path, category, risk_score, action, matched_rule_id, user_agent, created_at FROM attack_logs ";

    private final DatabaseConnection databaseConnection;

    public AttackLogJdbcDao(DatabaseConnection databaseConnection) {
        this.databaseConnection = databaseConnection;
    }

    public AttackLog insert(AttackLog log) throws DatabaseException {
        String sql = "INSERT INTO attack_logs "
                + "(org_id, ip_address, method, path, category, risk_score, action, matched_rule_id, user_agent) "
                + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try (Connection connection = databaseConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            statement.setInt(1, log.getOrgId());
            statement.setString(2, log.getIpAddress());
            statement.setString(3, log.getMethod());
            statement.setString(4, log.getPath());
            statement.setString(5, log.getCategory());
            statement.setInt(6, log.getRiskScore());
            statement.setString(7, log.getAction());
            if (log.getMatchedRuleId() != null) {
                statement.setInt(8, log.getMatchedRuleId());
            } else {
                statement.setNull(8, Types.INTEGER);
            }
            if (log.getUserAgent() != null) {
                statement.setString(9, log.getUserAgent());
            } else {
                statement.setNull(9, Types.VARCHAR);
            }
            statement.executeUpdate();
            try (ResultSet keys = statement.getGeneratedKeys()) {
                if (keys.next()) {
                    long generatedId = keys.getLong(1);
                    return findById(generatedId, log);
                }
            }
            return log;
        } catch (SQLException e) {
            throw new DatabaseException("Failed to insert attack log: " + e.getMessage(), e);
        }
    }

    private AttackLog findById(long id, AttackLog fallback) throws SQLException, DatabaseException {
        String sql = SELECT_COLUMNS + "WHERE id = ?";
        try (Connection connection = databaseConnection.getConnection()) {
            return JdbcTemplateHelper.queryForOptional(
                    connection,
                    sql,
                    statement -> statement.setLong(1, id),
                    AttackLogJdbcDao::mapRow
            ).orElseGet(() -> {
                fallback.setId(id);
                return fallback;
            });
        }
    }

    public List<AttackLog> findRecentByOrg(int orgId, int limit) throws DatabaseException {
        String sql = SELECT_COLUMNS + "WHERE org_id = ? ORDER BY created_at DESC, id DESC LIMIT ?";
        int safeLimit = Math.max(1, Math.min(limit, 5000));
        try (Connection connection = databaseConnection.getConnection()) {
            return JdbcTemplateHelper.queryForList(
                    connection,
                    sql,
                    statement -> {
                        statement.setInt(1, orgId);
                        statement.setInt(2, safeLimit);
                    },
                    AttackLogJdbcDao::mapRow
            );
        } catch (SQLException e) {
            throw new DatabaseException("Failed to query recent attack logs: " + e.getMessage(), e);
        }
    }

    public List<AttackLog> findAllByOrg(int orgId) throws DatabaseException {
        String sql = SELECT_COLUMNS + "WHERE org_id = ? ORDER BY created_at DESC, id DESC";
        try (Connection connection = databaseConnection.getConnection()) {
            return JdbcTemplateHelper.queryForList(
                    connection,
                    sql,
                    statement -> statement.setInt(1, orgId),
                    AttackLogJdbcDao::mapRow
            );
        } catch (SQLException e) {
            throw new DatabaseException("Failed to query all attack logs: " + e.getMessage(), e);
        }
    }

    public long[] countByAction(int orgId) throws DatabaseException {
        String sql = "SELECT COUNT(*) AS total_requests, "
                + "COALESCE(SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END), 0) AS total_blocked, "
                + "COALESCE(SUM(CASE WHEN action = 'allowed' THEN 1 ELSE 0 END), 0) AS total_allowed "
                + "FROM attack_logs WHERE org_id = ?";
        try (Connection connection = databaseConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setInt(1, orgId);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    return new long[] {
                            resultSet.getLong("total_requests"),
                            resultSet.getLong("total_blocked"),
                            resultSet.getLong("total_allowed")
                    };
                }
            }
            return new long[] { 0L, 0L, 0L };
        } catch (SQLException e) {
            throw new DatabaseException("Failed to aggregate attack log counts: " + e.getMessage(), e);
        }
    }

    public int deleteOlderThan(int orgId, Timestamp cutoff) throws DatabaseException {
        String sql = "DELETE FROM attack_logs WHERE org_id = ? AND created_at < ?";
        try (Connection connection = databaseConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setInt(1, orgId);
            statement.setTimestamp(2, cutoff);
            return statement.executeUpdate();
        } catch (SQLException e) {
            throw new DatabaseException("Failed to delete older attack logs: " + e.getMessage(), e);
        }
    }

    private static AttackLog mapRow(ResultSet resultSet) throws SQLException {
        int rawRuleId = resultSet.getInt("matched_rule_id");
        Integer matchedRuleId = resultSet.wasNull() ? null : rawRuleId;
        return new AttackLog(
                resultSet.getLong("id"),
                resultSet.getInt("org_id"),
                resultSet.getString("ip_address"),
                resultSet.getString("method"),
                resultSet.getString("path"),
                resultSet.getString("category"),
                resultSet.getInt("risk_score"),
                resultSet.getString("action"),
                matchedRuleId,
                resultSet.getString("user_agent"),
                resultSet.getTimestamp("created_at")
        );
    }
}
