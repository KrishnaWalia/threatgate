package com.threatgate.db;

import com.threatgate.exception.DatabaseException;
import com.threatgate.model.BlockedIp;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.List;
import java.util.Optional;

public class BlockedIpJdbcDao {
    private static final String SELECT_COLUMNS =
            "SELECT id, org_id, ip_address, reason, blocked_at, expires_at FROM blocked_ips ";

    private final DatabaseConnection databaseConnection;

    public BlockedIpJdbcDao(DatabaseConnection databaseConnection) {
        this.databaseConnection = databaseConnection;
    }

    public BlockedIp upsertBlock(BlockedIp block) throws DatabaseException {
        String upsertSql = "INSERT INTO blocked_ips (org_id, ip_address, reason, blocked_at, expires_at) "
                + "VALUES (?, ?, ?, ?, ?) "
                + "ON DUPLICATE KEY UPDATE reason = VALUES(reason), blocked_at = VALUES(blocked_at), expires_at = VALUES(expires_at)";
        Timestamp blockedAt = block.getBlockedAt() != null
                ? block.getBlockedAt()
                : new Timestamp(System.currentTimeMillis());

        try (Connection connection = databaseConnection.getConnection()) {
            try (PreparedStatement statement = connection.prepareStatement(upsertSql)) {
                statement.setInt(1, block.getOrgId());
                statement.setString(2, block.getIpAddress());
                if (block.getReason() != null) {
                    statement.setString(3, block.getReason());
                } else {
                    statement.setNull(3, Types.VARCHAR);
                }
                statement.setTimestamp(4, blockedAt);
                if (block.getExpiresAt() != null) {
                    statement.setTimestamp(5, block.getExpiresAt());
                } else {
                    statement.setNull(5, Types.TIMESTAMP);
                }
                statement.executeUpdate();
            }

            String selectSql = SELECT_COLUMNS + "WHERE org_id = ? AND ip_address = ?";
            return JdbcTemplateHelper.queryForOptional(
                    connection,
                    selectSql,
                    statement -> {
                        statement.setInt(1, block.getOrgId());
                        statement.setString(2, block.getIpAddress());
                    },
                    BlockedIpJdbcDao::mapRow
            ).orElse(block);
        } catch (SQLException e) {
            throw new DatabaseException("Failed to upsert blocked IP: " + e.getMessage(), e);
        }
    }

    public List<BlockedIp> findActiveByOrg(int orgId) throws DatabaseException {
        String sql = SELECT_COLUMNS
                + "WHERE org_id = ? AND (expires_at IS NULL OR expires_at > NOW()) ORDER BY blocked_at DESC";
        try (Connection connection = databaseConnection.getConnection()) {
            return JdbcTemplateHelper.queryForList(
                    connection,
                    sql,
                    statement -> statement.setInt(1, orgId),
                    BlockedIpJdbcDao::mapRow
            );
        } catch (SQLException e) {
            throw new DatabaseException("Failed to query active blocked IPs: " + e.getMessage(), e);
        }
    }

    public Optional<BlockedIp> findActiveByOrgAndIp(int orgId, String ipAddress) throws DatabaseException {
        String sql = SELECT_COLUMNS
                + "WHERE org_id = ? AND ip_address = ? AND (expires_at IS NULL OR expires_at > NOW()) LIMIT 1";
        try (Connection connection = databaseConnection.getConnection()) {
            return JdbcTemplateHelper.queryForOptional(
                    connection,
                    sql,
                    statement -> {
                        statement.setInt(1, orgId);
                        statement.setString(2, ipAddress);
                    },
                    BlockedIpJdbcDao::mapRow
            );
        } catch (SQLException e) {
            throw new DatabaseException("Failed to check active blocked IP: " + e.getMessage(), e);
        }
    }

    public Optional<BlockedIp> findById(int orgId, int id) throws DatabaseException {
        String sql = SELECT_COLUMNS + "WHERE org_id = ? AND id = ?";
        try (Connection connection = databaseConnection.getConnection()) {
            return JdbcTemplateHelper.queryForOptional(
                    connection,
                    sql,
                    statement -> {
                        statement.setInt(1, orgId);
                        statement.setInt(2, id);
                    },
                    BlockedIpJdbcDao::mapRow
            );
        } catch (SQLException e) {
            throw new DatabaseException("Failed to find blocked IP by ID: " + e.getMessage(), e);
        }
    }

    public Optional<BlockedIp> deleteById(int orgId, int id) throws DatabaseException {
        Optional<BlockedIp> existing = findById(orgId, id);
        if (existing.isEmpty()) {
            return Optional.empty();
        }
        String deleteSql = "DELETE FROM blocked_ips WHERE id = ? AND org_id = ?";
        try (Connection connection = databaseConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(deleteSql)) {
            statement.setInt(1, id);
            statement.setInt(2, orgId);
            statement.executeUpdate();
            return existing;
        } catch (SQLException e) {
            throw new DatabaseException("Failed to delete blocked IP: " + e.getMessage(), e);
        }
    }

    public int purgeExpired() throws DatabaseException {
        String sql = "DELETE FROM blocked_ips WHERE expires_at IS NOT NULL AND expires_at <= NOW()";
        try (Connection connection = databaseConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            return statement.executeUpdate();
        } catch (SQLException e) {
            throw new DatabaseException("Failed to purge expired IP blocks: " + e.getMessage(), e);
        }
    }

    private static BlockedIp mapRow(ResultSet resultSet) throws SQLException {
        return new BlockedIp(
                resultSet.getInt("id"),
                resultSet.getInt("org_id"),
                resultSet.getString("ip_address"),
                resultSet.getString("reason"),
                resultSet.getTimestamp("blocked_at"),
                resultSet.getTimestamp("expires_at")
        );
    }
}
