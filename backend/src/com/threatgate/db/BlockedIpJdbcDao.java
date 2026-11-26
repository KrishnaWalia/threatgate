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
        String updateSql = "UPDATE blocked_ips SET reason = ?, blocked_at = ?, expires_at = ? "
                + "WHERE org_id = ? AND ip_address = ?";
        String insertSql = "INSERT INTO blocked_ips (org_id, ip_address, reason, blocked_at, expires_at) "
                + "VALUES (?, ?, ?, ?, ?)";
        Timestamp blockedAt = block.getBlockedAt() != null
                ? block.getBlockedAt()
                : new Timestamp(System.currentTimeMillis());

        try (Connection connection = databaseConnection.getConnection()) {
            int updated;
            try (PreparedStatement statement = connection.prepareStatement(updateSql)) {
                setNullableString(statement, 1, block.getReason());
                statement.setTimestamp(2, blockedAt);
                setNullableTimestamp(statement, 3, block.getExpiresAt());
                statement.setInt(4, block.getOrgId());
                statement.setString(5, block.getIpAddress());
                updated = statement.executeUpdate();
            }

            if (updated == 0) {
                try (PreparedStatement statement = connection.prepareStatement(insertSql)) {
                    statement.setInt(1, block.getOrgId());
                    statement.setString(2, block.getIpAddress());
                    setNullableString(statement, 3, block.getReason());
                    statement.setTimestamp(4, blockedAt);
                    setNullableTimestamp(statement, 5, block.getExpiresAt());
                    statement.executeUpdate();
                }
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
                + "WHERE org_id = ? AND (expires_at IS NULL OR expires_at > ?) ORDER BY blocked_at DESC";
        Timestamp now = new Timestamp(System.currentTimeMillis());
        try (Connection connection = databaseConnection.getConnection()) {
            return JdbcTemplateHelper.queryForList(
                    connection,
                    sql,
                    statement -> {
                        statement.setInt(1, orgId);
                        statement.setTimestamp(2, now);
                    },
                    BlockedIpJdbcDao::mapRow
            );
        } catch (SQLException e) {
            throw new DatabaseException("Failed to query active blocked IPs: " + e.getMessage(), e);
        }
    }

    public Optional<BlockedIp> findActiveByOrgAndIp(int orgId, String ipAddress) throws DatabaseException {
        String sql = SELECT_COLUMNS
                + "WHERE org_id = ? AND ip_address = ? AND (expires_at IS NULL OR expires_at > ?) LIMIT 1";
        Timestamp now = new Timestamp(System.currentTimeMillis());
        try (Connection connection = databaseConnection.getConnection()) {
            return JdbcTemplateHelper.queryForOptional(
                    connection,
                    sql,
                    statement -> {
                        statement.setInt(1, orgId);
                        statement.setString(2, ipAddress);
                        statement.setTimestamp(3, now);
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
        String sql = "DELETE FROM blocked_ips WHERE expires_at IS NOT NULL AND expires_at <= ?";
        Timestamp now = new Timestamp(System.currentTimeMillis());
        try (Connection connection = databaseConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setTimestamp(1, now);
            return statement.executeUpdate();
        } catch (SQLException e) {
            throw new DatabaseException("Failed to purge expired IP blocks: " + e.getMessage(), e);
        }
    }

    private void setNullableString(PreparedStatement statement, int index, String value) throws SQLException {
        if (value != null) {
            statement.setString(index, value);
        } else {
            statement.setNull(index, Types.VARCHAR);
        }
    }

    private void setNullableTimestamp(PreparedStatement statement, int index, Timestamp value) throws SQLException {
        if (value != null) {
            statement.setTimestamp(index, value);
        } else {
            statement.setNull(index, Types.TIMESTAMP);
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
