package com.threatgate.db;

import com.threatgate.exception.DatabaseException;
import com.threatgate.model.Organization;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Optional;

public class OrgJdbcDao {
    private static final String SELECT_COLUMNS = "SELECT id, name, created_at FROM orgs ";

    private final DatabaseConnection databaseConnection;

    public OrgJdbcDao(DatabaseConnection databaseConnection) {
        this.databaseConnection = databaseConnection;
    }

    public List<Organization> findAll() throws DatabaseException {
        String sql = SELECT_COLUMNS + "ORDER BY id ASC";
        try (Connection connection = databaseConnection.getConnection()) {
            return JdbcTemplateHelper.queryForList(connection, sql, null, OrgJdbcDao::mapRow);
        } catch (SQLException e) {
            throw new DatabaseException("Failed to list organizations: " + e.getMessage(), e);
        }
    }

    public Optional<Organization> findById(int id) throws DatabaseException {
        String sql = SELECT_COLUMNS + "WHERE id = ?";
        try (Connection connection = databaseConnection.getConnection()) {
            return JdbcTemplateHelper.queryForOptional(
                    connection,
                    sql,
                    statement -> statement.setInt(1, id),
                    OrgJdbcDao::mapRow
            );
        } catch (SQLException e) {
            throw new DatabaseException("Failed to find organization by ID: " + e.getMessage(), e);
        }
    }

    public Organization create(Organization organization) throws DatabaseException {
        String sql = "INSERT INTO orgs (name) VALUES (?)";
        try (Connection connection = databaseConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            statement.setString(1, organization.getName());
            statement.executeUpdate();
            try (ResultSet keys = statement.getGeneratedKeys()) {
                if (keys.next()) {
                    organization.setId(keys.getInt(1));
                }
            }
            return organization;
        } catch (SQLException e) {
            throw new DatabaseException("Failed to create organization: " + e.getMessage(), e);
        }
    }

    private static Organization mapRow(ResultSet resultSet) throws SQLException {
        return new Organization(
                resultSet.getInt("id"),
                resultSet.getString("name"),
                resultSet.getTimestamp("created_at")
        );
    }
}
