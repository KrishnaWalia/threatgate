package com.threatgate.db;

import com.threatgate.exception.DatabaseException;
import com.threatgate.exception.InvalidDataException;
import com.threatgate.model.User;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Optional;

public class UserJdbcDao {
    private static final String SELECT_COLUMNS =
            "SELECT id, org_id, email, password_hash, role, created_at FROM users ";

    private final DatabaseConnection databaseConnection;

    public UserJdbcDao(DatabaseConnection databaseConnection) {
        this.databaseConnection = databaseConnection;
    }

    public Optional<User> findByEmail(String email) throws DatabaseException {
        String sql = SELECT_COLUMNS + "WHERE email = ?";
        try (Connection connection = databaseConnection.getConnection()) {
            return JdbcTemplateHelper.queryForOptional(
                    connection,
                    sql,
                    statement -> statement.setString(1, email.trim().toLowerCase()),
                    UserJdbcDao::mapRow
            );
        } catch (SQLException e) {
            throw new DatabaseException("Failed to find user by email: " + e.getMessage(), e);
        }
    }

    public Optional<User> findById(int id) throws DatabaseException {
        String sql = SELECT_COLUMNS + "WHERE id = ?";
        try (Connection connection = databaseConnection.getConnection()) {
            return JdbcTemplateHelper.queryForOptional(
                    connection,
                    sql,
                    statement -> statement.setInt(1, id),
                    UserJdbcDao::mapRow
            );
        } catch (SQLException e) {
            throw new DatabaseException("Failed to find user by ID: " + e.getMessage(), e);
        }
    }

    public List<User> findAllByOrg(int orgId) throws DatabaseException {
        String sql = SELECT_COLUMNS + "WHERE org_id = ? ORDER BY id ASC";
        try (Connection connection = databaseConnection.getConnection()) {
            return JdbcTemplateHelper.queryForList(
                    connection,
                    sql,
                    statement -> statement.setInt(1, orgId),
                    UserJdbcDao::mapRow
            );
        } catch (SQLException e) {
            throw new DatabaseException("Failed to list users for org: " + e.getMessage(), e);
        }
    }

    public User create(User user) throws DatabaseException, InvalidDataException {
        String sql = "INSERT INTO users (org_id, email, password_hash, role) VALUES (?, ?, ?, ?)";
        try (Connection connection = databaseConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            statement.setInt(1, user.getOrgId());
            statement.setString(2, user.getEmail());
            statement.setString(3, user.getPasswordHash());
            statement.setString(4, user.getRole());
            statement.executeUpdate();
            try (ResultSet keys = statement.getGeneratedKeys()) {
                if (keys.next()) {
                    user.setId(keys.getInt(1));
                }
            }
            return user;
        } catch (SQLException e) {
            if ("23000".equals(e.getSQLState()) || e.getErrorCode() == 1062) {
                throw new InvalidDataException("An account with that email already exists.", e);
            }
            throw new DatabaseException("Failed to create user: " + e.getMessage(), e);
        }
    }

    public boolean updateRole(int userId, String role) throws DatabaseException {
        String sql = "UPDATE users SET role = ? WHERE id = ?";
        try (Connection connection = databaseConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, "admin".equalsIgnoreCase(role) ? "admin" : "viewer");
            statement.setInt(2, userId);
            return statement.executeUpdate() > 0;
        } catch (SQLException e) {
            throw new DatabaseException("Failed to update user role: " + e.getMessage(), e);
        }
    }

    public boolean deleteById(int userId) throws DatabaseException {
        String sql = "DELETE FROM users WHERE id = ?";
        try (Connection connection = databaseConnection.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setInt(1, userId);
            return statement.executeUpdate() > 0;
        } catch (SQLException e) {
            throw new DatabaseException("Failed to delete user: " + e.getMessage(), e);
        }
    }

    private static User mapRow(ResultSet resultSet) throws SQLException {
        return new User(
                resultSet.getInt("id"),
                resultSet.getInt("org_id"),
                resultSet.getString("email"),
                resultSet.getString("password_hash"),
                resultSet.getString("role"),
                resultSet.getTimestamp("created_at")
        );
    }
}
