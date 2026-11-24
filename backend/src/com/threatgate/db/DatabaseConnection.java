package com.threatgate.db;

import com.threatgate.exception.DatabaseException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

public class DatabaseConnection {
    private final DatabaseConfig config;
    private volatile String lastError;

    public DatabaseConnection(DatabaseConfig config) {
        this.config = config;
        this.lastError = "";
        DriverManager.setLoginTimeout(3);
    }

    public void loadDriver() throws DatabaseException {
        try {
            Class.forName(config.getDriver());
        } catch (ClassNotFoundException e) {
            this.lastError = "JDBC driver class not found: " + config.getDriver();
            throw new DatabaseException(lastError, e);
        }
    }

    public Connection getServerConnection() throws DatabaseException {
        loadDriver();
        try {
            return DriverManager.getConnection(config.getServerUrl(), config.getUser(), config.getPassword());
        } catch (SQLException e) {
            this.lastError = e.getMessage();
            throw new DatabaseException("Failed to connect to MySQL server: " + e.getMessage(), e);
        }
    }

    public Connection getConnection() throws DatabaseException {
        loadDriver();
        try {
            return DriverManager.getConnection(config.getUrl(), config.getUser(), config.getPassword());
        } catch (SQLException e) {
            this.lastError = e.getMessage();
            throw new DatabaseException("Failed to connect to ThreatGate database: " + e.getMessage(), e);
        }
    }

    public void ensureDatabaseExists() throws DatabaseException {
        String safeDbName = config.getDatabaseName();
        String sql = "CREATE DATABASE IF NOT EXISTS `" + safeDbName
                + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci";
        try (Connection serverConnection = getServerConnection();
             Statement statement = serverConnection.createStatement()) {
            statement.executeUpdate(sql);
        } catch (SQLException e) {
            this.lastError = e.getMessage();
            throw new DatabaseException("Failed to create database '" + safeDbName + "': " + e.getMessage(), e);
        }
    }

    public boolean testConnection() {
        try {
            loadDriver();
            ensureDatabaseExists();
            try (Connection connection = getConnection()) {
                this.lastError = "";
                return connection != null && !connection.isClosed();
            }
        } catch (DatabaseException | SQLException e) {
            this.lastError = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            return false;
        }
    }

    public DatabaseConfig getConfig() {
        return config;
    }

    public String getLastError() {
        return lastError;
    }
}
