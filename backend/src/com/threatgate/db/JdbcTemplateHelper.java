package com.threatgate.db;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public final class JdbcTemplateHelper {
    private JdbcTemplateHelper() {
    }

    public static <T> List<T> queryForList(
            Connection connection,
            String sql,
            StatementBinder binder,
            RowMapper<T> mapper) throws SQLException {
        List<T> results = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            if (binder != null) {
                binder.bind(statement);
            }
            try (ResultSet resultSet = statement.executeQuery()) {
                while (resultSet.next()) {
                    results.add(mapper.mapRow(resultSet));
                }
            }
        }
        return results;
    }

    public static <T> Optional<T> queryForOptional(
            Connection connection,
            String sql,
            StatementBinder binder,
            RowMapper<T> mapper) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            if (binder != null) {
                binder.bind(statement);
            }
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    return Optional.of(mapper.mapRow(resultSet));
                }
            }
        }
        return Optional.empty();
    }
}
