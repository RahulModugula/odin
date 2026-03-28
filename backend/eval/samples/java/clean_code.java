package com.example.service;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.logging.Logger;

/**
 * Clean Java class — should produce zero findings.
 * Demonstrates proper practices: try-with-resources, parameterized queries,
 * specific exceptions, proper generics, structured logging.
 */
public class UserRepository {

    private static final Logger logger = Logger.getLogger(UserRepository.class.getName());
    private final Connection connection;

    public UserRepository(Connection connection) {
        this.connection = connection;
    }

    /**
     * Find a user by ID using a parameterized query.
     *
     * @param userId the user ID to look up
     * @return an Optional containing the user, or empty if not found
     * @throws SQLException if a database error occurs
     */
    public Optional<String> findById(int userId) throws SQLException {
        String sql = "SELECT name FROM users WHERE id = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setInt(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(rs.getString("name"));
                }
                return Optional.empty();
            }
        }
    }

    /**
     * List all active user names.
     *
     * @return list of user names
     * @throws SQLException if a database error occurs
     */
    public List<String> listActive() throws SQLException {
        List<String> names = new ArrayList<>();
        String sql = "SELECT name FROM users WHERE active = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setBoolean(1, true);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    names.add(rs.getString("name"));
                }
            }
        }
        return names;
    }

    /**
     * Delete a user by ID.
     *
     * @param userId the user ID to delete
     * @return true if a row was deleted
     */
    public boolean delete(int userId) {
        String sql = "DELETE FROM users WHERE id = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setInt(1, userId);
            int affected = ps.executeUpdate();
            logger.info(String.format("Removed user %d, rows affected: %d", userId, affected));
            return affected > 0;
        } catch (SQLException e) {
            logger.severe("Failed to remove user: " + e.getMessage());
            return false;
        }
    }
}
