package com.threatgate.model;

import java.io.Serial;
import java.io.Serializable;
import java.sql.Timestamp;
import java.util.List;
import java.util.Objects;

public class User implements Identifiable<Integer>, Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private int id;
    private int orgId;
    private String email;
    private String passwordHash;
    private String role;
    private Timestamp createdAt;

    public User() {
        this.orgId = 1;
        this.email = "";
        this.passwordHash = "";
        this.role = "viewer";
        this.createdAt = new Timestamp(System.currentTimeMillis());
    }

    public User(int id, int orgId, String email, String passwordHash, String role, Timestamp createdAt) {
        this.id = id;
        this.orgId = orgId;
        this.email = email != null ? email.trim().toLowerCase() : "";
        this.passwordHash = passwordHash != null ? passwordHash : "";
        this.role = "admin".equalsIgnoreCase(role) ? "admin" : "viewer";
        this.createdAt = createdAt != null ? createdAt : new Timestamp(System.currentTimeMillis());
    }

    @Override
    public Integer getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public int getOrgId() {
        return orgId;
    }

    public void setOrgId(int orgId) {
        this.orgId = orgId;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email != null ? email.trim().toLowerCase() : "";
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash != null ? passwordHash : "";
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = "admin".equalsIgnoreCase(role) ? "admin" : "viewer";
    }

    public Timestamp getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Timestamp createdAt) {
        this.createdAt = createdAt;
    }

    public boolean isAdmin() {
        return "admin".equalsIgnoreCase(role);
    }

    public String toCsvRow() {
        return CsvCodec.joinFields(
                String.valueOf(id),
                String.valueOf(orgId),
                CsvCodec.escapeField(email),
                CsvCodec.escapeField(passwordHash),
                CsvCodec.escapeField(role),
                CsvCodec.formatTimestampMillis(createdAt)
        );
    }

    public static User fromCsvRow(String csvLine) {
        if (csvLine == null || csvLine.trim().isEmpty()) {
            throw new IllegalArgumentException("Empty CSV line cannot be parsed into a User.");
        }
        List<String> parts = CsvCodec.parseRow(csvLine);
        if (parts.size() < 6) {
            throw new IllegalArgumentException("Invalid User CSV row: expected 6 fields, got " + parts.size());
        }
        int parsedId = Integer.parseInt(parts.get(0).trim());
        int parsedOrgId = Integer.parseInt(parts.get(1).trim());
        String parsedEmail = parts.get(2).trim();
        String parsedHash = parts.get(3).trim();
        String parsedRole = parts.get(4).trim();
        Timestamp parsedCreated = CsvCodec.parseTimestampMillis(parts.get(5));
        return new User(parsedId, parsedOrgId, parsedEmail, parsedHash, parsedRole, parsedCreated);
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof User)) {
            return false;
        }
        User that = (User) other;
        return id == that.id && orgId == that.orgId && Objects.equals(email, that.email);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, orgId, email);
    }

    @Override
    public String toString() {
        return String.format("User [id=%d, orgId=%d, email='%s', role='%s']", id, orgId, email, role);
    }
}
