package com.threatgate.model;

import java.io.Serial;
import java.io.Serializable;
import java.sql.Timestamp;
import java.util.List;
import java.util.Objects;

public class AttackLog implements Identifiable<Long>, Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private long id;
    private int orgId;
    private String ipAddress;
    private String method;
    private String path;
    private String category;
    private int riskScore;
    private String action;
    private Integer matchedRuleId;
    private String userAgent;
    private Timestamp createdAt;

    public AttackLog() {
        this.orgId = 1;
        this.ipAddress = "127.0.0.1";
        this.method = "GET";
        this.path = "/";
        this.category = "none";
        this.riskScore = 0;
        this.action = "allowed";
        this.createdAt = new Timestamp(System.currentTimeMillis());
    }

    public AttackLog(
            long id,
            int orgId,
            String ipAddress,
            String method,
            String path,
            String category,
            int riskScore,
            String action,
            Integer matchedRuleId,
            String userAgent,
            Timestamp createdAt) {
        this.id = id;
        this.orgId = orgId;
        this.ipAddress = ipAddress != null ? truncate(ipAddress, 45) : "unknown";
        this.method = method != null ? truncate(method.toUpperCase(), 10) : "GET";
        this.path = path != null ? truncate(path, 2048) : "/";
        this.category = category != null ? category.trim().toLowerCase() : "none";
        this.riskScore = Math.max(0, Math.min(100, riskScore));
        this.action = "blocked".equalsIgnoreCase(action) ? "blocked" : "allowed";
        this.matchedRuleId = matchedRuleId;
        this.userAgent = userAgent != null ? truncate(userAgent, 512) : null;
        this.createdAt = createdAt != null ? createdAt : new Timestamp(System.currentTimeMillis());
    }

    private static String truncate(String value, int maxLength) {
        return value.length() <= maxLength ? value : value.substring(0, maxLength);
    }

    @Override
    public Long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public int getOrgId() {
        return orgId;
    }

    public void setOrgId(int orgId) {
        this.orgId = orgId;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress != null ? truncate(ipAddress, 45) : "unknown";
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method != null ? truncate(method.toUpperCase(), 10) : "GET";
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path != null ? truncate(path, 2048) : "/";
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category != null ? category.trim().toLowerCase() : "none";
    }

    public int getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(int riskScore) {
        this.riskScore = Math.max(0, Math.min(100, riskScore));
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = "blocked".equalsIgnoreCase(action) ? "blocked" : "allowed";
    }

    public Integer getMatchedRuleId() {
        return matchedRuleId;
    }

    public void setMatchedRuleId(Integer matchedRuleId) {
        this.matchedRuleId = matchedRuleId;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent != null ? truncate(userAgent, 512) : null;
    }

    public Timestamp getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Timestamp createdAt) {
        this.createdAt = createdAt;
    }

    public boolean isBlocked() {
        return "blocked".equalsIgnoreCase(action);
    }

    public String toCsvRow() {
        return CsvCodec.joinFields(
                String.valueOf(id),
                String.valueOf(orgId),
                CsvCodec.escapeField(ipAddress),
                CsvCodec.escapeField(method),
                CsvCodec.escapeField(path),
                CsvCodec.escapeField(category),
                String.valueOf(riskScore),
                CsvCodec.escapeField(action),
                matchedRuleId != null ? String.valueOf(matchedRuleId) : "",
                CsvCodec.escapeField(userAgent != null ? userAgent : ""),
                CsvCodec.formatTimestampMillis(createdAt)
        );
    }

    public static AttackLog fromCsvRow(String csvLine) {
        if (csvLine == null || csvLine.trim().isEmpty()) {
            throw new IllegalArgumentException("Empty CSV line cannot be parsed into an AttackLog.");
        }
        List<String> parts = CsvCodec.parseRow(csvLine);
        if (parts.size() < 11) {
            throw new IllegalArgumentException("Invalid AttackLog CSV row: expected 11 fields, got " + parts.size());
        }
        long parsedId = Long.parseLong(parts.get(0).trim());
        int parsedOrgId = Integer.parseInt(parts.get(1).trim());
        String parsedIp = parts.get(2).trim();
        String parsedMethod = parts.get(3).trim();
        String parsedPath = parts.get(4);
        String parsedCategory = parts.get(5).trim();
        int parsedRisk = Integer.parseInt(parts.get(6).trim());
        String parsedAction = parts.get(7).trim();
        String rawRuleId = parts.get(8).trim();
        Integer parsedRuleId = rawRuleId.isEmpty() ? null : Integer.valueOf(rawRuleId);
        String parsedUa = parts.get(9).isEmpty() ? null : parts.get(9);
        Timestamp parsedCreated = CsvCodec.parseTimestampMillis(parts.get(10));
        return new AttackLog(
                parsedId,
                parsedOrgId,
                parsedIp,
                parsedMethod,
                parsedPath,
                parsedCategory,
                parsedRisk,
                parsedAction,
                parsedRuleId,
                parsedUa,
                parsedCreated
        );
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof AttackLog)) {
            return false;
        }
        AttackLog that = (AttackLog) other;
        return id == that.id && orgId == that.orgId && Objects.equals(ipAddress, that.ipAddress);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, orgId, ipAddress);
    }

    @Override
    public String toString() {
        return String.format(
                "AttackLog [id=%d, ip='%s', method='%s', path='%s', category='%s', risk=%d, action='%s']",
                id,
                ipAddress,
                method,
                path,
                category,
                riskScore,
                action
        );
    }
}
