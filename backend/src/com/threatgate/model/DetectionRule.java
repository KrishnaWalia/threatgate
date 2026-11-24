package com.threatgate.model;

import java.io.Serial;
import java.io.Serializable;
import java.sql.Timestamp;
import java.util.List;
import java.util.Objects;

public class DetectionRule implements Identifiable<Integer>, Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private int id;
    private int orgId;
    private String category;
    private String pattern;
    private int weight;
    private boolean active;
    private String description;
    private Timestamp createdAt;

    public DetectionRule() {
        this.orgId = 1;
        this.category = "other";
        this.pattern = "";
        this.weight = 10;
        this.active = true;
        this.description = "";
        this.createdAt = new Timestamp(System.currentTimeMillis());
    }

    public DetectionRule(
            int id,
            int orgId,
            String category,
            String pattern,
            int weight,
            boolean active,
            String description,
            Timestamp createdAt) {
        this.id = id;
        this.orgId = orgId;
        this.category = category != null ? category.trim().toLowerCase() : "other";
        this.pattern = pattern != null ? pattern : "";
        this.weight = Math.max(1, Math.min(100, weight));
        this.active = active;
        this.description = description != null ? description : "";
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

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category != null ? category.trim().toLowerCase() : "other";
    }

    public String getPattern() {
        return pattern;
    }

    public void setPattern(String pattern) {
        this.pattern = pattern != null ? pattern : "";
    }

    public int getWeight() {
        return weight;
    }

    public void setWeight(int weight) {
        this.weight = Math.max(1, Math.min(100, weight));
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description != null ? description : "";
    }

    public Timestamp getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Timestamp createdAt) {
        this.createdAt = createdAt;
    }

    public String toCsvRow() {
        return CsvCodec.joinFields(
                String.valueOf(id),
                String.valueOf(orgId),
                CsvCodec.escapeField(category),
                CsvCodec.escapeField(pattern),
                String.valueOf(weight),
                String.valueOf(active),
                CsvCodec.escapeField(description),
                CsvCodec.formatTimestampMillis(createdAt)
        );
    }

    public static DetectionRule fromCsvRow(String csvLine) {
        if (csvLine == null || csvLine.trim().isEmpty()) {
            throw new IllegalArgumentException("Empty CSV line cannot be parsed into a DetectionRule.");
        }
        List<String> parts = CsvCodec.parseRow(csvLine);
        if (parts.size() < 8) {
            throw new IllegalArgumentException("Invalid DetectionRule CSV row: expected 8 fields, got " + parts.size());
        }
        int parsedId = Integer.parseInt(parts.get(0).trim());
        int parsedOrgId = Integer.parseInt(parts.get(1).trim());
        String parsedCategory = parts.get(2).trim();
        String parsedPattern = parts.get(3);
        int parsedWeight = Integer.parseInt(parts.get(4).trim());
        boolean parsedActive = Boolean.parseBoolean(parts.get(5).trim());
        String parsedDescription = parts.get(6);
        Timestamp parsedCreated = CsvCodec.parseTimestampMillis(parts.get(7));
        return new DetectionRule(
                parsedId,
                parsedOrgId,
                parsedCategory,
                parsedPattern,
                parsedWeight,
                parsedActive,
                parsedDescription,
                parsedCreated
        );
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof DetectionRule)) {
            return false;
        }
        DetectionRule that = (DetectionRule) other;
        return id == that.id && orgId == that.orgId && Objects.equals(pattern, that.pattern);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, orgId, pattern);
    }

    @Override
    public String toString() {
        return String.format(
                "DetectionRule [id=%d, category='%s', weight=%d, active=%s, description='%s']",
                id,
                category,
                weight,
                active,
                description
        );
    }
}
