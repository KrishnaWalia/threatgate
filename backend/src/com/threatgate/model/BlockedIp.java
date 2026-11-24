package com.threatgate.model;

import java.io.Serial;
import java.io.Serializable;
import java.sql.Timestamp;
import java.util.List;
import java.util.Objects;

public class BlockedIp implements Identifiable<Integer>, Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private int id;
    private int orgId;
    private String ipAddress;
    private String reason;
    private Timestamp blockedAt;
    private Timestamp expiresAt;

    public BlockedIp() {
        this.orgId = 1;
        this.ipAddress = "";
        this.reason = "";
        this.blockedAt = new Timestamp(System.currentTimeMillis());
    }

    public BlockedIp(
            int id,
            int orgId,
            String ipAddress,
            String reason,
            Timestamp blockedAt,
            Timestamp expiresAt) {
        this.id = id;
        this.orgId = orgId;
        this.ipAddress = ipAddress != null ? ipAddress.trim() : "";
        this.reason = reason;
        this.blockedAt = blockedAt != null ? blockedAt : new Timestamp(System.currentTimeMillis());
        this.expiresAt = expiresAt;
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

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress != null ? ipAddress.trim() : "";
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public Timestamp getBlockedAt() {
        return blockedAt;
    }

    public void setBlockedAt(Timestamp blockedAt) {
        this.blockedAt = blockedAt;
    }

    public Timestamp getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Timestamp expiresAt) {
        this.expiresAt = expiresAt;
    }

    public boolean isPermanent() {
        return expiresAt == null;
    }

    public boolean isActiveAt(long nowMillis) {
        return expiresAt == null || expiresAt.getTime() > nowMillis;
    }

    public String toCsvRow() {
        return CsvCodec.joinFields(
                String.valueOf(id),
                String.valueOf(orgId),
                CsvCodec.escapeField(ipAddress),
                CsvCodec.escapeField(reason != null ? reason : ""),
                CsvCodec.formatTimestampMillis(blockedAt),
                CsvCodec.formatTimestampMillis(expiresAt)
        );
    }

    public static BlockedIp fromCsvRow(String csvLine) {
        if (csvLine == null || csvLine.trim().isEmpty()) {
            throw new IllegalArgumentException("Empty CSV line cannot be parsed into a BlockedIp.");
        }
        List<String> parts = CsvCodec.parseRow(csvLine);
        if (parts.size() < 6) {
            throw new IllegalArgumentException("Invalid BlockedIp CSV row: expected 6 fields, got " + parts.size());
        }
        int parsedId = Integer.parseInt(parts.get(0).trim());
        int parsedOrgId = Integer.parseInt(parts.get(1).trim());
        String parsedIp = parts.get(2).trim();
        String parsedReason = parts.get(3).isEmpty() ? null : parts.get(3);
        Timestamp parsedBlockedAt = CsvCodec.parseTimestampMillis(parts.get(4));
        Timestamp parsedExpiresAt = CsvCodec.parseTimestampMillis(parts.get(5));
        return new BlockedIp(parsedId, parsedOrgId, parsedIp, parsedReason, parsedBlockedAt, parsedExpiresAt);
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof BlockedIp)) {
            return false;
        }
        BlockedIp that = (BlockedIp) other;
        return id == that.id && orgId == that.orgId && Objects.equals(ipAddress, that.ipAddress);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, orgId, ipAddress);
    }

    @Override
    public String toString() {
        return String.format(
                "BlockedIp [id=%d, ip='%s', reason='%s', blockedAt=%s, expiresAt=%s]",
                id,
                ipAddress,
                reason,
                blockedAt,
                expiresAt != null ? expiresAt : "Permanent"
        );
    }
}
