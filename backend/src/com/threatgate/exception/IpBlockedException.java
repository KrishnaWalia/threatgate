package com.threatgate.exception;

import java.io.Serial;
import java.sql.Timestamp;

public class IpBlockedException extends Exception {
    @Serial
    private static final long serialVersionUID = 1L;

    private final String ipAddress;
    private final String reason;
    private final Timestamp expiresAt;

    public IpBlockedException(String ipAddress, String reason, Timestamp expiresAt) {
        super(String.format("Access blocked for IP '%s': %s", ipAddress, reason != null ? reason : "policy"));
        this.ipAddress = ipAddress;
        this.reason = reason;
        this.expiresAt = expiresAt;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String getReason() {
        return reason;
    }

    public Timestamp getExpiresAt() {
        return expiresAt;
    }
}
