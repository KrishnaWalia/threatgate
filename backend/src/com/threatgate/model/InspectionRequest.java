package com.threatgate.model;

import java.io.Serial;
import java.io.Serializable;

public class InspectionRequest implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private final int orgId;
    private final String ipAddress;
    private final String method;
    private final String url;
    private final String body;
    private final String userAgent;
    private final String referer;
    private final String cookie;
    private final int simulatedLoginStatus;

    public InspectionRequest(
            int orgId,
            String ipAddress,
            String method,
            String url,
            String body,
            String userAgent,
            String referer,
            String cookie,
            int simulatedLoginStatus) {
        this.orgId = orgId;
        this.ipAddress = ipAddress != null && !ipAddress.trim().isEmpty() ? ipAddress.trim() : "127.0.0.1";
        this.method = method != null && !method.trim().isEmpty() ? method.trim().toUpperCase() : "GET";
        this.url = url != null && !url.isEmpty() ? url : "/";
        this.body = body != null ? body : "";
        this.userAgent = userAgent != null ? userAgent : "";
        this.referer = referer != null ? referer : "";
        this.cookie = cookie != null ? cookie : "";
        this.simulatedLoginStatus = simulatedLoginStatus;
    }

    public InspectionRequest(int orgId, String ipAddress, String method, String url, String body, String userAgent) {
        this(orgId, ipAddress, method, url, body, userAgent, "", "", 0);
    }

    public int getOrgId() {
        return orgId;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String getMethod() {
        return method;
    }

    public String getUrl() {
        return url;
    }

    public String getBody() {
        return body;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public String getReferer() {
        return referer;
    }

    public String getCookie() {
        return cookie;
    }

    public int getSimulatedLoginStatus() {
        return simulatedLoginStatus;
    }

    @Override
    public String toString() {
        return String.format("InspectionRequest [ip='%s', method='%s', url='%s', simStatus=%d]",
                ipAddress, method, url, simulatedLoginStatus);
    }
}
