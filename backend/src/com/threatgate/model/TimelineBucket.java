package com.threatgate.model;

import java.io.Serial;
import java.io.Serializable;

public class TimelineBucket implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private final String bucket;
    private final long allowed;
    private final long blocked;

    public TimelineBucket(String bucket, long allowed, long blocked) {
        this.bucket = bucket != null ? bucket : "";
        this.allowed = allowed;
        this.blocked = blocked;
    }

    public String getBucket() {
        return bucket;
    }

    public long getAllowed() {
        return allowed;
    }

    public long getBlocked() {
        return blocked;
    }

    @Override
    public String toString() {
        return String.format("TimelineBucket [bucket='%s', allowed=%d, blocked=%d]", bucket, allowed, blocked);
    }
}
