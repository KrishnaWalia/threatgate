package com.threatgate.model;

import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class DashboardStats implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private final long totalRequests;
    private final long totalBlocked;
    private final long totalAllowed;
    private final long activeBlockedIps;
    private final ArrayList<CategoryCount> byCategory;
    private final ArrayList<TimelineBucket> timeline;

    public DashboardStats(
            long totalRequests,
            long totalBlocked,
            long totalAllowed,
            long activeBlockedIps,
            List<CategoryCount> byCategory,
            List<TimelineBucket> timeline) {
        this.totalRequests = totalRequests;
        this.totalBlocked = totalBlocked;
        this.totalAllowed = totalAllowed;
        this.activeBlockedIps = activeBlockedIps;
        this.byCategory = byCategory != null ? new ArrayList<>(byCategory) : new ArrayList<>();
        this.timeline = timeline != null ? new ArrayList<>(timeline) : new ArrayList<>();
    }

    public long getTotalRequests() {
        return totalRequests;
    }

    public long getTotalBlocked() {
        return totalBlocked;
    }

    public long getTotalAllowed() {
        return totalAllowed;
    }

    public long getActiveBlockedIps() {
        return activeBlockedIps;
    }

    public List<CategoryCount> getByCategory() {
        return Collections.unmodifiableList(byCategory);
    }

    public List<TimelineBucket> getTimeline() {
        return Collections.unmodifiableList(timeline);
    }

    @Override
    public String toString() {
        return String.format(
                "DashboardStats [total=%d, blocked=%d, allowed=%d, activeBlockedIps=%d, categories=%d, buckets=%d]",
                totalRequests,
                totalBlocked,
                totalAllowed,
                activeBlockedIps,
                byCategory.size(),
                timeline.size()
        );
    }
}
