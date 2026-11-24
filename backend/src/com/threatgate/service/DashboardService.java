package com.threatgate.service;

import com.threatgate.exception.DatabaseException;
import com.threatgate.model.AttackLog;
import com.threatgate.model.CategoryCount;
import com.threatgate.model.DashboardStats;
import com.threatgate.model.TimelineBucket;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class DashboardService {
    private static final long ONE_DAY_MS = 24L * 3600L * 1000L;
    private static final long ONE_HOUR_MS = 3600L * 1000L;
    private static final DateTimeFormatter BUCKET_FORMATTER =
            DateTimeFormatter.ofPattern("HH:mm").withZone(ZoneId.systemDefault());

    private final AttackLogService attackLogService;
    private final BruteForceService bruteForceService;

    public DashboardService(AttackLogService attackLogService, BruteForceService bruteForceService) {
        this.attackLogService = attackLogService;
        this.bruteForceService = bruteForceService;
    }

    public DashboardStats getStats(int orgId) throws DatabaseException {
        List<AttackLog> orgLogs = attackLogService.listAllLogs(orgId);
        long activeBlockedIps = bruteForceService.countActiveBlockedIps(orgId);

        long totalRequests = orgLogs.size();
        long totalBlocked = orgLogs.stream()
                .filter(AttackLog::isBlocked)
                .count();
        long totalAllowed = totalRequests - totalBlocked;

        long now = System.currentTimeMillis();
        long dayAgo = now - ONE_DAY_MS;
        long hourAgo = now - ONE_HOUR_MS;

        Map<String, Long> categoryMap = orgLogs.stream()
                .filter(log -> log.getCreatedAt() != null && log.getCreatedAt().getTime() >= dayAgo)
                .collect(Collectors.groupingBy(AttackLog::getCategory, Collectors.counting()));

        List<CategoryCount> byCategory = categoryMap.entrySet().stream()
                .map(entry -> new CategoryCount(entry.getKey(), entry.getValue()))
                .sorted(Comparator.comparingLong(CategoryCount::getCount).reversed()
                        .thenComparing(CategoryCount::getCategory))
                .collect(Collectors.toList());

        Map<String, List<AttackLog>> bucketGroups = orgLogs.stream()
                .filter(log -> log.getCreatedAt() != null && log.getCreatedAt().getTime() >= hourAgo)
                .collect(Collectors.groupingBy(
                        log -> BUCKET_FORMATTER.format(Instant.ofEpochMilli(log.getCreatedAt().getTime()))
                ));

        List<TimelineBucket> timeline = bucketGroups.entrySet().stream()
                .map(entry -> {
                    long allowedCount = entry.getValue().stream().filter(log -> !log.isBlocked()).count();
                    long blockedCount = entry.getValue().size() - allowedCount;
                    return new TimelineBucket(entry.getKey(), allowedCount, blockedCount);
                })
                .sorted(Comparator.comparing(TimelineBucket::getBucket))
                .collect(Collectors.toList());

        return new DashboardStats(
                totalRequests,
                totalBlocked,
                totalAllowed,
                activeBlockedIps,
                byCategory,
                timeline
        );
    }
}
