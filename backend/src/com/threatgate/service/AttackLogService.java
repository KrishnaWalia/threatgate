package com.threatgate.service;

import com.threatgate.db.AttackLogJdbcDao;
import com.threatgate.exception.DatabaseException;
import com.threatgate.model.AttackLog;
import com.threatgate.model.GenericStore;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.List;
import java.util.stream.Collectors;

public class AttackLogService {
    private static final int MAX_MEMORY_LOGS = 5000;

    private final GenericStore<AttackLog, Long> offlineLogs = new GenericStore<>();
    private final Deque<Long> insertionOrder = new ArrayDeque<>();
    private final AttackLogJdbcDao attackLogJdbcDao;
    private volatile boolean useDatabase;
    private long nextOfflineId = 1L;
    private long totalRecordedCounter = 0L;

    public AttackLogService(AttackLogJdbcDao attackLogJdbcDao, boolean useDatabase) {
        this.attackLogJdbcDao = attackLogJdbcDao;
        this.useDatabase = useDatabase;
    }

    public synchronized void setUseDatabase(boolean useDatabase) {
        this.useDatabase = useDatabase;
    }

    public synchronized AttackLog recordLog(AttackLog log) throws DatabaseException {
        totalRecordedCounter++;
        if (useDatabase && attackLogJdbcDao != null) {
            return attackLogJdbcDao.insert(log);
        }
        long assignedId = nextOfflineId++;
        log.setId(assignedId);
        offlineLogs.save(log);
        insertionOrder.addLast(assignedId);
        while (insertionOrder.size() > MAX_MEMORY_LOGS) {
            Long oldestId = insertionOrder.pollFirst();
            if (oldestId != null) {
                offlineLogs.deleteById(oldestId);
            }
        }
        return log;
    }

    public List<AttackLog> listRecentLogs(int orgId, int limit) throws DatabaseException {
        int safeLimit = Math.max(1, Math.min(limit, 500));
        if (useDatabase && attackLogJdbcDao != null) {
            return attackLogJdbcDao.findRecentByOrg(orgId, safeLimit);
        }
        return listAllLogs(orgId).stream()
                .limit(safeLimit)
                .collect(Collectors.toList());
    }

    public List<AttackLog> listAllLogs(int orgId) throws DatabaseException {
        if (useDatabase && attackLogJdbcDao != null) {
            return attackLogJdbcDao.findAllByOrg(orgId);
        }
        return offlineLogs.findAll().stream()
                .filter(log -> log.getOrgId() == orgId)
                .sorted(Comparator.comparing(AttackLog::getCreatedAt).reversed()
                        .thenComparing(Comparator.comparingLong(AttackLog::getId).reversed()))
                .collect(Collectors.toList());
    }

    public List<AttackLog> getPagedLogs(
            int orgId,
            int page,
            int pageSize,
            String categoryFilter,
            String actionFilter) throws DatabaseException {
        int safePage = Math.max(1, page);
        int safeSize = Math.max(1, Math.min(pageSize, 100));
        long offset = (long) (safePage - 1) * safeSize;
        String cat = categoryFilter != null ? categoryFilter.trim().toLowerCase() : "";
        String act = actionFilter != null ? actionFilter.trim().toLowerCase() : "";

        return listAllLogs(orgId).stream()
                .filter(log -> cat.isEmpty() || "all".equals(cat) || log.getCategory().equalsIgnoreCase(cat))
                .filter(log -> act.isEmpty() || "all".equals(act) || log.getAction().equalsIgnoreCase(act))
                .skip(offset)
                .limit(safeSize)
                .collect(Collectors.toList());
    }

    public List<String> getDistinctBlockedIps(int orgId) throws DatabaseException {
        return listAllLogs(orgId).stream()
                .filter(AttackLog::isBlocked)
                .map(AttackLog::getIpAddress)
                .distinct()
                .sorted()
                .collect(Collectors.toList());
    }

    public List<AttackLog> getTopHighRiskLogs(int orgId, int limit) throws DatabaseException {
        int safeLimit = Math.max(1, Math.min(limit, 100));
        return listAllLogs(orgId).stream()
                .filter(log -> log.getRiskScore() > 0)
                .sorted(Comparator.comparingInt(AttackLog::getRiskScore).reversed()
                        .thenComparing(Comparator.comparingLong(AttackLog::getId).reversed()))
                .limit(safeLimit)
                .collect(Collectors.toList());
    }

    public synchronized void replaceOfflineLogs(List<AttackLog> loadedLogs) {
        offlineLogs.clear();
        insertionOrder.clear();
        nextOfflineId = 1L;
        if (loadedLogs != null) {
            List<AttackLog> ordered = loadedLogs.stream()
                    .sorted(Comparator.comparingLong(AttackLog::getId))
                    .collect(Collectors.toList());
            for (AttackLog log : ordered) {
                offlineLogs.save(log);
                insertionOrder.addLast(log.getId());
                if (log.getId() >= nextOfflineId) {
                    nextOfflineId = log.getId() + 1L;
                }
            }
            while (insertionOrder.size() > MAX_MEMORY_LOGS) {
                Long oldest = insertionOrder.pollFirst();
                if (oldest != null) {
                    offlineLogs.deleteById(oldest);
                }
            }
        }
    }

    public synchronized List<AttackLog> getAllOfflineLogs() {
        return Collections.unmodifiableList(offlineLogs.findAll());
    }

    public synchronized long getTotalRecordedCounter() {
        return totalRecordedCounter;
    }
}
