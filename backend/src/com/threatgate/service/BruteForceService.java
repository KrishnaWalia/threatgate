package com.threatgate.service;

import com.threatgate.db.BlockedIpJdbcDao;
import com.threatgate.exception.DatabaseException;
import com.threatgate.exception.EntityNotFoundException;
import com.threatgate.exception.InvalidDataException;
import com.threatgate.exception.UnauthorizedRoleException;
import com.threatgate.model.BlockedIp;
import com.threatgate.model.GenericStore;
import com.threatgate.model.User;
import java.sql.Timestamp;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class BruteForceService {
    private static final Pattern LOGIN_PATH_PATTERN =
            Pattern.compile("/(login|signin|sign-in|auth)\\b", Pattern.CASE_INSENSITIVE);

    private final SlidingWindow failedLogins;
    private final SlidingWindow requestRate;
    private final SlidingWindow attackStrikes;
    private final int loginFailMax;
    private final int rateLimitMax;
    private final int attackStrikeMax;
    private final long blockDurationMs;

    private final GenericStore<BlockedIp, Integer> offlineBlocks = new GenericStore<>();
    private final BlockedIpJdbcDao blockedIpJdbcDao;
    private final AuthService authService;
    private volatile boolean useDatabase;
    private int nextOfflineId = 1;

    public BruteForceService(
            BlockedIpJdbcDao blockedIpJdbcDao,
            AuthService authService,
            boolean useDatabase,
            int loginFailMax,
            long loginFailWindowMs,
            int rateLimitMax,
            long rateLimitWindowMs,
            int attackStrikeMax,
            long attackStrikeWindowMs,
            long blockDurationMs) {
        this.blockedIpJdbcDao = blockedIpJdbcDao;
        this.authService = authService;
        this.useDatabase = useDatabase;
        this.loginFailMax = loginFailMax;
        this.rateLimitMax = rateLimitMax;
        this.attackStrikeMax = attackStrikeMax;
        this.blockDurationMs = blockDurationMs;
        this.failedLogins = new SlidingWindow(loginFailWindowMs);
        this.requestRate = new SlidingWindow(rateLimitWindowMs);
        this.attackStrikes = new SlidingWindow(attackStrikeWindowMs);
    }

    public synchronized void setUseDatabase(boolean useDatabase) {
        this.useDatabase = useDatabase;
    }

    public boolean isLoginPath(String url) {
        if (url == null || url.isEmpty()) {
            return false;
        }
        int qIdx = url.indexOf('?');
        String pathPart = qIdx == -1 ? url : url.substring(0, qIdx);
        return LOGIN_PATH_PATTERN.matcher(pathPart).find();
    }

    public synchronized Optional<BlockedIp> findActiveBlock(int orgId, String ipAddress) throws DatabaseException {
        if (useDatabase && blockedIpJdbcDao != null) {
            return blockedIpJdbcDao.findActiveByOrgAndIp(orgId, ipAddress);
        }
        long now = System.currentTimeMillis();
        Optional<BlockedIp> match = offlineBlocks.findAll().stream()
                .filter(block -> block.getOrgId() == orgId && block.getIpAddress().equals(ipAddress))
                .findFirst();
        if (match.isEmpty()) {
            return Optional.empty();
        }
        BlockedIp block = match.get();
        if (!block.isActiveAt(now)) {
            offlineBlocks.deleteById(block.getId());
            return Optional.empty();
        }
        return Optional.of(block);
    }

    public Optional<BlockedIp> trackRequest(int orgId, String ipAddress) throws DatabaseException {
        int count = requestRate.hit(keyOf(orgId, ipAddress));
        if (count > rateLimitMax) {
            String reason = String.format(
                    "Rate limit exceeded (%d requests in %ds)",
                    count,
                    requestRate.getWindowMs() / 1000L
            );
            return Optional.of(blockIp(orgId, ipAddress, reason, blockDurationMs));
        }
        return Optional.empty();
    }

    public Optional<BlockedIp> trackAttack(int orgId, String ipAddress) throws DatabaseException {
        int count = attackStrikes.hit(keyOf(orgId, ipAddress));
        if (count >= attackStrikeMax) {
            String reason = String.format(
                    "Repeated attacks (%d malicious requests in %ds)",
                    count,
                    attackStrikes.getWindowMs() / 1000L
            );
            return Optional.of(blockIp(orgId, ipAddress, reason, blockDurationMs));
        }
        return Optional.empty();
    }

    public Optional<BlockedIp> trackFailedLogin(int orgId, String ipAddress) throws DatabaseException {
        int count = failedLogins.hit(keyOf(orgId, ipAddress));
        if (count >= loginFailMax) {
            String reason = String.format(
                    "Brute force: %d failed logins in %ds",
                    count,
                    failedLogins.getWindowMs() / 1000L
            );
            return Optional.of(blockIp(orgId, ipAddress, reason, blockDurationMs));
        }
        return Optional.empty();
    }

    public void clearFailedLogins(int orgId, String ipAddress) {
        failedLogins.reset(keyOf(orgId, ipAddress));
    }

    public void clearAllWindows(int orgId, String ipAddress) {
        String key = keyOf(orgId, ipAddress);
        failedLogins.reset(key);
        requestRate.reset(key);
        attackStrikes.reset(key);
    }

    public synchronized BlockedIp blockIp(int orgId, String ipAddress, String reason, Long durationMs)
            throws DatabaseException {
        long now = System.currentTimeMillis();
        Timestamp blockedAt = new Timestamp(now);
        Timestamp expiresAt = durationMs != null && durationMs > 0
                ? new Timestamp(now + durationMs)
                : null;
        BlockedIp candidate = new BlockedIp(0, orgId, ipAddress, reason, blockedAt, expiresAt);

        BlockedIp saved;
        if (useDatabase && blockedIpJdbcDao != null) {
            saved = blockedIpJdbcDao.upsertBlock(candidate);
        } else {
            List<BlockedIp> staleForIp = offlineBlocks.findMatching(
                    b -> b.getOrgId() == orgId && b.getIpAddress().equals(ipAddress)
            );
            for (BlockedIp stale : staleForIp) {
                offlineBlocks.deleteById(stale.getId());
            }
            candidate.setId(nextOfflineId++);
            saved = offlineBlocks.save(candidate);
        }
        clearAllWindows(orgId, ipAddress);
        return saved;
    }

    public BlockedIp manualBlockIp(User actor, String ipAddress, String reason, Long durationMs)
            throws UnauthorizedRoleException, InvalidDataException, DatabaseException {
        authService.requireRole(actor, "admin");
        if (ipAddress == null || ipAddress.trim().isEmpty()) {
            throw new InvalidDataException("IP address cannot be empty.");
        }
        String effectiveReason = reason != null && !reason.trim().isEmpty()
                ? reason.trim()
                : "Manual admin block";
        return blockIp(actor.getOrgId(), ipAddress.trim(), effectiveReason, durationMs);
    }

    public List<BlockedIp> listBlockedIps(User actor) throws UnauthorizedRoleException, DatabaseException {
        authService.requireRole(actor, "admin");
        return listActiveBlockedIpsInternal(actor.getOrgId());
    }

    public synchronized List<BlockedIp> listActiveBlockedIpsInternal(int orgId) throws DatabaseException {
        if (useDatabase && blockedIpJdbcDao != null) {
            return blockedIpJdbcDao.findActiveByOrg(orgId);
        }
        long now = System.currentTimeMillis();
        return offlineBlocks.findAll().stream()
                .filter(block -> block.getOrgId() == orgId && block.isActiveAt(now))
                .sorted(Comparator.comparing(BlockedIp::getBlockedAt).reversed())
                .collect(Collectors.toList());
    }

    public long countActiveBlockedIps(int orgId) throws DatabaseException {
        return listActiveBlockedIpsInternal(orgId).size();
    }

    public synchronized BlockedIp unblockIp(User actor, int blockId)
            throws UnauthorizedRoleException, EntityNotFoundException, DatabaseException {
        authService.requireRole(actor, "admin");
        Optional<BlockedIp> removedOpt;
        if (useDatabase && blockedIpJdbcDao != null) {
            removedOpt = blockedIpJdbcDao.deleteById(actor.getOrgId(), blockId);
        } else {
            removedOpt = offlineBlocks.findById(blockId)
                    .filter(block -> block.getOrgId() == actor.getOrgId());
            if (removedOpt.isPresent()) {
                offlineBlocks.deleteById(blockId);
            }
        }
        if (removedOpt.isEmpty()) {
            throw new EntityNotFoundException("Blocked IP", String.valueOf(blockId));
        }
        BlockedIp removed = removedOpt.get();
        clearAllWindows(actor.getOrgId(), removed.getIpAddress());
        return removed;
    }

    public synchronized int purgeExpired() throws DatabaseException {
        long now = System.currentTimeMillis();
        failedLogins.sweep(now);
        requestRate.sweep(now);
        attackStrikes.sweep(now);

        if (useDatabase && blockedIpJdbcDao != null) {
            return blockedIpJdbcDao.purgeExpired();
        }
        List<BlockedIp> expired = offlineBlocks.findMatching(block -> !block.isActiveAt(now));
        for (BlockedIp block : expired) {
            offlineBlocks.deleteById(block.getId());
        }
        return expired.size();
    }

    public synchronized void replaceOfflineBlocks(List<BlockedIp> loadedBlocks) {
        offlineBlocks.clear();
        nextOfflineId = 1;
        if (loadedBlocks != null) {
            for (BlockedIp block : loadedBlocks) {
                offlineBlocks.save(block);
                if (block.getId() >= nextOfflineId) {
                    nextOfflineId = block.getId() + 1;
                }
            }
        }
    }

    public synchronized List<BlockedIp> getAllOfflineBlocks() {
        return offlineBlocks.findAll();
    }

    public int getLoginFailMax() {
        return loginFailMax;
    }

    public int getRateLimitMax() {
        return rateLimitMax;
    }

    public int getAttackStrikeMax() {
        return attackStrikeMax;
    }

    public long getBlockDurationMs() {
        return blockDurationMs;
    }

    private String keyOf(int orgId, String ipAddress) {
        return orgId + ":" + ipAddress;
    }
}
