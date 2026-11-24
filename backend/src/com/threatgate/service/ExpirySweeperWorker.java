package com.threatgate.service;

import com.threatgate.exception.DatabaseException;

public final class ExpirySweeperWorker extends Thread {
    private final BruteForceService bruteForceService;
    private final long intervalMs;
    private volatile boolean running = true;
    private int sweepCount = 0;
    private int totalPurged = 0;

    public ExpirySweeperWorker(String name, BruteForceService bruteForceService, long intervalMs) {
        super(name);
        this.bruteForceService = bruteForceService;
        this.intervalMs = Math.max(50L, intervalMs);
        setDaemon(true);
        setPriority(Thread.MIN_PRIORITY);
    }

    @Override
    public void run() {
        try {
            while (running && !isInterrupted()) {
                Thread.sleep(intervalMs);
                if (!running || isInterrupted()) {
                    break;
                }
                try {
                    int purged = bruteForceService.purgeExpired();
                    recordSweep(purged);
                } catch (DatabaseException ignored) {
                }
            }
        } catch (InterruptedException e) {
            interrupt();
        } finally {
            running = false;
        }
    }

    private synchronized void recordSweep(int purged) {
        sweepCount++;
        totalPurged += purged;
    }

    public void stopWorker() {
        this.running = false;
        interrupt();
    }

    public synchronized int getSweepCount() {
        return sweepCount;
    }

    public synchronized int getTotalPurged() {
        return totalPurged;
    }
}
