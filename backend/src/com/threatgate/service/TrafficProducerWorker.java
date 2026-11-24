package com.threatgate.service;

import com.threatgate.model.InspectionRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class TrafficProducerWorker implements Runnable {
    private static final String[] SAMPLE_IPS = {
            "203.0.113.7", "198.51.100.23", "192.0.2.44", "203.0.113.99", "10.0.0.14"
    };

    private final RequestBuffer<InspectionRequest> buffer;
    private final int orgId;
    private final long delayMs;
    private final int maxRequests;
    private final List<InspectionRequest> fixedBatch;
    private final Random random = new Random();
    private volatile boolean running = true;
    private int producedCount = 0;

    public TrafficProducerWorker(
            RequestBuffer<InspectionRequest> buffer,
            int orgId,
            long delayMs,
            int maxRequests) {
        this.buffer = buffer;
        this.orgId = orgId;
        this.delayMs = Math.max(0L, delayMs);
        this.maxRequests = maxRequests;
        this.fixedBatch = null;
    }

    public TrafficProducerWorker(
            RequestBuffer<InspectionRequest> buffer,
            List<InspectionRequest> fixedBatch,
            long delayMs) {
        this.buffer = buffer;
        this.orgId = 1;
        this.delayMs = Math.max(0L, delayMs);
        this.fixedBatch = new ArrayList<>(fixedBatch);
        this.maxRequests = this.fixedBatch.size();
    }

    @Override
    public void run() {
        try {
            if (fixedBatch != null) {
                for (InspectionRequest request : fixedBatch) {
                    if (!running || Thread.currentThread().isInterrupted()) {
                        break;
                    }
                    buffer.produce(request);
                    incrementProduced();
                    if (delayMs > 0) {
                        Thread.sleep(delayMs);
                    }
                }
            } else {
                while (running && !Thread.currentThread().isInterrupted()) {
                    if (maxRequests > 0 && getProducedCount() >= maxRequests) {
                        break;
                    }
                    buffer.produce(buildSampleRequest());
                    incrementProduced();
                    if (delayMs > 0) {
                        Thread.sleep(delayMs);
                    }
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            running = false;
        }
    }

    public void stopWorker() {
        this.running = false;
    }

    public synchronized int getProducedCount() {
        return producedCount;
    }

    private synchronized void incrementProduced() {
        producedCount++;
    }

    private InspectionRequest buildSampleRequest() {
        String ip = SAMPLE_IPS[random.nextInt(SAMPLE_IPS.length)];
        int choice = random.nextInt(8);
        return switch (choice) {
            case 0 -> new InspectionRequest(orgId, ip, "GET", "/api/products?id=1", "", "demo-simulator/1.0");
            case 1 -> new InspectionRequest(orgId, ip, "GET", "/api/users?id=1' OR '1'='1", "", "demo-simulator/1.0");
            case 2 -> new InspectionRequest(orgId, ip, "POST", "/comments", "comment=<script>alert(1)</script>", "demo-simulator/1.0");
            case 3 -> new InspectionRequest(orgId, ip, "GET", "/files?name=../../../../etc/passwd", "", "demo-simulator/1.0");
            case 4 -> new InspectionRequest(orgId, ip, "POST", "/login", "email=test@org.com", "demo-simulator/1.0", "", "", 401);
            case 5 -> new InspectionRequest(orgId, ip, "GET", "/search?q=O'Brien", "", "demo-simulator/1.0");
            case 6 -> new InspectionRequest(orgId, ip, "GET", "/files?name=%252e%252e%252fetc/passwd", "", "demo-simulator/1.0");
            default -> new InspectionRequest(orgId, ip, "GET", "/search?q=hello", "", "demo-simulator/1.0");
        };
    }
}
