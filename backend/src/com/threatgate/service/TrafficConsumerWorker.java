package com.threatgate.service;

import com.threatgate.model.InspectionRequest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class TrafficConsumerWorker extends Thread {
    private final RequestBuffer<InspectionRequest> buffer;
    private final TrafficPipelineService pipelineService;
    private final List<TrafficPipelineService.WafDecision> decisions = new ArrayList<>();
    private final boolean recordDecisions;
    private volatile boolean running = true;
    private int consumedCount = 0;

    public TrafficConsumerWorker(
            String name,
            RequestBuffer<InspectionRequest> buffer,
            TrafficPipelineService pipelineService,
            int priority,
            boolean recordDecisions) {
        super(name);
        this.buffer = buffer;
        this.pipelineService = pipelineService;
        this.recordDecisions = recordDecisions;
        setPriority(Math.max(Thread.MIN_PRIORITY, Math.min(Thread.MAX_PRIORITY, priority)));
    }

    @Override
    public void run() {
        try {
            while (running && !isInterrupted()) {
                InspectionRequest request = buffer.consume();
                if (request == null) {
                    break;
                }
                TrafficPipelineService.WafDecision decision = pipelineService.processSingleRequest(request);
                recordProcessed(decision);
            }
        } catch (InterruptedException e) {
            interrupt();
        } finally {
            running = false;
        }
    }

    private synchronized void recordProcessed(TrafficPipelineService.WafDecision decision) {
        consumedCount++;
        if (recordDecisions && decision != null) {
            decisions.add(decision);
        }
    }

    public void stopWorker() {
        this.running = false;
        interrupt();
    }

    public synchronized int getConsumedCount() {
        return consumedCount;
    }

    public synchronized List<TrafficPipelineService.WafDecision> getDecisions() {
        return Collections.unmodifiableList(new ArrayList<>(decisions));
    }
}
