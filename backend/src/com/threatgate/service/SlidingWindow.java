package com.threatgate.service;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class SlidingWindow {
    private final long windowMs;
    private final Map<String, List<Long>> hits = new LinkedHashMap<>();
    private final Object lock = new Object();

    public SlidingWindow(long windowMs) {
        this.windowMs = Math.max(1L, windowMs);
    }

    public int hit(String key) {
        return hit(key, System.currentTimeMillis());
    }

    public int hit(String key, long nowMillis) {
        long cutoff = nowMillis - windowMs;
        synchronized (lock) {
            List<Long> timestamps = hits.get(key);
            if (timestamps == null) {
                timestamps = new ArrayList<>();
                hits.put(key, timestamps);
            }
            int dropCount = 0;
            while (dropCount < timestamps.size() && timestamps.get(dropCount) <= cutoff) {
                dropCount++;
            }
            if (dropCount > 0) {
                timestamps.subList(0, dropCount).clear();
            }
            timestamps.add(nowMillis);
            return timestamps.size();
        }
    }

    public void reset(String key) {
        synchronized (lock) {
            hits.remove(key);
        }
    }

    public int sweep(long nowMillis) {
        long cutoff = nowMillis - windowMs;
        int removed = 0;
        synchronized (lock) {
            Iterator<Map.Entry<String, List<Long>>> iterator = hits.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<String, List<Long>> entry = iterator.next();
                List<Long> timestamps = entry.getValue();
                if (timestamps.isEmpty() || timestamps.get(timestamps.size() - 1) <= cutoff) {
                    iterator.remove();
                    removed++;
                }
            }
        }
        return removed;
    }

    public int getTrackedKeyCount() {
        synchronized (lock) {
            return hits.size();
        }
    }

    public long getWindowMs() {
        return windowMs;
    }
}
