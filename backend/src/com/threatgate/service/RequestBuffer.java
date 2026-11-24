package com.threatgate.service;

import java.util.LinkedList;

public class RequestBuffer<T> {
    private final LinkedList<T> queue = new LinkedList<>();
    private final int capacity;
    private boolean closed;

    public RequestBuffer(int capacity) {
        this.capacity = Math.max(1, capacity);
        this.closed = false;
    }

    public synchronized void produce(T item) throws InterruptedException {
        while (queue.size() >= capacity && !closed) {
            wait();
        }
        if (closed) {
            return;
        }
        queue.addLast(item);
        notifyAll();
    }

    public synchronized T consume() throws InterruptedException {
        while (queue.isEmpty() && !closed) {
            wait();
        }
        if (queue.isEmpty()) {
            return null;
        }
        T item = queue.removeFirst();
        notifyAll();
        return item;
    }

    public synchronized void close() {
        this.closed = true;
        notifyAll();
    }

    public synchronized void reopen() {
        this.closed = false;
        notifyAll();
    }

    public synchronized int size() {
        return queue.size();
    }

    public synchronized boolean isClosed() {
        return closed;
    }

    public int getCapacity() {
        return capacity;
    }
}
