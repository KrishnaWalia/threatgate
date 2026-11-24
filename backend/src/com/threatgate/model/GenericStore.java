package com.threatgate.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public class GenericStore<T extends Identifiable<ID>, ID> implements DataRepository<T, ID> {
    private final Map<ID, T> storage = new LinkedHashMap<>();

    @Override
    public synchronized T save(T entity) {
        Objects.requireNonNull(entity, "Entity cannot be null.");
        Objects.requireNonNull(entity.getId(), "Entity ID cannot be null.");
        storage.put(entity.getId(), entity);
        return entity;
    }

    @Override
    public synchronized Optional<T> findById(ID id) {
        if (id == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(storage.get(id));
    }

    @Override
    public synchronized List<T> findAll() {
        return Collections.unmodifiableList(new ArrayList<>(storage.values()));
    }

    @Override
    public synchronized boolean deleteById(ID id) {
        if (id == null) {
            return false;
        }
        return storage.remove(id) != null;
    }

    @Override
    public synchronized int count() {
        return storage.size();
    }

    public synchronized void clear() {
        storage.clear();
    }

    public synchronized List<T> findMatching(Predicate<? super T> predicate) {
        Objects.requireNonNull(predicate, "Predicate cannot be null.");
        return storage.values().stream()
                .filter(predicate)
                .collect(Collectors.toList());
    }

    public synchronized <R> List<R> filterAndMap(
            Predicate<? super T> predicate,
            Function<? super T, ? extends R> mapper) {
        Objects.requireNonNull(predicate, "Predicate cannot be null.");
        Objects.requireNonNull(mapper, "Mapper cannot be null.");
        return storage.values().stream()
                .filter(predicate)
                .map(mapper)
                .collect(Collectors.toList());
    }

    public synchronized void copyTo(List<? super T> destination) {
        Objects.requireNonNull(destination, "Destination list cannot be null.");
        destination.addAll(storage.values());
    }

    public synchronized void saveAll(List<? extends T> items) {
        Objects.requireNonNull(items, "Items list cannot be null.");
        for (T item : items) {
            save(item);
        }
    }

    public static int countAll(List<? extends Identifiable<?>> items) {
        return items != null ? items.size() : 0;
    }
}
