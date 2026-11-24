package com.threatgate.model;

import java.util.List;
import java.util.Optional;

public interface DataRepository<T extends Identifiable<ID>, ID> {
    T save(T entity);

    Optional<T> findById(ID id);

    List<T> findAll();

    boolean deleteById(ID id);

    int count();
}
