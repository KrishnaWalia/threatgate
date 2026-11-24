package com.threatgate.model;

import java.io.Serial;
import java.io.Serializable;

public class CategoryCount implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private final String category;
    private final long count;

    public CategoryCount(String category, long count) {
        this.category = category != null ? category : "none";
        this.count = count;
    }

    public String getCategory() {
        return category;
    }

    public long getCount() {
        return count;
    }

    @Override
    public String toString() {
        return String.format("CategoryCount [category='%s', count=%d]", category, count);
    }
}
