package com.threatgate.model;

import java.io.Serial;
import java.io.Serializable;

public class RuleMatch implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private final int ruleId;
    private final String category;
    private final int weight;
    private final String where;
    private final String description;

    public RuleMatch(int ruleId, String category, int weight, String where, String description) {
        this.ruleId = ruleId;
        this.category = category;
        this.weight = weight;
        this.where = where;
        this.description = description;
    }

    public int getRuleId() {
        return ruleId;
    }

    public String getCategory() {
        return category;
    }

    public int getWeight() {
        return weight;
    }

    public String getWhere() {
        return where;
    }

    public String getDescription() {
        return description;
    }

    @Override
    public String toString() {
        return String.format("RuleMatch [ruleId=%d, category='%s', weight=%d, where='%s']",
                ruleId, category, weight, where);
    }
}
