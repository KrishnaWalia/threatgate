package com.threatgate.model;

import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class InspectionResult implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private final int riskScore;
    private final String category;
    private final Integer matchedRuleId;
    private final boolean blocked;
    private final ArrayList<RuleMatch> matches;

    public InspectionResult(
            int riskScore,
            String category,
            Integer matchedRuleId,
            boolean blocked,
            List<RuleMatch> matches) {
        this.riskScore = riskScore;
        this.category = category != null ? category : "none";
        this.matchedRuleId = matchedRuleId;
        this.blocked = blocked;
        this.matches = matches != null ? new ArrayList<>(matches) : new ArrayList<>();
    }

    public int getRiskScore() {
        return riskScore;
    }

    public String getCategory() {
        return category;
    }

    public Integer getMatchedRuleId() {
        return matchedRuleId;
    }

    public boolean isBlocked() {
        return blocked;
    }

    public List<RuleMatch> getMatches() {
        return Collections.unmodifiableList(matches);
    }

    @Override
    public String toString() {
        return String.format("InspectionResult [riskScore=%d, category='%s', matchedRuleId=%s, blocked=%s, matches=%d]",
                riskScore, category, matchedRuleId, blocked, matches.size());
    }
}
