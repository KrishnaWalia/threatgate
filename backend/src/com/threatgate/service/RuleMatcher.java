package com.threatgate.service;

import com.threatgate.model.DetectionRule;

@FunctionalInterface
public interface RuleMatcher {
    boolean matches(DetectionRule rule, String normalizedText);
}
