package com.threatgate.service;

import com.threatgate.model.InspectionRequest;

@FunctionalInterface
public interface RequestValidator {
    boolean validate(InspectionRequest request);
}
