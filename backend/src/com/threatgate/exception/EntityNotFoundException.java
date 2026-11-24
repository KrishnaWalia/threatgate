package com.threatgate.exception;

import java.io.Serial;

public class EntityNotFoundException extends Exception {
    @Serial
    private static final long serialVersionUID = 1L;

    private final String entityType;
    private final String identifier;

    public EntityNotFoundException(String message) {
        super(message);
        this.entityType = "";
        this.identifier = "";
    }

    public EntityNotFoundException(String entityType, String identifier) {
        super(String.format("%s '%s' not found.", entityType, identifier));
        this.entityType = entityType;
        this.identifier = identifier;
    }

    public String getEntityType() {
        return entityType;
    }

    public String getIdentifier() {
        return identifier;
    }
}
