package com.threatgate.exception;

import java.io.Serial;

public class UnauthorizedRoleException extends Exception {
    @Serial
    private static final long serialVersionUID = 1L;

    private final String requiredRole;
    private final String actualRole;

    public UnauthorizedRoleException(String message) {
        super(message);
        this.requiredRole = "";
        this.actualRole = "";
    }

    public UnauthorizedRoleException(String requiredRole, String actualRole) {
        super(String.format("Forbidden: requires '%s' role, current role is '%s'.",
                requiredRole,
                actualRole != null ? actualRole : "none"));
        this.requiredRole = requiredRole;
        this.actualRole = actualRole != null ? actualRole : "none";
    }

    public String getRequiredRole() {
        return requiredRole;
    }

    public String getActualRole() {
        return actualRole;
    }
}
