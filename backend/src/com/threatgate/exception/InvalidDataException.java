package com.threatgate.exception;

import java.io.Serial;

public class InvalidDataException extends Exception {
    @Serial
    private static final long serialVersionUID = 1L;

    public InvalidDataException(String message) {
        super(message);
    }

    public InvalidDataException(String message, Throwable cause) {
        super(message, cause);
    }
}
