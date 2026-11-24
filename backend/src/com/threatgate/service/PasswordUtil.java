package com.threatgate.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public final class PasswordUtil {
    private static final int SALT_BYTES = 16;
    private static final SecureRandom RANDOM = new SecureRandom();

    private PasswordUtil() {
    }

    public static String hashPassword(String rawPassword) {
        if (rawPassword == null) {
            throw new IllegalArgumentException("Password cannot be null.");
        }
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        byte[] digest = sha256(salt, rawPassword.getBytes(StandardCharsets.UTF_8));
        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(salt) + ":" + encoder.encodeToString(digest);
    }

    public static boolean verifyPassword(String rawPassword, String storedHash) {
        if (rawPassword == null || storedHash == null) {
            return false;
        }
        int sep = storedHash.indexOf(':');
        if (sep <= 0 || sep >= storedHash.length() - 1) {
            return false;
        }
        try {
            Base64.Decoder decoder = Base64.getDecoder();
            byte[] salt = decoder.decode(storedHash.substring(0, sep));
            byte[] expectedDigest = decoder.decode(storedHash.substring(sep + 1));
            byte[] candidateDigest = sha256(salt, rawPassword.getBytes(StandardCharsets.UTF_8));
            return MessageDigest.isEqual(expectedDigest, candidateDigest);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static byte[] sha256(byte[] salt, byte[] passwordBytes) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(salt);
            return digest.digest(passwordBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm unavailable.", e);
        }
    }
}
