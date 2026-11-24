package com.threatgate.model;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.StringJoiner;

public final class CsvCodec {
    private CsvCodec() {
    }

    public static String escapeField(String value) {
        String safe = value != null ? value.replace("\"", "\"\"") : "";
        return "\"" + safe + "\"";
    }

    public static String joinFields(String... fields) {
        StringJoiner joiner = new StringJoiner(",");
        for (String field : fields) {
            joiner.add(field != null ? field : "");
        }
        return joiner.toString();
    }

    public static List<String> parseRow(String csvLine) {
        if (csvLine == null) {
            throw new IllegalArgumentException("CSV line cannot be null.");
        }
        List<String> tokens = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inQuotes = false;

        for (int i = 0; i < csvLine.length(); i++) {
            char ch = csvLine.charAt(i);
            if (ch == '"') {
                if (inQuotes && i + 1 < csvLine.length() && csvLine.charAt(i + 1) == '"') {
                    current.append('"');
                    i++;
                } else {
                    inQuotes = !inQuotes;
                }
            } else if (ch == ',' && !inQuotes) {
                tokens.add(current.toString());
                current.setLength(0);
            } else {
                current.append(ch);
            }
        }
        tokens.add(current.toString());
        return tokens;
    }

    public static String formatTimestampMillis(Timestamp timestamp) {
        return timestamp != null ? String.valueOf(timestamp.getTime()) : "";
    }

    public static Timestamp parseTimestampMillis(String raw) {
        if (raw == null || raw.trim().isEmpty()) {
            return null;
        }
        return new Timestamp(Long.parseLong(raw.trim()));
    }
}
