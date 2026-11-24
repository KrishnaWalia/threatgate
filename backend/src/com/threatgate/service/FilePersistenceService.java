package com.threatgate.service;

import com.threatgate.model.AttackLog;
import com.threatgate.model.BlockedIp;
import com.threatgate.model.DashboardStats;
import com.threatgate.model.DetectionRule;
import com.threatgate.model.User;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StreamTokenizer;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class FilePersistenceService {
    private static final String AUDIT_MAGIC = "TGAUDIT1";
    private static final Set<String> VALID_RULE_CATEGORIES = Set.of("sqli", "xss", "path_traversal", "other");

    public void exportRulesToCsv(List<DetectionRule> rules, String filePath) throws IOException {
        exportCsv(rules, "id,org_id,category,pattern,weight,is_active,description,created_at", DetectionRule::toCsvRow, filePath);
    }

    public CsvImportResult<DetectionRule> importRulesFromCsv(String filePath) throws IOException {
        return importCsv(filePath, DetectionRule::fromCsvRow);
    }

    public void exportAttackLogsToCsv(List<AttackLog> logs, String filePath) throws IOException {
        exportCsv(
                logs,
                "id,org_id,ip_address,method,path,category,risk_score,action,matched_rule_id,user_agent,created_at",
                AttackLog::toCsvRow,
                filePath
        );
    }

    public CsvImportResult<AttackLog> importAttackLogsFromCsv(String filePath) throws IOException {
        return importCsv(filePath, AttackLog::fromCsvRow);
    }

    public void exportBlockedIpsToCsv(List<BlockedIp> blocks, String filePath) throws IOException {
        exportCsv(blocks, "id,org_id,ip_address,reason,blocked_at,expires_at", BlockedIp::toCsvRow, filePath);
    }

    public CsvImportResult<BlockedIp> importBlockedIpsFromCsv(String filePath) throws IOException {
        return importCsv(filePath, BlockedIp::fromCsvRow);
    }

    public void exportUsersToCsv(List<User> users, String filePath) throws IOException {
        exportCsv(users, "id,org_id,email,password_hash,role,created_at", User::toCsvRow, filePath);
    }

    public CsvImportResult<User> importUsersFromCsv(String filePath) throws IOException {
        return importCsv(filePath, User::fromCsvRow);
    }

    private <T> void exportCsv(
            List<T> items,
            String header,
            Function<T, String> serializer,
            String filePath) throws IOException {
        File target = new File(filePath);
        ensureParentExists(target);
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(target, StandardCharsets.UTF_8, false))) {
            writer.write(header);
            writer.newLine();
            if (items != null) {
                for (T item : items) {
                    writer.write(serializer.apply(item));
                    writer.newLine();
                }
            }
        }
    }

    private <T> CsvImportResult<T> importCsv(String filePath, Function<String, T> parser) throws IOException {
        File source = new File(filePath);
        if (!source.exists()) {
            return new CsvImportResult<>(Collections.emptyList(), 0);
        }
        List<T> parsed = new ArrayList<>();
        int skipped = 0;

        try (BufferedReader reader = new BufferedReader(new FileReader(source, StandardCharsets.UTF_8))) {
            String line;
            int lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                String trimmed = line.trim();
                if (trimmed.isEmpty()) {
                    continue;
                }
                if (lineNumber == 1 && (trimmed.startsWith("id,") || trimmed.startsWith("#"))) {
                    continue;
                }
                if (trimmed.startsWith("#")) {
                    continue;
                }
                try {
                    parsed.add(parser.apply(trimmed));
                } catch (RuntimeException e) {
                    skipped++;
                }
            }
        }
        return new CsvImportResult<>(parsed, skipped);
    }

    public void writeBinaryAuditSnapshot(
            DashboardStats stats,
            List<AttackLog> logs,
            String filePath) throws IOException {
        File target = new File(filePath);
        ensureParentExists(target);
        List<AttackLog> snapshotLogs = logs != null
                ? logs.subList(0, Math.min(logs.size(), 500))
                : Collections.emptyList();

        try (FileOutputStream output = new FileOutputStream(target)) {
            output.write(AUDIT_MAGIC.getBytes(StandardCharsets.UTF_8));
            writeLong(output, System.currentTimeMillis());
            writeLong(output, stats.getTotalRequests());
            writeLong(output, stats.getTotalBlocked());
            writeLong(output, stats.getTotalAllowed());
            writeLong(output, stats.getActiveBlockedIps());
            writeInt(output, snapshotLogs.size());
            for (AttackLog log : snapshotLogs) {
                writeLong(output, log.getId());
                writeUtfString(output, log.getIpAddress());
                writeUtfString(output, log.getMethod());
                writeUtfString(output, log.getPath());
                writeUtfString(output, log.getCategory());
                writeInt(output, log.getRiskScore());
                writeUtfString(output, log.getAction());
            }
        }
    }

    public AuditSnapshotSummary readBinaryAuditSnapshot(String filePath) throws IOException {
        File source = new File(filePath);
        try (FileInputStream input = new FileInputStream(source)) {
            byte[] magicBytes = readExactBytes(input, 8);
            String magic = new String(magicBytes, StandardCharsets.UTF_8);
            if (!AUDIT_MAGIC.equals(magic)) {
                throw new IOException("Invalid audit snapshot header.");
            }
            long createdAtMillis = readLong(input);
            long totalRequests = readLong(input);
            long totalBlocked = readLong(input);
            long totalAllowed = readLong(input);
            long activeBlockedIps = readLong(input);
            int logCount = readInt(input);
            List<String> previews = new ArrayList<>();
            for (int i = 0; i < logCount; i++) {
                long logId = readLong(input);
                String ip = readUtfString(input);
                String method = readUtfString(input);
                String path = readUtfString(input);
                String category = readUtfString(input);
                int riskScore = readInt(input);
                String action = readUtfString(input);
                previews.add(String.format("#%d %s %s %s [%s risk=%d -> %s]",
                        logId, ip, method, path, category, riskScore, action));
            }
            return new AuditSnapshotSummary(
                    createdAtMillis,
                    totalRequests,
                    totalBlocked,
                    totalAllowed,
                    activeBlockedIps,
                    previews
            );
        }
    }

    public long copyFileByteByByte(String sourcePath, String destinationPath) throws IOException {
        File source = new File(sourcePath);
        File destination = new File(destinationPath);
        ensureParentExists(destination);
        long totalBytes = 0L;
        byte[] buffer = new byte[4096];
        try (FileInputStream input = new FileInputStream(source);
             FileOutputStream output = new FileOutputStream(destination)) {
            int bytesRead;
            while ((bytesRead = input.read(buffer)) != -1) {
                output.write(buffer, 0, bytesRead);
                totalBytes += bytesRead;
            }
        }
        return totalBytes;
    }

    public TokenizedRuleParseResult parseTokenizedRulesFile(int orgId, String filePath) throws IOException {
        File source = new File(filePath);
        if (!source.exists()) {
            throw new IOException("Tokenized rules file not found: " + filePath);
        }
        List<DetectionRule> rules = new ArrayList<>();
        int skipped = 0;
        Timestamp now = new Timestamp(System.currentTimeMillis());

        try (FileReader reader = new FileReader(source, StandardCharsets.UTF_8)) {
            StreamTokenizer tokenizer = new StreamTokenizer(reader);
            tokenizer.resetSyntax();
            tokenizer.whitespaceChars(0, ' ');
            tokenizer.wordChars('a', 'z');
            tokenizer.wordChars('A', 'Z');
            tokenizer.wordChars('0', '9');
            tokenizer.wordChars('_', '_');
            tokenizer.wordChars('-', '-');
            tokenizer.parseNumbers();
            tokenizer.quoteChar('"');
            tokenizer.eolIsSignificant(true);

            while (true) {
                int token = tokenizer.nextToken();
                if (token == StreamTokenizer.TT_EOF) {
                    break;
                }
                if (token == StreamTokenizer.TT_EOL) {
                    continue;
                }
                if (token != StreamTokenizer.TT_WORD || !"RULE".equalsIgnoreCase(tokenizer.sval)) {
                    skipped++;
                    skipToEndOfLine(tokenizer);
                    continue;
                }

                int categoryToken = tokenizer.nextToken();
                if (categoryToken != StreamTokenizer.TT_WORD) {
                    skipped++;
                    skipToEndOfLine(tokenizer);
                    continue;
                }
                String category = tokenizer.sval.trim().toLowerCase();

                int weightToken = tokenizer.nextToken();
                if (weightToken != StreamTokenizer.TT_NUMBER) {
                    skipped++;
                    skipToEndOfLine(tokenizer);
                    continue;
                }
                int weight = (int) Math.round(tokenizer.nval);

                int patternToken = tokenizer.nextToken();
                if (patternToken != '"') {
                    skipped++;
                    skipToEndOfLine(tokenizer);
                    continue;
                }
                String pattern = tokenizer.sval;

                int descToken = tokenizer.nextToken();
                if (descToken != '"') {
                    skipped++;
                    skipToEndOfLine(tokenizer);
                    continue;
                }
                String description = tokenizer.sval;
                skipToEndOfLine(tokenizer);

                if (!VALID_RULE_CATEGORIES.contains(category) || weight < 1 || weight > 100 || pattern.isEmpty()) {
                    skipped++;
                    continue;
                }
                try {
                    Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
                    rules.add(new DetectionRule(0, orgId, category, pattern, weight, true, description, now));
                } catch (PatternSyntaxException e) {
                    skipped++;
                }
            }
        }
        return new TokenizedRuleParseResult(rules, skipped);
    }

    public void writeSampleTokenizedRulesFile(String filePath) throws IOException {
        File target = new File(filePath);
        ensureParentExists(target);
        try (FileWriter writer = new FileWriter(target, StandardCharsets.UTF_8, false)) {
            writer.write("RULE sqli 75 \"\\\\bexec(?:ute)?\\\\s*\\\\(\" \"Stored procedure execution probe\"\n");
            writer.write("RULE xss 65 \"<\\\\s*svg\\\\b[^>]*\\\\bonload\\\\s*=\" \"SVG onload XSS payload\"\n");
            writer.write("RULE path_traversal 70 \"\\\\.\\\\.%2f\" \"Encoded directory climb signature\"\n");
        }
    }

    private void skipToEndOfLine(StreamTokenizer tokenizer) throws IOException {
        while (tokenizer.ttype != StreamTokenizer.TT_EOL && tokenizer.ttype != StreamTokenizer.TT_EOF) {
            tokenizer.nextToken();
        }
    }

    private void ensureParentExists(File file) {
        File parent = file.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }
    }

    private void writeInt(FileOutputStream output, int value) throws IOException {
        output.write((value >>> 24) & 0xFF);
        output.write((value >>> 16) & 0xFF);
        output.write((value >>> 8) & 0xFF);
        output.write(value & 0xFF);
    }

    private void writeLong(FileOutputStream output, long value) throws IOException {
        for (int shift = 56; shift >= 0; shift -= 8) {
            output.write((int) ((value >>> shift) & 0xFF));
        }
    }

    private void writeUtfString(FileOutputStream output, String value) throws IOException {
        byte[] bytes = value != null ? value.getBytes(StandardCharsets.UTF_8) : new byte[0];
        writeInt(output, bytes.length);
        output.write(bytes);
    }

    private int readInt(FileInputStream input) throws IOException {
        byte[] b = readExactBytes(input, 4);
        return ((b[0] & 0xFF) << 24)
                | ((b[1] & 0xFF) << 16)
                | ((b[2] & 0xFF) << 8)
                | (b[3] & 0xFF);
    }

    private long readLong(FileInputStream input) throws IOException {
        byte[] b = readExactBytes(input, 8);
        long result = 0L;
        for (int i = 0; i < 8; i++) {
            result = (result << 8) | (b[i] & 0xFFL);
        }
        return result;
    }

    private String readUtfString(FileInputStream input) throws IOException {
        int length = readInt(input);
        if (length < 0 || length > 10_000_000) {
            throw new IOException("Corrupt UTF string length in binary snapshot: " + length);
        }
        byte[] bytes = readExactBytes(input, length);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private byte[] readExactBytes(FileInputStream input, int length) throws IOException {
        byte[] data = new byte[length];
        int offset = 0;
        while (offset < length) {
            int read = input.read(data, offset, length - offset);
            if (read == -1) {
                throw new EOFException("Unexpected end of binary audit snapshot.");
            }
            offset += read;
        }
        return data;
    }

    public static final class CsvImportResult<T> {
        private final List<T> items;
        private final int skippedCount;

        public CsvImportResult(List<T> items, int skippedCount) {
            this.items = Collections.unmodifiableList(new ArrayList<>(items));
            this.skippedCount = skippedCount;
        }

        public List<T> getItems() {
            return items;
        }

        public int getSkippedCount() {
            return skippedCount;
        }
    }

    public static final class TokenizedRuleParseResult {
        private final List<DetectionRule> rules;
        private final int skippedCount;

        public TokenizedRuleParseResult(List<DetectionRule> rules, int skippedCount) {
            this.rules = Collections.unmodifiableList(new ArrayList<>(rules));
            this.skippedCount = skippedCount;
        }

        public List<DetectionRule> getRules() {
            return rules;
        }

        public int getSkippedCount() {
            return skippedCount;
        }
    }

    public static final class AuditSnapshotSummary {
        private final long createdAtMillis;
        private final long totalRequests;
        private final long totalBlocked;
        private final long totalAllowed;
        private final long activeBlockedIps;
        private final List<String> logPreviews;

        public AuditSnapshotSummary(
                long createdAtMillis,
                long totalRequests,
                long totalBlocked,
                long totalAllowed,
                long activeBlockedIps,
                List<String> logPreviews) {
            this.createdAtMillis = createdAtMillis;
            this.totalRequests = totalRequests;
            this.totalBlocked = totalBlocked;
            this.totalAllowed = totalAllowed;
            this.activeBlockedIps = activeBlockedIps;
            this.logPreviews = Collections.unmodifiableList(new ArrayList<>(logPreviews));
        }

        public long getCreatedAtMillis() {
            return createdAtMillis;
        }

        public long getTotalRequests() {
            return totalRequests;
        }

        public long getTotalBlocked() {
            return totalBlocked;
        }

        public long getTotalAllowed() {
            return totalAllowed;
        }

        public long getActiveBlockedIps() {
            return activeBlockedIps;
        }

        public List<String> getLogPreviews() {
            return logPreviews;
        }
    }
}
