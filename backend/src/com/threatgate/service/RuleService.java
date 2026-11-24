package com.threatgate.service;

import com.threatgate.db.RuleJdbcDao;
import com.threatgate.exception.DatabaseException;
import com.threatgate.exception.EntityNotFoundException;
import com.threatgate.exception.InvalidDataException;
import com.threatgate.exception.UnauthorizedRoleException;
import com.threatgate.model.DetectionRule;
import com.threatgate.model.GenericStore;
import com.threatgate.model.User;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

public class RuleService {
    private static final Set<String> VALID_CATEGORIES = Set.of("sqli", "xss", "path_traversal", "other");

    private final GenericStore<DetectionRule, Integer> ruleStore = new GenericStore<>();
    private final Map<Integer, Pattern> compiledPatterns = new LinkedHashMap<>();
    private final RuleJdbcDao ruleJdbcDao;
    private final AuthService authService;
    private volatile boolean useDatabase;
    private int nextOfflineId = 1;

    public RuleService(RuleJdbcDao ruleJdbcDao, AuthService authService, boolean useDatabase) {
        this.ruleJdbcDao = ruleJdbcDao;
        this.authService = authService;
        this.useDatabase = useDatabase;
        initRules(createDefaultRules(1));
    }

    public static List<DetectionRule> createDefaultRules(int orgId) {
        Timestamp now = new Timestamp(System.currentTimeMillis());
        List<DetectionRule> defaults = new ArrayList<>();
        defaults.add(new DetectionRule(1, orgId, "sqli", "\\bunion\\b[\\s\\S]{0,40}\\bselect\\b", 80, true,
                "UNION SELECT - appends attacker query to read other tables", now));
        defaults.add(new DetectionRule(2, orgId, "sqli", "['\"]\\s*(?:or|and)\\s+['\"]?\\w+['\"]?\\s*(?:=|like)\\s*['\"]?\\w+", 75, true,
                "Quote-based tautology - ' OR '1'='1 (breaks out of a string, forces TRUE)", now));
        defaults.add(new DetectionRule(3, orgId, "sqli", "\\b(?:or|and)\\s+\\d+\\s*=\\s*\\d+", 70, true,
                "Numeric tautology - OR 1=1 (injection into a numeric context)", now));
        defaults.add(new DetectionRule(4, orgId, "sqli", "['\"]\\s*(?:--|#|/\\*)", 60, true,
                "Quote followed by SQL comment - admin'-- (cuts off the rest of the query)", now));
        defaults.add(new DetectionRule(5, orgId, "sqli",
                ";\\s*(?:drop\\s+(?:table|database)|truncate\\s+table|delete\\s+from|insert\\s+into|update\\s+\\w+\\s+set|alter\\s+table|create\\s+(?:table|user))",
                85, true, "Stacked query - ; DROP TABLE ... (runs a second, destructive statement)", now));
        defaults.add(new DetectionRule(6, orgId, "sqli",
                "\\b(?:sleep\\s*\\(\\s*\\d+|benchmark\\s*\\(|pg_sleep\\s*\\(|waitfor\\s+delay)", 80, true,
                "Time-based blind SQLi - SLEEP()/BENCHMARK()/WAITFOR DELAY", now));
        defaults.add(new DetectionRule(7, orgId, "sqli",
                "\\b(?:information_schema|sqlite_master|pg_catalog|mysql\\.user)\\b", 70, true,
                "Schema reconnaissance - reading the database catalog", now));
        defaults.add(new DetectionRule(8, orgId, "sqli",
                "\\b(?:extractvalue|updatexml|load_file)\\s*\\(|into\\s+(?:out|dump)file", 75, true,
                "Error-based / file-access SQL functions", now));
        defaults.add(new DetectionRule(9, orgId, "sqli", "\\bselect\\b[\\s\\S]{1,60}\\bfrom\\b", 40, true,
                "Weak signal - SELECT ... FROM in user input (blocks only with another match)", now));

        defaults.add(new DetectionRule(10, orgId, "xss", "<\\s*script\\b", 80, true,
                "<script> tag injection", now));
        defaults.add(new DetectionRule(11, orgId, "xss",
                "\\bon(?:error|load|click|mouseover|mouseenter|focus|blur|toggle|begin|start|animationstart|pointerover)\\s*=",
                65, true, "Inline event handler - onerror=, onload=, onclick= ...", now));
        defaults.add(new DetectionRule(12, orgId, "xss", "\\b(?:javascript|vbscript)\\s*:", 70, true,
                "javascript: / vbscript: URL scheme", now));
        defaults.add(new DetectionRule(13, orgId, "xss", "<\\s*(?:iframe|object|embed)\\b", 60, true,
                "<iframe>/<object>/<embed> injection", now));
        defaults.add(new DetectionRule(14, orgId, "xss", "data\\s*:\\s*text/html", 60, true,
                "data:text/html URL (inline HTML document)", now));
        defaults.add(new DetectionRule(15, orgId, "xss", "document\\s*\\.\\s*(?:cookie|write|location)", 60, true,
                "Cookie theft / DOM manipulation - document.cookie, .write, .location", now));
        defaults.add(new DetectionRule(16, orgId, "xss", "\\b(?:alert|prompt|confirm|eval)\\s*\\(", 40, true,
                "JS probe functions - alert()/prompt()/eval() (weak alone)", now));

        defaults.add(new DetectionRule(17, orgId, "path_traversal", "\\.\\.[\\\\/]", 55, true,
                "../ or ..\\ - directory climb", now));
        defaults.add(new DetectionRule(18, orgId, "path_traversal", "(?:\\.\\.[\\\\/]){2,}", 80, true,
                "Repeated ../../ - deep traversal toward the filesystem root", now));
        defaults.add(new DetectionRule(19, orgId, "path_traversal",
                "(?:^|[\\\\/=])(?:etc[\\\\/](?:passwd|shadow|hosts|group)|proc[\\\\/]self[\\\\/]\\w+|boot\\.ini|windows[\\\\/](?:win\\.ini|system32)|var[\\\\/]log[\\\\/])",
                85, true, "Well-known sensitive files - /etc/passwd, win.ini, /proc/self/...", now));
        defaults.add(new DetectionRule(20, orgId, "path_traversal",
                "[\\\\/]\\.(?:env|git|svn|htaccess|htpasswd|ssh|aws)(?:[\\\\/\\s?]|$)", 70, true,
                "Hidden config/credential files - /.env, /.git/, /.ssh/", now));
        defaults.add(new DetectionRule(21, orgId, "path_traversal", "\\x00", 55, true,
                "Null byte - used to truncate file extensions (file.php%00.jpg)", now));
        defaults.add(new DetectionRule(22, orgId, "path_traversal", "\\b(?:file|php|zip|expect|gopher|phar)://", 60, true,
                "File/protocol wrapper - file://, php://, expect:// (LFI/SSRF)", now));
        return defaults;
    }

    public synchronized void setUseDatabase(boolean useDatabase) {
        this.useDatabase = useDatabase;
    }

    public synchronized void seedDefaultRules(int orgId) {
        replaceRules(createDefaultRules(orgId));
    }

    public synchronized void loadFromDatabase(int orgId) throws DatabaseException {
        if (!useDatabase || ruleJdbcDao == null) {
            return;
        }
        List<DetectionRule> loaded = ruleJdbcDao.findAllByOrg(orgId);
        if (!loaded.isEmpty()) {
            replaceRules(loaded);
        }
    }

    public synchronized void replaceRules(List<DetectionRule> rules) {
        initRules(rules);
    }

    private void initRules(List<DetectionRule> rules) {
        ruleStore.clear();
        nextOfflineId = 1;
        if (rules != null) {
            for (DetectionRule rule : rules) {
                ruleStore.save(rule);
                if (rule.getId() >= nextOfflineId) {
                    nextOfflineId = rule.getId() + 1;
                }
            }
        }
        recompilePatterns();
    }

    private void recompilePatterns() {
        compiledPatterns.clear();
        for (DetectionRule rule : ruleStore.findAll()) {
            if (!rule.isActive()) {
                continue;
            }
            try {
                compiledPatterns.put(rule.getId(), Pattern.compile(rule.getPattern(), Pattern.CASE_INSENSITIVE));
            } catch (PatternSyntaxException ignored) {
            }
        }
    }

    public synchronized List<DetectionRule> listRules(int orgId) {
        return ruleStore.findAll().stream()
                .filter(rule -> rule.getOrgId() == orgId)
                .sorted(Comparator.comparingInt(DetectionRule::getId))
                .collect(Collectors.toList());
    }

    public synchronized List<DetectionRule> getActiveRules(int orgId) {
        return ruleStore.findAll().stream()
                .filter(rule -> rule.getOrgId() == orgId && rule.isActive())
                .sorted(Comparator.comparingInt(DetectionRule::getId))
                .collect(Collectors.toList());
    }

    public synchronized List<DetectionRule> filterRulesByCategory(int orgId, String category) {
        String normalized = category != null ? category.trim().toLowerCase() : "";
        return ruleStore.findAll().stream()
                .filter(rule -> rule.getOrgId() == orgId && rule.getCategory().equalsIgnoreCase(normalized))
                .sorted(Comparator.comparingInt(DetectionRule::getId))
                .collect(Collectors.toList());
    }

    public synchronized Map<Integer, Pattern> getCompiledPatternsSnapshot() {
        return Collections.unmodifiableMap(new LinkedHashMap<>(compiledPatterns));
    }

    public synchronized DetectionRule findById(int orgId, int ruleId) throws EntityNotFoundException {
        Optional<DetectionRule> found = ruleStore.findById(ruleId)
                .filter(rule -> rule.getOrgId() == orgId);
        if (found.isEmpty()) {
            throw new EntityNotFoundException("Rule", String.valueOf(ruleId));
        }
        return found.get();
    }

    public synchronized DetectionRule updateRule(User actor, int ruleId, Boolean active, Integer weight)
            throws UnauthorizedRoleException, EntityNotFoundException, InvalidDataException, DatabaseException {
        authService.requireRole(actor, "admin");
        DetectionRule existing = findById(actor.getOrgId(), ruleId);
        boolean nextActive = active != null ? active : existing.isActive();
        int nextWeight = existing.getWeight();
        if (weight != null) {
            if (weight < 1 || weight > 100) {
                throw new InvalidDataException("Rule weight must be between 1 and 100.");
            }
            nextWeight = weight;
        }
        if (useDatabase && ruleJdbcDao != null) {
            ruleJdbcDao.update(actor.getOrgId(), ruleId, nextActive, nextWeight);
        }
        existing.setActive(nextActive);
        existing.setWeight(nextWeight);
        ruleStore.save(existing);
        recompilePatterns();
        return existing;
    }

    public synchronized DetectionRule addRule(
            User actor,
            String category,
            String pattern,
            int weight,
            String description)
            throws UnauthorizedRoleException, InvalidDataException, DatabaseException {
        authService.requireRole(actor, "admin");
        String normalizedCategory = category != null ? category.trim().toLowerCase() : "";
        if (!VALID_CATEGORIES.contains(normalizedCategory)) {
            throw new InvalidDataException("Category must be one of: sqli, xss, path_traversal, other.");
        }
        if (pattern == null || pattern.trim().isEmpty()) {
            throw new InvalidDataException("Regex pattern cannot be empty.");
        }
        try {
            Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
        } catch (PatternSyntaxException e) {
            throw new InvalidDataException("Invalid regex pattern: " + e.getMessage(), e);
        }
        if (weight < 1 || weight > 100) {
            throw new InvalidDataException("Weight must be between 1 and 100.");
        }
        DetectionRule rule = new DetectionRule(
                0,
                actor.getOrgId(),
                normalizedCategory,
                pattern,
                weight,
                true,
                description != null ? description.trim() : "",
                new Timestamp(System.currentTimeMillis())
        );
        if (useDatabase && ruleJdbcDao != null) {
            ruleJdbcDao.create(rule);
        } else {
            rule.setId(nextOfflineId++);
        }
        ruleStore.save(rule);
        recompilePatterns();
        return rule;
    }

    public synchronized void deleteRule(User actor, int ruleId)
            throws UnauthorizedRoleException, EntityNotFoundException, DatabaseException {
        authService.requireRole(actor, "admin");
        DetectionRule existing = findById(actor.getOrgId(), ruleId);
        if (useDatabase && ruleJdbcDao != null) {
            ruleJdbcDao.deleteById(actor.getOrgId(), ruleId);
        }
        ruleStore.deleteById(existing.getId());
        recompilePatterns();
    }
}
