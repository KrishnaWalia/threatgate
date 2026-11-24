package com.threatgate.service;

import com.threatgate.model.DetectionRule;
import com.threatgate.model.InspectionRequest;
import com.threatgate.model.InspectionResult;
import com.threatgate.model.RuleMatch;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class DetectionEngine {
    private static final int MAX_VALUE_LEN = 20_000;
    private static final int DEFAULT_BLOCK_THRESHOLD = 50;

    private static final Pattern PERCENT_HEX_PATTERN = Pattern.compile("%([0-9a-fA-F]{2})");
    private static final Pattern PERCENT_UNICODE_PATTERN = Pattern.compile("%u([0-9a-fA-F]{4})", Pattern.CASE_INSENSITIVE);
    private static final Pattern JSON_UNICODE_PATTERN = Pattern.compile("\\\\u([0-9a-fA-F]{4})", Pattern.CASE_INSENSITIVE);
    private static final Pattern HTML_HEX_PATTERN = Pattern.compile("&#x([0-9a-fA-F]+);?", Pattern.CASE_INSENSITIVE);
    private static final Pattern HTML_DEC_PATTERN = Pattern.compile("&#(\\d+);?");
    private static final Pattern HTML_NAMED_PATTERN = Pattern.compile("&(lt|gt|quot|apos|amp|sol|bsol);", Pattern.CASE_INSENSITIVE);
    private static final Pattern SQL_INLINE_COMMENT_PATTERN = Pattern.compile("/\\*[\\s\\S]*?\\*/");
    private static final Pattern WHITESPACE_COLLAPSE_PATTERN = Pattern.compile("\\s+");

    private static final Map<String, String> NAMED_ENTITIES = createNamedEntities();

    private final int blockThreshold;
    private final RequestValidator requestValidator;

    public DetectionEngine(int blockThreshold) {
        this.blockThreshold = blockThreshold > 0 ? blockThreshold : DEFAULT_BLOCK_THRESHOLD;
        this.requestValidator = req -> req != null && req.getUrl() != null;
    }

    public DetectionEngine() {
        this(DEFAULT_BLOCK_THRESHOLD);
    }

    private static Map<String, String> createNamedEntities() {
        Map<String, String> entities = new LinkedHashMap<>();
        entities.put("lt", "<");
        entities.put("gt", ">");
        entities.put("quot", "\"");
        entities.put("apos", "'");
        entities.put("amp", "&");
        entities.put("sol", "/");
        entities.put("bsol", "\\");
        return Collections.unmodifiableMap(entities);
    }

    public String normalize(String input) {
        if (input == null || input.isEmpty()) {
            return "";
        }
        String current = input.length() > MAX_VALUE_LEN ? input.substring(0, MAX_VALUE_LEN) : input;
        current = current.replace('+', ' ');
        for (int round = 0; round < 3; round++) {
            String next = decodeOnce(current);
            if (next.equals(current)) {
                break;
            }
            current = next;
        }
        current = SQL_INLINE_COMMENT_PATTERN.matcher(current).replaceAll(" ");
        return WHITESPACE_COLLAPSE_PATTERN.matcher(current).replaceAll(" ");
    }

    private String decodeOnce(String value) {
        String step1 = replaceHexCodes(PERCENT_HEX_PATTERN, value, 16);
        String step2 = replaceHexCodes(PERCENT_UNICODE_PATTERN, step1, 16);
        String step3 = replaceHexCodes(JSON_UNICODE_PATTERN, step2, 16);
        String step4 = replaceHexCodes(HTML_HEX_PATTERN, step3, 16);
        String step5 = replaceHexCodes(HTML_DEC_PATTERN, step4, 10);

        Matcher namedMatcher = HTML_NAMED_PATTERN.matcher(step5);
        StringBuilder sb = new StringBuilder();
        while (namedMatcher.find()) {
            String key = namedMatcher.group(1).toLowerCase();
            String replacement = NAMED_ENTITIES.getOrDefault(key, namedMatcher.group(0));
            namedMatcher.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        namedMatcher.appendTail(sb);
        return sb.toString();
    }

    private String replaceHexCodes(Pattern pattern, String input, int radix) {
        Matcher matcher = pattern.matcher(input);
        StringBuilder sb = new StringBuilder();
        while (matcher.find()) {
            String token = matcher.group(1);
            String replacement = safeCharFromCode(token, radix);
            matcher.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    private String safeCharFromCode(String digits, int radix) {
        try {
            int codePoint = Integer.parseInt(digits, radix);
            if (codePoint > 0 && codePoint < 0x110000) {
                return new String(Character.toChars(codePoint));
            }
            if (codePoint == 0) {
                return String.valueOf((char) 0);
            }
            return "";
        } catch (NumberFormatException e) {
            return "";
        }
    }

    public List<TargetField> extractTargets(InspectionRequest request) {
        if (!requestValidator.validate(request)) {
            return Collections.emptyList();
        }
        String url = request.getUrl();
        int qIdx = url.indexOf('?');
        String pathPart = qIdx == -1 ? url : url.substring(0, qIdx);
        String queryPart = qIdx == -1 ? "" : url.substring(qIdx + 1);

        List<TargetField> rawTargets = new ArrayList<>();
        rawTargets.add(new TargetField("path", pathPart));
        rawTargets.add(new TargetField("query", queryPart));
        rawTargets.add(new TargetField("body", request.getBody()));
        rawTargets.add(new TargetField("user-agent", request.getUserAgent()));
        rawTargets.add(new TargetField("referer", request.getReferer()));
        rawTargets.add(new TargetField("cookie", request.getCookie()));

        return rawTargets.stream()
                .filter(target -> target.value != null && !target.value.isEmpty())
                .collect(Collectors.toList());
    }

    public InspectionResult inspect(
            InspectionRequest request,
            List<DetectionRule> activeRules,
            Map<Integer, Pattern> compiledPatterns) {
        if (!requestValidator.validate(request) || activeRules == null || activeRules.isEmpty()) {
            return new InspectionResult(0, "none", null, false, Collections.emptyList());
        }

        List<TargetField> targets = extractTargets(request);
        Map<Integer, RuleMatch> distinctMatches = new LinkedHashMap<>();

        RuleMatcher matcher = (rule, normalizedText) -> {
            Pattern pattern = compiledPatterns != null ? compiledPatterns.get(rule.getId()) : null;
            if (pattern == null) {
                try {
                    pattern = Pattern.compile(rule.getPattern(), Pattern.CASE_INSENSITIVE);
                } catch (RuntimeException e) {
                    return false;
                }
            }
            return pattern.matcher(normalizedText).find();
        };

        for (TargetField target : targets) {
            String normalizedText = normalize(target.value);
            for (DetectionRule rule : activeRules) {
                if (!rule.isActive() || distinctMatches.containsKey(rule.getId())) {
                    continue;
                }
                if (matcher.matches(rule, normalizedText)) {
                    distinctMatches.put(
                            rule.getId(),
                            new RuleMatch(
                                    rule.getId(),
                                    rule.getCategory(),
                                    rule.getWeight(),
                                    target.where,
                                    rule.getDescription()
                            )
                    );
                }
            }
        }

        return score(new ArrayList<>(distinctMatches.values()));
    }

    public InspectionResult score(List<RuleMatch> matches) {
        if (matches == null || matches.isEmpty()) {
            return new InspectionResult(0, "none", null, false, Collections.emptyList());
        }
        List<RuleMatch> sorted = matches.stream()
                .sorted(Comparator.comparingInt(RuleMatch::getWeight).reversed())
                .collect(Collectors.toList());

        RuleMatch top = sorted.get(0);
        int corroboratingSum = sorted.stream()
                .skip(1)
                .mapToInt(RuleMatch::getWeight)
                .sum();
        int riskScore = (int) Math.min(100L, Math.round(top.getWeight() + 0.5 * corroboratingSum));
        boolean blocked = riskScore >= blockThreshold;
        return new InspectionResult(riskScore, top.getCategory(), top.getRuleId(), blocked, sorted);
    }

    public int getBlockThreshold() {
        return blockThreshold;
    }

    public static final class TargetField {
        private final String where;
        private final String value;

        public TargetField(String where, String value) {
            this.where = where;
            this.value = value;
        }

        public String getWhere() {
            return where;
        }

        public String getValue() {
            return value;
        }
    }
}
