/**
 * DETECTOR — Track A's core. Pure functions, no I/O, so it can be
 * unit-tested (test/detector.test.js) without starting a server.
 *
 * Pipeline for one request:
 *   1. extractTargets()  -> which parts of the request we inspect
 *   2. normalize()       -> undo the attacker's encoding tricks
 *   3. run every active rule's regex against every target
 *   4. score()           -> combine matches into ONE risk number 0-100
 *
 * RISK SCORING FORMULA
 * --------------------
 *   risk = min( 100,  W_max  +  0.5 * (sum of the OTHER distinct weights) )
 *
 *   W_max  = weight of the single strongest rule that matched.
 *   Others = weights of the remaining *distinct* rules that matched
 *            (a rule counts once even if it matches in 3 places, so
 *            an attacker can't inflate the score by repeating one
 *            payload).
 *
 * Why this shape?
 *   - The strongest signal sets the floor: one UNION SELECT (80) is
 *     already a block, no need for corroboration.
 *   - Extra, *different* rules matching is corroborating evidence,
 *     so they add — but at half weight, so a pile of weak signals
 *     (e.g. "select ... from" 40 + "alert(" 40 = 40 + 20 = 60) can
 *     tip over the threshold without ever out-scoring a real hit.
 *   - Capped at 100 so the number stays a readable percentage.
 *
 * The request is BLOCKED when risk >= BLOCK_THRESHOLD (default 50).
 * The category reported is the category of the strongest rule.
 */

const MAX_VALUE_LEN = 20_000; // per target — bounds regex work per request

// ------------------------------------------------------------------
// 2. NORMALISATION — attackers encode payloads to slip past naive
// regexes. We decode first, then match, so one rule catches all forms.
// ------------------------------------------------------------------
const NAMED_ENTITIES = { lt: '<', gt: '>', quot: '"', apos: "'", amp: '&', sol: '/', bsol: '\\' };

function decodeOnce(s) {
  return s
    // %27 -> '   (manual, so a malformed %zz never throws)
    .replace(/%([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
    // %u0027 legacy IIS-style
    .replace(/%u([0-9a-f]{4})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
    // JSON-style \u003c
    .replace(/\\u([0-9a-f]{4})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
    // HTML numeric entities &#60; &#x3c;
    .replace(/&#x([0-9a-f]+);?/gi, (_, h) => safeChar(parseInt(h, 16)))
    .replace(/&#(\d+);?/g, (_, d) => safeChar(parseInt(d, 10)))
    // HTML named entities (the handful that matter)
    .replace(/&(lt|gt|quot|apos|amp|sol|bsol);/gi, (_, n) => NAMED_ENTITIES[n.toLowerCase()]);
}

function safeChar(code) {
  return code > 0 && code < 0x110000 ? String.fromCodePoint(code) : '';
}

function normalize(input) {
  let s = String(input).slice(0, MAX_VALUE_LEN).replace(/\+/g, ' ');
  // Decode repeatedly: %252e%252e%252f is "double-encoded ../".
  // Three rounds is enough for real attacks; the loop stops early
  // once decoding no longer changes anything.
  for (let i = 0; i < 3; i++) {
    const next = decodeOnce(s);
    if (next === s) break;
    s = next;
  }
  return s
    .replace(/\/\*[\s\S]*?\*\//g, ' ') // UNION/**/SELECT -> UNION SELECT
    .replace(/\s+/g, ' ');             // collapse whitespace tricks (tabs, newlines)
}

// ------------------------------------------------------------------
// 1. WHAT WE INSPECT
// ------------------------------------------------------------------
function extractTargets(req, bodyText = '') {
  const url = req.originalUrl || req.url || '/';
  const qIdx = url.indexOf('?');
  const pathPart = qIdx === -1 ? url : url.slice(0, qIdx);
  const queryPart = qIdx === -1 ? '' : url.slice(qIdx + 1);
  const h = req.headers || {};

  const targets = [
    { where: 'path', value: pathPart },
    { where: 'query', value: queryPart },
    { where: 'body', value: bodyText },
    { where: 'user-agent', value: h['user-agent'] || '' },
    { where: 'referer', value: h['referer'] || '' },
    { where: 'cookie', value: h['cookie'] || '' },
  ];
  return targets.filter((t) => t.value);
}

// ------------------------------------------------------------------
// Rule compilation — rules arrive as rows ({pattern: string}); we
// compile each once and skip (loudly) any that aren't valid regex.
// ------------------------------------------------------------------
function compileRules(rules) {
  const compiled = [];
  for (const r of rules) {
    if (!r.is_active) continue;
    try {
      compiled.push({ ...r, regex: new RegExp(r.pattern, 'i') });
    } catch (err) {
      console.warn(`[detector] rule ${r.id} has an invalid pattern, skipped: ${err.message}`);
    }
  }
  return compiled;
}

// ------------------------------------------------------------------
// 4. SCORING
// ------------------------------------------------------------------
function score(matches) {
  if (matches.length === 0) return { riskScore: 0, category: 'none', top: null };
  const sorted = [...matches].sort((a, b) => b.weight - a.weight);
  const top = sorted[0];
  const rest = sorted.slice(1).reduce((sum, m) => sum + m.weight, 0);
  const riskScore = Math.min(100, Math.round(top.weight + 0.5 * rest));
  return { riskScore, category: top.category, top };
}

/**
 * inspect(req, bodyText, compiledRules) -> {
 *   riskScore, category, matchedRuleId, matches: [{id, category, weight, where, description}]
 * }
 */
function inspect(req, bodyText, compiledRules) {
  const targets = extractTargets(req, bodyText);
  const best = new Map(); // ruleId -> match (distinct rules only)

  for (const t of targets) {
    const text = normalize(t.value);
    for (const rule of compiledRules) {
      if (best.has(rule.id)) continue; // a rule counts once
      if (rule.regex.test(text)) {
        best.set(rule.id, {
          id: rule.id,
          category: rule.category,
          weight: rule.weight,
          where: t.where,
          description: rule.description,
        });
      }
    }
  }

  const matches = [...best.values()];
  const { riskScore, category, top } = score(matches);
  return { riskScore, category, matchedRuleId: top ? top.id : null, matches };
}

module.exports = { normalize, extractTargets, compileRules, score, inspect };
