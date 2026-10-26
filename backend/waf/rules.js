/**
 * DEFAULT RULES — "rules as data".
 *
 * Each rule is a row-shaped object matching the `rules` table in
 * schema/schema.sql (id, category, pattern, weight, is_active,
 * description). The detector never contains a hardcoded regex; it
 * only runs whatever rules the rulesStore hands it. These defaults
 * are what the in-memory store starts with (and what seed.js
 * inserts into MySQL).
 *
 * `weight` (1-100) is how much risk a match adds. With the default
 * block threshold of 50:
 *   weight >= 50  -> strong signal, blocks on its own
 *   weight  < 50  -> weak signal, only blocks in combination
 *
 * All patterns are matched case-insensitively against INPUT THAT
 * HAS ALREADY BEEN NORMALISED (URL-decoded up to 3 times, HTML
 * entities decoded, inline SQL comments replaced by a space) — see
 * detector.normalize(). That is why most patterns don't need to
 * mention %27, &#39; or comment tricks.
 */
const DEFAULT_RULES = [
  // ------------------------------------------------------------
  // SQL INJECTION
  // ------------------------------------------------------------
  {
    id: 1, category: 'sqli', weight: 80,
    pattern: '\\bunion\\b[\\s\\S]{0,40}\\bselect\\b',
    description: 'UNION SELECT — appends attacker query to read other tables',
  },
  {
    id: 2, category: 'sqli', weight: 75,
    pattern: '[\'"]\\s*(?:or|and)\\s+[\'"]?\\w+[\'"]?\\s*(?:=|like)\\s*[\'"]?\\w+',
    description: "Quote-based tautology — ' OR '1'='1 (breaks out of a string, forces TRUE)",
  },
  {
    id: 3, category: 'sqli', weight: 70,
    pattern: '\\b(?:or|and)\\s+\\d+\\s*=\\s*\\d+',
    description: 'Numeric tautology — OR 1=1 (injection into a numeric context)',
  },
  {
    id: 4, category: 'sqli', weight: 60,
    pattern: '[\'"]\\s*(?:--|#|/\\*)',
    description: "Quote followed by SQL comment — admin'-- (cuts off the rest of the query)",
  },
  {
    id: 5, category: 'sqli', weight: 85,
    pattern: ';\\s*(?:drop\\s+(?:table|database)|truncate\\s+table|delete\\s+from|insert\\s+into|update\\s+\\w+\\s+set|alter\\s+table|create\\s+(?:table|user))',
    description: 'Stacked query — ; DROP TABLE ... (runs a second, destructive statement)',
  },
  {
    id: 6, category: 'sqli', weight: 80,
    pattern: '\\b(?:sleep\\s*\\(\\s*\\d+|benchmark\\s*\\(|pg_sleep\\s*\\(|waitfor\\s+delay)',
    description: 'Time-based blind SQLi — SLEEP()/BENCHMARK()/WAITFOR DELAY',
  },
  {
    id: 7, category: 'sqli', weight: 70,
    pattern: '\\b(?:information_schema|sqlite_master|pg_catalog|mysql\\.user)\\b',
    description: 'Schema reconnaissance — reading the database catalog',
  },
  {
    id: 8, category: 'sqli', weight: 75,
    pattern: '\\b(?:extractvalue|updatexml|load_file)\\s*\\(|into\\s+(?:out|dump)file',
    description: 'Error-based / file-access SQL functions',
  },
  {
    id: 9, category: 'sqli', weight: 40,
    pattern: '\\bselect\\b[\\s\\S]{1,60}\\bfrom\\b',
    description: 'Weak signal — SELECT ... FROM in user input (blocks only with another match)',
  },

  // ------------------------------------------------------------
  // CROSS-SITE SCRIPTING
  // ------------------------------------------------------------
  {
    id: 10, category: 'xss', weight: 80,
    pattern: '<\\s*script\\b',
    description: '<script> tag injection',
  },
  {
    id: 11, category: 'xss', weight: 65,
    pattern: '\\bon(?:error|load|click|mouseover|mouseenter|focus|blur|toggle|begin|start|animationstart|pointerover)\\s*=',
    description: 'Inline event handler — onerror=, onload=, onclick= ...',
  },
  {
    id: 12, category: 'xss', weight: 70,
    pattern: '\\b(?:javascript|vbscript)\\s*:',
    description: 'javascript: / vbscript: URL scheme',
  },
  {
    id: 13, category: 'xss', weight: 60,
    pattern: '<\\s*(?:iframe|object|embed)\\b',
    description: '<iframe>/<object>/<embed> injection',
  },
  {
    id: 14, category: 'xss', weight: 60,
    pattern: 'data\\s*:\\s*text/html',
    description: 'data:text/html URL (inline HTML document)',
  },
  {
    id: 15, category: 'xss', weight: 60,
    pattern: 'document\\s*\\.\\s*(?:cookie|write|location)',
    description: 'Cookie theft / DOM manipulation — document.cookie, .write, .location',
  },
  {
    id: 16, category: 'xss', weight: 40,
    pattern: '\\b(?:alert|prompt|confirm|eval)\\s*\\(',
    description: 'JS probe functions — alert()/prompt()/eval() (weak alone)',
  },

  // ------------------------------------------------------------
  // PATH TRAVERSAL
  // ------------------------------------------------------------
  {
    id: 17, category: 'path_traversal', weight: 55,
    pattern: '\\.\\.[\\\\/]',
    description: '../ or ..\\ — directory climb',
  },
  {
    id: 18, category: 'path_traversal', weight: 80,
    pattern: '(?:\\.\\.[\\\\/]){2,}',
    description: 'Repeated ../../ — deep traversal toward the filesystem root',
  },
  {
    id: 19, category: 'path_traversal', weight: 85,
    pattern: '(?:^|[\\\\/=])(?:etc[\\\\/](?:passwd|shadow|hosts|group)|proc[\\\\/]self[\\\\/]\\w+|boot\\.ini|windows[\\\\/](?:win\\.ini|system32)|var[\\\\/]log[\\\\/])',
    description: 'Well-known sensitive files — /etc/passwd, win.ini, /proc/self/...',
  },
  {
    id: 20, category: 'path_traversal', weight: 70,
    pattern: '[\\\\/]\\.(?:env|git|svn|htaccess|htpasswd|ssh|aws)(?:[\\\\/\\s?]|$)',
    description: 'Hidden config/credential files — /.env, /.git/, /.ssh/',
  },
  {
    id: 21, category: 'path_traversal', weight: 55,
    pattern: '\\x00',
    description: 'Null byte — used to truncate file extensions (file.php%00.jpg)',
  },
  {
    id: 22, category: 'path_traversal', weight: 60,
    pattern: '\\b(?:file|php|zip|expect|gopher|phar)://',
    description: 'File/protocol wrapper — file://, php://, expect:// (LFI/SSRF)',
  },
].map((r) => ({ ...r, is_active: true, org_id: 1 }));

module.exports = { DEFAULT_RULES };
