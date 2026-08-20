/**
 * Sink-hint scanner — regex catalog of dangerous patterns.
 *
 * Per Claude §8 (static-first redesign):
 *   "Закрытый JSON-schema, куски ≤4K только по sink-hints (innerHTML, eval,
 *    child_process, fetch(user), solidity-unrelated), hard timeout 30–45s"
 *
 * This module is the GATE for LLM invocation. If no sink-hints are found,
 * LLM is SKIPPED entirely (saves $0.84/target + 250s avg time).
 * If sink-hints are found, only the surrounding context (~4K) is sent to LLM,
 * not the full 32K sourceCode.
 *
 * IMPORTANT: This is HINT detection, not VULN detection.
 * A sink-hint says "this MIGHT be exploitable — look closer with LLM/active probe".
 * Many sink-hints will be false positives (e.g. innerHTML with hardcoded string).
 * The LLM's job is to filter sink-hints to real vulns.
 *
 * Categories (per OWASP Top 10 + web3-specific):
 *   - DOM XSS sinks: innerHTML, outerHTML, document.write, eval, Function()
 *   - SSRF sinks: fetch(userInput), axios.get(userInput), /_next/image?url=
 *   - SQLi sinks: string-concat SQL, raw query()
 *   - Path traversal sinks: fs.readFile(userInput), path.join(userInput)
 *   - Open redirect sinks: window.location = userInput, res.redirect(userInput)
 *   - Prototype pollution: __proto__, merge(userInput), $.extend(deep, ...)
 *   - Web3 sinks: setApprovalForAll, permit, infinite allowance, hidden spender
 *   - Secret patterns: sk-/eyJ/AKIA/ghp_/AIza/xox (already in api_leak checker)
 */

export interface SinkHint {
  type:
    | 'xss_sink'
    | 'ssrf_sink'
    | 'sqli_sink'
    | 'path_traversal_sink'
    | 'open_redirect_sink'
    | 'prototype_pollution_sink'
    | 'web3_sink'
    | 'secret_pattern';
  pattern: string;        // regex that matched
  match: string;           // the actual matched string (truncated for secrets)
  location: number;        // char offset in sourceCode
  contextBefore: string;   // 200 chars before match
  contextAfter: string;    // 200 chars after match
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;     // human-readable explanation
}

interface SinkPattern {
  type: SinkHint['type'];
  regex: RegExp;
  severity: SinkHint['severity'];
  description: string;
  // For secrets: redact the match value (don't log full secret)
  redactMatch?: boolean;
}

const SINK_PATTERNS: SinkPattern[] = [
  // ─── DOM XSS sinks ───
  {
    type: 'xss_sink',
    regex: /\.innerHTML\s*=/g,
    severity: 'high',
    description: 'innerHTML assignment — potential DOM XSS if user-controlled input flows here',
  },
  {
    type: 'xss_sink',
    regex: /\.outerHTML\s*=/g,
    severity: 'high',
    description: 'outerHTML assignment — potential DOM XSS',
  },
  {
    type: 'xss_sink',
    regex: /document\.write\s*\(/g,
    severity: 'high',
    description: 'document.write() — direct HTML injection sink',
  },
  {
    type: 'xss_sink',
    regex: /\beval\s*\(/g,
    severity: 'critical',
    description: 'eval() — arbitrary code execution sink',
  },
  {
    type: 'xss_sink',
    regex: /new\s+Function\s*\(/g,
    severity: 'critical',
    description: 'new Function() — code evaluation sink',
  },
  {
    type: 'xss_sink',
    regex: /setTimeout\s*\(\s*['"]/g,
    severity: 'high',
    description: 'setTimeout(string) — string-code evaluation',
  },
  {
    type: 'xss_sink',
    regex: /setInterval\s*\(\s*['"]/g,
    severity: 'high',
    description: 'setInterval(string) — string-code evaluation',
  },

  // ─── SSRF sinks ───
  {
    type: 'ssrf_sink',
    regex: /\/_next\/image\?url=/g,
    severity: 'medium',
    description: 'Next.js /_next/image?url= — common SSRF sink (often allowlisted, but worth checking)',
  },
  {
    type: 'ssrf_sink',
    regex: /\/api\/proxy\?url=/g,
    severity: 'high',
    description: 'Proxy endpoint with url= parameter — direct SSRF sink',
  },
  {
    type: 'ssrf_sink',
    regex: /\/api\/fetch\?url=/g,
    severity: 'high',
    description: 'Fetch endpoint with url= parameter — direct SSRF sink',
  },
  {
    type: 'ssrf_sink',
    regex: /fetch\s*\(\s*[a-zA-Z_$][\w$]*\s*\)/g,
    severity: 'medium',
    description: 'fetch(variable) — possible SSRF if variable is user-controlled',
  },
  {
    type: 'ssrf_sink',
    regex: /axios\.get\s*\(\s*[a-zA-Z_$][\w$]*\s*\)/g,
    severity: 'medium',
    description: 'axios.get(variable) — possible SSRF if variable is user-controlled',
  },
  {
    type: 'ssrf_sink',
    regex: /https?:\/\/[^'"\s)]*\$\{/g,
    severity: 'medium',
    description: 'URL with ${template} interpolation — possible SSRF if template is user-controlled',
  },

  // ─── SQLi sinks ───
  {
    type: 'sqli_sink',
    regex: /query\s*\(\s*['"`].*?\$\{.*?\}.*?['"`]/g,
    severity: 'high',
    description: 'SQL query with template literal — string concat = SQLi',
  },
  {
    type: 'sqli_sink',
    regex: /SELECT\s+.*?\+.*?(?:FROM|WHERE)/gi,
    severity: 'high',
    description: 'SQL string concat — likely SQLi',
  },
  {
    type: 'sqli_sink',
    regex: /\.raw\s*\(\s*['"`].*?\$\{.*?\}.*?['"`]/g,
    severity: 'high',
    description: 'ORM raw() with template — likely SQLi',
  },

  // ─── Path traversal sinks ───
  {
    type: 'path_traversal_sink',
    regex: /readFile\s*\(\s*[a-zA-Z_$][\w$]*\s*\)/g,
    severity: 'medium',
    description: 'readFile(variable) — possible path traversal',
  },
  {
    type: 'path_traversal_sink',
    regex: /readFileSync\s*\(\s*[a-zA-Z_$][\w$]*\s*\)/g,
    severity: 'medium',
    description: 'readFileSync(variable) — possible path traversal',
  },
  {
    type: 'path_traversal_sink',
    regex: /\.join\s*\(\s*[^,)]+,\s*[a-zA-Z_$][\w$]*\s*\)/g,
    severity: 'low',
    description: 'path.join(static, variable) — possible path traversal',
  },

  // ─── Open redirect sinks ───
  {
    type: 'open_redirect_sink',
    regex: /window\.location\s*=\s*[a-zA-Z_$][\w$]*/g,
    severity: 'medium',
    description: 'window.location = variable — possible open redirect',
  },
  {
    type: 'open_redirect_sink',
    regex: /location\.href\s*=\s*[a-zA-Z_$][\w$]*/g,
    severity: 'medium',
    description: 'location.href = variable — possible open redirect',
  },
  {
    type: 'open_redirect_sink',
    regex: /res\.redirect\s*\(\s*[a-zA-Z_$][\w$]*\s*\)/g,
    severity: 'medium',
    description: 'res.redirect(variable) — possible open redirect',
  },

  // ─── Prototype pollution sinks ───
  {
    type: 'prototype_pollution_sink',
    regex: /__proto__\s*=/g,
    severity: 'high',
    description: '__proto__ assignment — prototype pollution',
  },
  {
    type: 'prototype_pollution_sink',
    regex: /\$\.extend\s*\(\s*true/g,
    severity: 'high',
    description: '$.extend(true, ...) — deep merge can pollute prototype',
  },
  {
    type: 'prototype_pollution_sink',
    regex: /Object\.assign\s*\(\s*[a-zA-Z_$][\w$]*\s*,\s*[a-zA-Z_$][\w$]*\s*\)/g,
    severity: 'low',
    description: 'Object.assign with user-controlled source — possible prototype pollution',
  },

  // ─── Web3 sinks (the namesake of CryptoSentinel) ───
  {
    type: 'web3_sink',
    regex: /setApprovalForAll\s*\(/g,
    severity: 'high',
    description: 'setApprovalForAll() — infinite allowance, phishing risk',
  },
  {
    type: 'web3_sink',
    regex: /\.permit\s*\(/g,
    severity: 'high',
    description: 'permit() — EIP-2612 signature-based approval, phishing risk',
  },
  {
    type: 'web3_sink',
    regex: /increaseAllowance\s*\(/g,
    severity: 'medium',
    description: 'increaseAllowance() — possible infinite allowance',
  },
  {
    type: 'web3_sink',
    regex: /signMessage\s*\(/g,
    severity: 'high',
    description: 'signMessage() — user signs arbitrary data, phishing risk',
  },
  {
    type: 'web3_sink',
    regex: /signTypedData\s*\(/g,
    severity: 'high',
    description: 'signTypedData() — EIP-712 signing, phishing risk if domain/contents attacker-controlled',
  },
  {
    type: 'web3_sink',
    regex: /eth_requestAccounts/g,
    severity: 'low',
    description: 'eth_requestAccounts — wallet connection entry point (normal but worth tracking)',
  },

  // ─── Secret patterns (overlap with api_leak passive evidence checker) ───
  {
    type: 'secret_pattern',
    regex: /\bsk-[a-zA-Z0-9_-]{20,}\b/g,
    severity: 'critical',
    description: 'OpenAI/Stripe-style API key detected',
    redactMatch: true,
  },
  {
    type: 'secret_pattern',
    regex: /\bAKIA[A-Z0-9]{16}\b/g,
    severity: 'critical',
    description: 'AWS access key ID detected',
    redactMatch: true,
  },
  {
    type: 'secret_pattern',
    regex: /\bghp_[A-Za-z0-9]{36,}\b/g,
    severity: 'critical',
    description: 'GitHub personal access token detected',
    redactMatch: true,
  },
  {
    type: 'secret_pattern',
    regex: /\bAIza[A-Za-z0-9_\-]{35}\b/g,
    severity: 'critical',
    description: 'Google API key detected',
    redactMatch: true,
  },
  {
    type: 'secret_pattern',
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
    severity: 'critical',
    description: 'Slack token detected',
    redactMatch: true,
  },
  {
    type: 'secret_pattern',
    regex: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
    severity: 'high',
    description: 'JWT token detected (verify if it's a session token vs public API token)',
    redactMatch: true,
  },
];

// Placeholder patterns to reject (don't flag these as secrets)
const PLACEHOLDER_PATTERNS = /^(sk-test|sk-leaked|sk-fake|sk-placeholder|test|example|demo|sample|xxx|yyy|aaa|your[_-]?api[_-]?key|placeholder|changeme|default|foo|bar|baz|password|secret|token|abc123|123456789|00000000|example\.com|placeholder\.com)/i;

/**
 * Scan source code for sink hints.
 * Returns array of hints, sorted by severity (critical first).
 * Each hint includes 200 chars of context before/after for LLM analysis.
 *
 * @param sourceCode HTML + JS bundle content (up to 32K chars)
 * @param maxHints Maximum hints to return (default 50 — keeps LLM context small)
 */
export function scanSinkHints(sourceCode: string, maxHints = 50): SinkHint[] {
  const hints: SinkHint[] = [];

  for (const pattern of SINK_PATTERNS) {
    // Reset regex lastIndex (stateful with /g flag)
    pattern.regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    let count = 0;
    while ((match = pattern.regex.exec(sourceCode)) !== null) {
      count++;
      if (count > 20) break;  // cap per-pattern matches

      const matchedValue = match[0];
      // Skip placeholder secrets
      if (pattern.type === 'secret_pattern' && PLACEHOLDER_PATTERNS.test(matchedValue)) {
        continue;
      }

      const start = match.index;
      const end = start + matchedValue.length;
      const contextBefore = sourceCode.slice(Math.max(0, start - 200), start);
      const contextAfter = sourceCode.slice(end, end + 200);

      // For secrets: redact the matched value to prefix + suffix + length
      let displayMatch = matchedValue;
      if (pattern.redactMatch && matchedValue.length > 12) {
        displayMatch = matchedValue.slice(0, 4) + '...' + matchedValue.slice(-4) + ` [len=${matchedValue.length}]`;
      } else if (matchedValue.length > 80) {
        displayMatch = matchedValue.slice(0, 80) + '...';
      }

      hints.push({
        type: pattern.type,
        pattern: pattern.regex.source,
        match: displayMatch,
        location: start,
        contextBefore: contextBefore.slice(-100),  // last 100 chars
        contextAfter: contextAfter.slice(0, 100),  // first 100 chars
        severity: pattern.severity,
        description: pattern.description,
      });
    }
  }

  // Sort by severity (critical first, then high, medium, low)
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  hints.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  return hints.slice(0, maxHints);
}

/**
 * Group sink hints by type for the LLM context.
 * Returns a map like { xss_sink: [hint1, hint2], ssrf_sink: [hint3] }
 * Used to build LLM prompt sections.
 */
export function groupHintsByType(hints: SinkHint[]): Record<string, SinkHint[]> {
  const grouped: Record<string, SinkHint[]> = {};
  for (const h of hints) {
    if (!grouped[h.type]) grouped[h.type] = [];
    grouped[h.type].push(h);
  }
  return grouped;
}

/**
 * Build a compact LLM context from sink hints.
 * Returns ~4K char string with all hints + their contexts.
 * This replaces the 30K sourceCode slice — LLM gets focused context.
 */
export function buildLLMContextFromHints(hints: SinkHint[]): string {
  if (hints.length === 0) return '';
  const grouped = groupHintsByType(hints);
  const sections: string[] = [];
  for (const [type, typeHints] of Object.entries(grouped)) {
    sections.push(`## ${type.toUpperCase()} (${typeHints.length} hints)\n`);
    for (const h of typeHints) {
      sections.push(`### [${h.severity}] ${h.description}`);
      sections.push(`Match: ${h.match}`);
      sections.push(`Context before: ...${h.contextBefore}`);
      sections.push(`Context after: ${h.contextAfter}...`);
      sections.push('');
    }
  }
  return sections.join('\n').slice(0, 4000);
}
