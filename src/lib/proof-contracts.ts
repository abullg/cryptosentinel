/**
 * CryptoSentinel — Vulnerability Proof Contracts
 *
 * For EACH vulnerability class, defines:
 * 1. PROOF REQUIRED — what specific evidence proves the vulnerability
 * 2. REQUESTS — exact HTTP requests to make
 * 3. RESPONSE COMPARISON — what differences prove the vuln
 * 4. MISCONFIG vs VULNERABILITY boundary
 * 5. INCONCLUSIVE vs DROP criteria
 * 6. LEGITIMATE EXCLUSION — how to exclude false positives
 * 7. IMPACT PROOF — how to demonstrate impact safely
 *
 * Three-state model:
 *   CONFIRMED  — security property PROVEN → confidence=1.0
 *   INCONCLUSIVE — evidence AMBIGUOUS (could be real, could be FP) → confidence=0.5
 *   DROP — actively DISPROVEN (false positive) → confidence=0
 *
 * INCONCLUSIVE ≠ "we didn't try". It means "we tried but evidence is
 * ambiguous — human should verify manually."
 * DROP means "we tried and found evidence that this is NOT a vulnerability."
 */

export type Verdict = 'CONFIRMED' | 'INCONCLUSIVE' | 'DROP';

export interface ProofContract {
  type: string;
  proofRequired: string;
  requests: { method: string; url: string; headers?: Record<string, string>; body?: string; description: string }[];
  responseComparison: string;
  misconfigVsVuln: string;
  inconclusiveCriteria: string;
  dropCriteria: string;
  legitimateExclusion: string;
  impactProof: string;
}

// ─── PROOF CONTRACTS FOR ALL VULNERABILITY CLASSES ──────────────────

export const PROOF_CONTRACTS: Record<string, ProofContract> = {
  // ── XSS (Reflected) ───────────────────────────────────────────
  xss: {
    type: 'xss',
    proofRequired: 'Payload reflected VERBATIM (not escaped) in HTML response body, with Content-Type: text/html.',
    requests: [
      { method: 'GET', url: '{targetUrl}?{param}=<script>alert(1)</script>', description: 'Inject XSS payload in URL parameter' },
      { method: 'GET', url: '{targetUrl}?{param}=<img src=x onerror=alert(1)>', description: 'Alternative payload (img tag)' },
    ],
    responseComparison: 'Compare response with payload vs. without. Payload string must appear VERBATIM in response body. If escaped (&lt;script&gt;) → DROP. If Content-Type is not text/html → DROP.',
    misconfigVsVuln: 'CSP missing = misconfiguration (low). Reflected payload in HTML = vulnerability (high).',
    inconclusiveCriteria: 'Payload partially reflected (some chars escaped, some not) → INCONCLUSIVE (might be exploitable with encoding bypass).',
    dropCriteria: 'Payload not reflected at all, OR fully escaped, OR Content-Type is text/plain/json → DROP.',
    legitimateExclusion: 'Reflected in HTML comment or <script> tag value (not in renderable context) → DROP.',
    impactProof: 'Non-destructive: show that <script>alert(document.cookie)</script> would execute. Do NOT actually execute it.',
  },

  // ── SQL Injection (Error-based) ───────────────────────────────
  sql_injection: {
    type: 'sql_injection',
    proofRequired: 'Database error message in response body (MySQL/PostgreSQL/MSSQL/Oracle/SQLite error syntax).',
    requests: [
      { method: 'GET', url: '{targetUrl}?{param}=\'', description: 'Single quote to trigger SQL error' },
      { method: 'GET', url: '{targetUrl}?{param}=1\' AND \'1\'=\'1', description: 'Always-true condition' },
      { method: 'GET', url: '{targetUrl}?{param}=1\' AND \'1\'=\'2', description: 'Always-false condition' },
    ],
    responseComparison: 'Compare true vs. false condition responses. If different → boolean-based SQLi confirmed. If error message → error-based SQLi confirmed.',
    misconfigVsVuln: 'Verbose error messages = misconfiguration (medium). Exploitable injection = vulnerability (critical).',
    inconclusiveCriteria: 'Response differs between true/false but no error message → INCONCLUSIVE (might be blind SQLi, need time-based proof).',
    dropCriteria: 'No SQL error, no boolean difference, no time delay → DROP.',
    legitimateExclusion: 'Error message from framework (not database) → DROP. Generic 500 error → DROP.',
    impactProof: 'Show that UNION SELECT or information_schema queries would work. Do NOT extract real user data.',
  },

  // ── SQL Injection (Blind/Time-based) ─────────────────────────
  sqli_blind: {
    type: 'sqli_blind',
    proofRequired: 'Response time ≥3s when SLEEP/pg_sleep injected. Baseline response <1s.',
    requests: [
      { method: 'GET', url: '{targetUrl}?{param}=1\' AND SLEEP(3)-- -', description: 'MySQL SLEEP 3s' },
      { method: 'GET', url: '{targetUrl}?{param}=1; WAITFOR DELAY \'0:0:3\'--', description: 'MSSQL WAITFOR 3s' },
      { method: 'GET', url: '{targetUrl}?{param}=1\' AND pg_sleep(3)--', description: 'PostgreSQL pg_sleep 3s' },
    ],
    responseComparison: 'Measure response time. Baseline (no payload) should be <1s. SLEEP payload should be ≥3s. If 3x slower → confirmed.',
    misconfigVsVuln: 'Time delay = vulnerability (critical). No delay but verbose errors = misconfiguration.',
    inconclusiveCriteria: 'Response 1-2s slower but not ≥3s → INCONCLUSIVE (might be slow server, need more testing).',
    dropCriteria: 'No time difference between baseline and SLEEP payload → DROP.',
    legitimateExclusion: 'Server is generally slow (>2s baseline) → INCONCLUSIVE (can\'t distinguish).',
    impactProof: 'Time-based proof is non-destructive. Shows database executes injected SQL.',
  },

  // ── SSRF ──────────────────────────────────────────────────────
  ssrf: {
    type: 'ssrf',
    proofRequired: 'Response contains data from internal service (AWS metadata, localhost service, internal IP) — not from the target application itself.',
    requests: [
      { method: 'GET', url: '{targetUrl}?{param}=http://169.254.169.254/latest/meta-data/', description: 'AWS metadata endpoint' },
      { method: 'GET', url: '{targetUrl}?{param}=http://127.0.0.1:22', description: 'Internal port scan' },
      { method: 'GET', url: '{targetUrl}?{param}=file:///etc/passwd', description: 'File protocol' },
    ],
    responseComparison: 'Response must contain content from the INTERNAL service (ami-id, instance-id, root:x:0:0:). NOT just HTTP 200 from the target.',
    misconfigVsVuln: 'URL parameter accepts external URLs = misconfiguration (medium). Returns internal data = vulnerability (critical).',
    inconclusiveCriteria: 'URL parameter accepts URLs but returns target\'s own error page → INCONCLUSIVE (might be SSRF but can\'t confirm data from internal service).',
    dropCriteria: 'URL parameter rejected, OR response is same as normal page, OR no internal data in response → DROP.',
    legitimateExclusion: 'URL parameter used for legitimate redirects (e.g., OAuth callback) with allowlist → DROP.',
    impactProof: 'Show that AWS metadata (IAM credentials) would be accessible. Do NOT extract real credentials.',
  },

  // ── Open Redirect ────────────────────────────────────────────
  open_redirect: {
    type: 'open_redirect',
    proofRequired: 'Location header in response redirects to attacker-controlled domain (evil.com).',
    requests: [
      { method: 'GET', url: '{targetUrl}?{param}=//evil.com', description: 'Protocol-relative redirect' },
      { method: 'GET', url: '{targetUrl}?{param}=https://evil.com', description: 'Full URL redirect' },
      { method: 'GET', url: '{targetUrl}?{param}=//evil.com/path', description: 'Redirect with path' },
    ],
    responseComparison: 'Check Location header in response. Must point to evil.com or start with //evil.com. If Location stays on same domain → DROP.',
    misconfigVsVuln: 'Redirect to any URL = vulnerability (medium). Redirect only to same domain = not a vuln.',
    inconclusiveCriteria: 'Redirect to subdomain of target (might be intended behavior) → INCONCLUSIVE.',
    dropCriteria: 'No redirect, OR redirect to same domain, OR redirect blocked by allowlist → DROP.',
    legitimateExclusion: 'OAuth callback redirect with state validation → legitimate. Marketing redirect with allowlist → legitimate.',
    impactProof: 'Non-destructive: show that user would be redirected to attacker site. Do NOT actually redirect.',
  },

  // ── Path Traversal / LFI ─────────────────────────────────────
  path_traversal: {
    type: 'path_traversal',
    proofRequired: 'Response body contains content of system file (/etc/passwd on Linux, win.ini on Windows).',
    requests: [
      { method: 'GET', url: '{targetUrl}?{param}=../../../../etc/passwd', description: 'Linux path traversal' },
      { method: 'GET', url: '{targetUrl}?{param}=..\\\\..\\\\..\\\\windows\\\\win.ini', description: 'Windows path traversal' },
      { method: 'GET', url: '{targetUrl}?{param}=....//....//....//etc/passwd', description: 'Bypass with double dots' },
    ],
    responseComparison: 'Response must contain root:x:0:0: (Linux) or [fonts] (Windows). If response is just the target app\'s normal page → DROP.',
    misconfigVsVuln: 'Path traversal that reads system files = vulnerability (critical). Directory listing = misconfiguration (medium).',
    inconclusiveCriteria: 'Response contains file-like content but can\'t identify specific file → INCONCLUSIVE.',
    dropCriteria: 'No system file content in response, OR response is normal app page → DROP.',
    legitimateExclusion: 'File parameter loads only from allowlisted directory → DROP.',
    impactProof: 'Show that /etc/passwd is readable. Do NOT read sensitive config files (shadow, ssh keys).',
  },

  // ── Auth Bypass ──────────────────────────────────────────────
  auth_bypass: {
    type: 'auth_bypass',
    proofRequired: 'Endpoint returns user-specific data (userId, email, balance) WITHOUT auth headers, AND data is DIFFERENT from public homepage, AND data is not demo/placeholder, AND reproducible.',
    requests: [
      { method: 'GET', url: '{findingUrl}', headers: { 'User-Agent': 'Mozilla/5.0 (iPhone)' }, description: 'No auth, mobile UA' },
      { method: 'GET', url: '{targetUrl}/', headers: { 'User-Agent': 'Mozilla/5.0 (iPhone)' }, description: 'Public homepage for comparison' },
      { method: 'GET', url: '{findingUrl}', headers: { 'User-Agent': 'Mozilla/5.0 (iPhone)' }, description: 'Repeat for reproducibility' },
    ],
    responseComparison: 'Finding response vs. homepage: must differ >5% in size. Finding response vs. repeat: must be same status. Finding response: must NOT be 3xx redirect / 401 / 403.',
    misconfigVsVuln: 'Endpoint returns public data without auth = misconfiguration (low). Endpoint returns PRIVATE user data without auth = vulnerability (critical).',
    inconclusiveCriteria: 'Response has some data but can\'t determine if it\'s user-specific or public → INCONCLUSIVE (need authenticated request for comparison).',
    dropCriteria: 'Response is redirect/401/403, OR identical to homepage (SPA shell), OR contains demo/placeholder data, OR not reproducible → DROP.',
    legitimateExclusion: 'Public API that intentionally returns public data (price feeds, public profiles) → DROP.',
    impactProof: 'Show that userId/email/balance is accessible. Do NOT modify or delete user data.',
  },

  // ── Info Exposure ────────────────────────────────────────────
  info_exposure: {
    type: 'info_exposure',
    proofRequired: 'Response contains SPECIFIC sensitive data: clientIp in JS-accessible form, internal file paths in stack traces, 5+ real email addresses, or internal API endpoints in JS.',
    requests: [
      { method: 'GET', url: '{findingUrl}', description: 'Fetch page with potential info exposure' },
    ],
    responseComparison: 'Check response body for specific patterns: __net_track__ with clientIp, /usr/var/home paths, real emails, /api/internal/ endpoints.',
    misconfigVsVuln: 'API documentation publicly accessible = misconfiguration (low). Client IP exposed in JS = info exposure (low). Internal user data exposed = vulnerability (high).',
    inconclusiveCriteria: 'Response has some data that COULD be sensitive but context is unclear → INCONCLUSIVE (need manual verification of sensitivity).',
    dropCriteria: 'No specific sensitive data pattern matched, OR data is public by design (swagger docs, public API), OR data is demo/placeholder → DROP.',
    legitimateExclusion: 'Swagger/OpenAPI docs public by design → DROP. Public API endpoints in JS → DROP (normal for SPA). Server header (nginx/1.24) → DROP (normal).',
    impactProof: 'Show that exposed data could be used for fingerprinting, tracking, or targeted attacks. Non-destructive.',
  },

  // ── API Leak ──────────────────────────────────────────────────
  api_leak: {
    type: 'api_leak',
    proofRequired: 'REAL secret pattern (sk-/eyJ JWT/AKIA AWS/ghp_ GitHub/AIza Google/xox Slack) in response body, that is NOT a placeholder.',
    requests: [
      { method: 'GET', url: '{findingUrl}', description: 'Fetch page/JS bundle with potential secret' },
    ],
    responseComparison: 'Search response body for real secret patterns. Must match known credential format AND not be a test/placeholder value.',
    misconfigVsVuln: 'UUID/tracking ID in page = NOT a leak (DROP). Real API key in client-side code = vulnerability (critical).',
    inconclusiveCriteria: 'String looks like a secret but doesn\'t match known patterns (sk-/AKIA/etc.) → INCONCLUSIVE (might be custom format, need manual verification).',
    dropCriteria: 'No real secret pattern found, OR value is placeholder (test/example/demo/your_api_key), OR finding mentions UUID/identifier/tracking → DROP.',
    legitimateExclusion: 'Cloudflare Turnstile site key, Google Analytics ID, Stripe publishable key (pk_) → all PUBLIC by design → DROP.',
    impactProof: 'Show that the secret could be used to access protected resources. Do NOT actually use the key.',
  },

  // ── CORS Misconfiguration ────────────────────────────────────
  cors_misconfig: {
    type: 'cors_misconfig',
    proofRequired: 'Access-Control-Allow-Origin reflects arbitrary origin AND Access-Control-Allow-Credentials: true.',
    requests: [
      { method: 'GET', url: '{findingUrl}', headers: { 'Origin': 'https://evil.com' }, description: 'Arbitrary origin' },
      { method: 'GET', url: '{findingUrl}', headers: { 'Origin': 'https://attacker.example.com' }, description: 'Different origin' },
    ],
    responseComparison: 'Check ACAO header. Must reflect arbitrary origin (or be *) AND ACAC must be true. If ACAO is * but ACAC is false → DROP (public API, no impact).',
    misconfigVsVuln: 'ACAO: * without credentials = misconfiguration (low, normal for public API). ACAO reflects origin + ACAC: true = vulnerability (high).',
    inconclusiveCriteria: 'ACAO reflects some origins but not all → INCONCLUSIVE (need to test specific origin patterns).',
    dropCriteria: 'ACAO is specific (not *), OR ACAC is false, OR no CORS headers at all → DROP.',
    legitimateExclusion: 'ACAO: * with ACAC: false = public API by design → DROP. ACAO allowlist with trusted domains → DROP.',
    impactProof: 'Show that attacker website could read authenticated responses. Do NOT actually exfiltrate data.',
  },

  // ── CSP Missing ───────────────────────────────────────────────
  csp_missing: {
    type: 'csp_missing',
    proofRequired: 'Content-Security-Policy header is ABSENT in HTTP response headers.',
    requests: [],
    responseComparison: 'Check security headers. CSP must be absent. If CSP present (even weak) → DROP.',
    misconfigVsVuln: 'CSP absent = misconfiguration (medium, defense-in-depth weakness). CSP present but weak (unsafe-inline) = misconfiguration (low).',
    inconclusiveCriteria: 'CSP present but with unsafe-inline + unsafe-eval → INCONCLUSIVE (weak CSP, depends on XSS presence).',
    dropCriteria: 'CSP header present → DROP.',
    legitimateExclusion: 'CSP with unsafe-inline is common for SPAs with inline scripts → INCONCLUSIVE (not best practice but not exploitable alone).',
    impactProof: 'CSP absence alone has no direct impact. It amplifies XSS impact if XSS exists. Show as defense-in-depth weakness.',
  },

  // ── Clickjacking ─────────────────────────────────────────────
  clickjacking: {
    type: 'clickjacking',
    proofRequired: 'X-Frame-Options header is ABSENT AND page contains wallet/financial interactions.',
    requests: [],
    responseComparison: 'Check X-Frame-Options. Must be absent. If present (DENY/SAMEORIGIN) → DROP. Check HTML for wallet/financial actions (metamask, withdraw, approve).',
    misconfigVsVuln: 'X-Frame-Options absent on non-interactive page = misconfiguration (low). Absent on wallet/financial page = vulnerability (medium).',
    inconclusiveCriteria: 'X-Frame-Options absent but page has no sensitive interactions → INCONCLUSIVE (low impact).',
    dropCriteria: 'X-Frame-Options present → DROP. Page has no interactive elements → DROP.',
    legitimateExclusion: 'CSP frame-ancestors directive present (modern replacement for X-Frame-Options) → DROP.',
    impactProof: 'Show that page could be iframed by attacker. Do NOT actually create malicious iframe.',
  },

  // ── Subdomain Takeover ───────────────────────────────────────
  subdomain_takeover: {
    type: 'subdomain_takeover',
    proofRequired: 'DNS CNAME to cloud service + cloud resource is UNCLAIMED (dangling) + application uses this subdomain.',
    requests: [
      { method: 'DNS', url: '{subdomain}', description: 'CNAME lookup' },
      { method: 'GET', url: 'https://{subdomain}', description: 'Check if resource is claimed or dangling' },
    ],
    responseComparison: 'CNAME must point to cloud service (S3/Heroku/GitHub Pages). HTTP response must show "NoSuchBucket"/"Repository not found"/"no GitHub Pages site here".',
    misconfigVsVuln: 'Fallback domains in HTML = misconfiguration (low, potential risk). DNS CNAME to dangling resource = vulnerability (high).',
    inconclusiveCriteria: 'DNS lookup fails or CNAME doesn\'t point to known cloud service → INCONCLUSIVE (can\'t verify without DNS, need manual check).',
    dropCriteria: 'No CNAME, OR CNAME points to active/claimed resource, OR subdomain doesn\'t resolve → DROP.',
    legitimateExclusion: 'Subdomain resolves to active CDN/app (resource claimed) → DROP. Fallback domains that are registered and active → DROP.',
    impactProof: 'Show that attacker could claim the dangling resource and serve content in application\'s context. Do NOT actually claim it.',
  },

  // ── Command Injection ────────────────────────────────────────
  command_injection: {
    type: 'command_injection',
    proofRequired: 'Response contains output of OS command (uid= for id) OR response time ≥3s for sleep.',
    requests: [
      { method: 'GET', url: '{targetUrl}?{param}=;id', description: 'id command' },
      { method: 'GET', url: '{targetUrl}?{param}=|whoami', description: 'whoami command' },
      { method: 'GET', url: '{targetUrl}?{param}=;sleep 3', description: 'sleep (blind)' },
    ],
    responseComparison: 'Response must contain uid=...gid=... (id output) OR response time ≥3s for sleep. If neither → DROP.',
    misconfigVsVuln: 'OS command execution = vulnerability (critical). No command execution → DROP.',
    inconclusiveCriteria: 'Response time slightly slower (1-2s) but not ≥3s → INCONCLUSIVE (might be slow server).',
    dropCriteria: 'No command output, no time delay → DROP.',
    legitimateExclusion: 'Parameter is used in safe way (e.g., argument to library function, not shell) → DROP.',
    impactProof: 'id/whoami output is non-destructive. Do NOT run rm/wget/curl.',
  },

  // ── SSTI ──────────────────────────────────────────────────────
  ssti: {
    type: 'ssti',
    proofRequired: 'Response contains evaluated result of template expression (7*7=49, not the literal {{7*7}}).',
    requests: [
      { method: 'GET', url: '{targetUrl}?{param}={{7*7}}', description: 'Jinja2/Twig expression' },
      { method: 'GET', url: '{targetUrl}?{param}=${7*7}', description: 'FreeMarker/Velocity expression' },
      { method: 'GET', url: '{targetUrl}?{param}=#{7*7}', description: 'Ruby ERB expression' },
    ],
    responseComparison: 'Response must contain "49" (evaluated result) but NOT contain "{{7*7}}" (literal). If response contains {{7*7}} literally → DROP (not evaluated).',
    misconfigVsVuln: 'Template engine error message = misconfiguration (low). Expression evaluated = vulnerability (critical, can lead to RCE).',
    inconclusiveCriteria: 'Response changes when expression injected but no "49" → INCONCLUSIVE (might be partial evaluation).',
    dropCriteria: 'No "49" in response, OR response contains literal {{7*7}} → DROP.',
    legitimateExclusion: 'Parameter is not used in template context → DROP.',
    impactProof: '7*7=49 is non-destructive. Shows template engine evaluates expressions. Do NOT inject RCE payloads.',
  },

  // ── NoSQL Injection ──────────────────────────────────────────
  nosql_injection: {
    type: 'nosql_injection',
    proofRequired: 'Response with $ne/$gt operator differs from normal response, indicating operator injection works.',
    requests: [
      { method: 'GET', url: '{targetUrl}?{param}={"$ne":null}', description: '$ne operator' },
      { method: 'GET', url: '{targetUrl}?{param}={"$gt":""}', description: '$gt operator' },
    ],
    responseComparison: 'Compare response with operator vs. without. If different (more data, different user, bypassed auth) → confirmed. If same → DROP.',
    misconfigVsVuln: 'Operator accepted but same data returned = misconfiguration (low). Operator returns different/unauthorized data = vulnerability (critical).',
    inconclusiveCriteria: 'Response differs but can\'t determine if data is unauthorized → INCONCLUSIVE.',
    dropCriteria: 'Operator rejected or same response as normal → DROP.',
    legitimateExclusion: 'Parameter is not used in NoSQL query → DROP.',
    impactProof: 'Show that auth bypass or data extraction would work. Do NOT extract real user data.',
  },

  // ── GraphQL Introspection ───────────────────────────────────
  graphql_introspection: {
    type: 'graphql_introspection',
    proofRequired: 'GraphQL endpoint returns schema introspection result (types, fields, queries, mutations).',
    requests: [
      { method: 'POST', url: '{targetUrl}/graphql', body: '{"query":"{__schema{types{name fields{name type{name}}}}}"}', headers: { 'Content-Type': 'application/json' }, description: 'Introspection query' },
    ],
    responseComparison: 'Response must contain "__schema" with types/fields. If response is error or doesn\'t contain __schema → DROP.',
    misconfigVsVuln: 'Introspection enabled in production = misconfiguration (low/medium). Introspection reveals admin mutations = vulnerability (medium).',
    inconclusiveCriteria: 'GraphQL endpoint responds but introspection is disabled → INCONCLUSIVE (endpoint exists but can\'t verify schema exposure).',
    dropCriteria: 'No GraphQL endpoint, OR introspection explicitly disabled, OR response is not GraphQL → DROP.',
    legitimateExclusion: 'Introspection enabled on public GraphQL API (e.g., SpaceX API) → DROP (by design).',
    impactProof: 'Show that schema reveals internal types/queries. Non-destructive.',
  },

  // ── IDOR ─────────────────────────────────────────────────────
  idor: {
    type: 'idor',
    proofRequired: 'Accessing /api/user/{id1} returns user1 data. Accessing /api/user/{id2} returns user2 data. Both WITHOUT auth. Data belongs to DIFFERENT users.',
    requests: [
      { method: 'GET', url: '{targetUrl}/api/user/1', description: 'User 1 data' },
      { method: 'GET', url: '{targetUrl}/api/user/2', description: 'User 2 data' },
    ],
    responseComparison: 'Both responses must return user-specific data (different userIds/emails). If both return same demo data → DROP. If both return same user → DROP.',
    misconfigVsVuln: 'Sequential IDs in URLs = misconfiguration (low). Accessing other user\'s data without auth = vulnerability (high).',
    inconclusiveCriteria: 'Can\'t find two different user IDs to test → INCONCLUSIVE (need more user IDs).',
    dropCriteria: 'Both requests return same data, OR endpoint requires auth, OR data is public by design → DROP.',
    legitimateExclusion: 'Public profile pages (e.g., /user/john) with public data → DROP.',
    impactProof: 'Show that different user IDs return different user data. Do NOT modify any user data.',
  },

  // ── JWT alg:none ─────────────────────────────────────────────
  jwt_none_alg: {
    type: 'jwt_none_alg',
    proofRequired: 'Server accepts JWT with alg:none (no signature) and returns authenticated response.',
    requests: [
      { method: 'GET', url: '{targetUrl}/api/me', headers: { 'Authorization': 'Bearer {forged_none_jwt}' }, description: 'Forged JWT with alg:none' },
      { method: 'GET', url: '{targetUrl}/api/me', description: 'No auth (baseline)' },
    ],
    responseComparison: 'Forged JWT response must return authenticated data (200 with user data). Baseline must return 401/403. If both 401 → DROP. If both 200 → INCONCLUSIVE (endpoint is public).',
    misconfigVsVuln: 'JWT library accepts alg:none = vulnerability (critical). JWT library rejects alg:none → DROP.',
    inconclusiveCriteria: 'Server accepts malformed JWT but can\'t determine if it\'s authenticated → INCONCLUSIVE.',
    dropCriteria: 'Server rejects alg:none JWT with 401/403 → DROP.',
    legitimateExclusion: 'Server uses stateless JWT with explicit alg allowlist → DROP.',
    impactProof: 'Show that forged JWT is accepted. Do NOT escalate privileges or modify data.',
  },

  // ── Business Logic ──────────────────────────────────────────
  business_logic: {
    type: 'business_logic',
    proofRequired: 'Sequence of requests demonstrates that business rule can be bypassed (e.g., negative amount, race condition, step skipping).',
    requests: [
      { method: 'POST', url: '{targetUrl}/api/withdraw', body: '{"amount":-100}', description: 'Negative amount' },
      { method: 'POST', url: '{targetUrl}/api/order', body: '{"price":0}', description: 'Zero price' },
    ],
    responseComparison: 'Response must show successful operation with abnormal input (negative amount, zero price). If error/rejection → DROP.',
    misconfigVsVuln: 'Missing input validation = misconfiguration (medium). Successful operation with malicious input = vulnerability (critical).',
    inconclusiveCriteria: 'Response is ambiguous (200 but unclear if operation actually executed) → INCONCLUSIVE.',
    dropCriteria: 'Request rejected with validation error → DROP.',
    legitimateExclusion: 'Amount is validated server-side and rejected → DROP.',
    impactProof: 'Show that malicious input is accepted. Do NOT actually withdraw/transfer funds.',
  },

  // ── Stored XSS ───────────────────────────────────────────────
  stored_xss: {
    type: 'stored_xss',
    proofRequired: 'Payload submitted via one request appears VERBATIM in another request\'s response (persisted across requests).',
    requests: [
      { method: 'POST', url: '{targetUrl}/api/comment', body: '{"text":"<script>alert(1)</script>"}', description: 'Submit XSS payload' },
      { method: 'GET', url: '{targetUrl}/comments', description: 'View where payload would appear' },
    ],
    responseComparison: 'GET response must contain <script>alert(1)</script> verbatim. If escaped or not present → DROP.',
    misconfigVsVuln: 'Payload stored but escaped = misconfiguration (low). Payload stored and rendered as HTML = vulnerability (high).',
    inconclusiveCriteria: 'Can\'t find where payload is rendered → INCONCLUSIVE (might be stored but not visible).',
    dropCriteria: 'Payload not stored, OR not rendered, OR escaped → DROP.',
    legitimateExclusion: 'Input is sanitized before storage (HTMLPurifier, DOMPurify) → DROP.',
    impactProof: 'Show that payload persists across requests. Do NOT inject actual malicious script.',
  },

  // ── HTTP Smuggling ───────────────────────────────────────────
  http_smuggling: {
    type: 'http_smuggling',
    proofRequired: 'Two requests with CL.TE or TE.CL discrepancy cause response from another user\'s request to be served.',
    requests: [
      { method: 'POST', url: '{targetUrl}', headers: { 'Content-Length': '13', 'Transfer-Encoding': 'chunked' }, body: '0\r\n\r\nSMUGGLED', description: 'CL.TE smuggling attempt' },
    ],
    responseComparison: 'If subsequent requests return unexpected data (from smuggled request) → confirmed. If normal responses → DROP.',
    misconfigVsVuln: 'Frontend/backend disagree on TE/CL = vulnerability (high). Consistent TE/CL handling → DROP.',
    inconclusiveCriteria: 'Can\'t determine if smuggling worked (responses look normal) → INCONCLUSIVE (need timing analysis).',
    dropCriteria: 'Both TE and CL handled consistently → DROP.',
    legitimateExclusion: 'Server rejects requests with both TE and CL → DROP (secure behavior).',
    impactProof: 'Show that smuggled request reaches backend. Do NOT inject actual malicious content.',
  },

  // ── DEFAULT: unimplemented types ─────────────────────────────
  _default: {
    type: '_default',
    proofRequired: 'No type-specific proof contract defined. Cannot confirm without manual verification.',
    requests: [],
    responseComparison: 'N/A — no proof contract.',
    misconfigVsVuln: 'Unknown — depends on specific vulnerability class.',
    inconclusiveCriteria: 'Finding type has no automated proof contract → always INCONCLUSIVE (need manual verification).',
    dropCriteria: 'N/A — INCONCLUSIVE is the default for unimplemented types.',
    legitimateExclusion: 'N/A.',
    impactProof: 'N/A — manual verification required.',
  },
};

/**
 * Get the proof contract for a finding type.
 * Returns _default if no specific contract exists.
 */
export function getProofContract(type: string): ProofContract {
  return PROOF_CONTRACTS[type.toLowerCase()] || PROOF_CONTRACTS._default;
}
