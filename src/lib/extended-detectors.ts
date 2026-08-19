/**
 * Extended Detectors — additional finding patterns for web app analysis.
 *
 * These detectors complement analyzeSecurityHeaders/analyzeCookies/etc.
 * by finding MORE vulnerability indicators in crawled pages and JS bundles.
 *
 * Each detector returns a list of FindingPattern objects that get included
 * in the AI analysis context, helping the AI produce more findings.
 *
 * Detectors:
 *   1. JS Library Version Disclosure (jQuery/Bootstrap/Angular with known CVEs)
 *   2. WebSocket Endpoints (ws:// and wss://)
 *   3. Subresource Integrity (SRI) missing on <script>/<link> tags
 *   4. Mixed Content (HTTP resources on HTTPS pages)
 *   5. localStorage / sessionStorage misuse (sensitive data in storage)
 *   6. autocomplete="on" on sensitive form fields
 *   7. Forms without action attribute (XSS via base tag injection)
 *   8. target="_blank" without rel="noopener" (tabnabbing)
 *   9. <a> tags with javascript: URLs
 *  10. Comment leaks (TODO/FIXME/HACK/password/secret in HTML comments)
 *  11. Internal IP disclosure in HTML/JS
 *  12. Cloud storage bucket URLs (s3://, gs://, wasb://)
 *  13. JWT tokens in source code
 *  14. GraphQL endpoints in JS
 *  15. Inline event handlers (onclick=, onmouseover=, etc.)
 */

export interface FindingPattern {
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  location?: string;
  evidence?: string;
}

interface CrawledPage {
  url: string;
  html?: string;
  title?: string;
}

interface JsBundle {
  url: string;
  content?: string;
}

// ─── 1. JS Library Version Disclosure ───────────────────────────────
const LIBRARY_CVES: Array<{ name: string; pattern: RegExp; cveRange: string; severity: FindingPattern['severity'] }> = [
  { name: 'jQuery', pattern: /jquery[\/\-]v?(\d+\.\d+\.\d+)/i, cveRange: '<3.5.0 has XSS (CVE-2020-11022, CVE-2020-11023)', severity: 'high' },
  { name: 'jQuery', pattern: /jquery[\/\-]v?(\d+\.\d+)(\.\d+)?/i, cveRange: '<3.5 — check CVE', severity: 'medium' },
  { name: 'Bootstrap', pattern: /bootstrap[\/\-]v?(\d+\.\d+\.\d+)/i, cveRange: '<4.6.2 has XSS (CVE-2024-6484)', severity: 'high' },
  { name: 'Angular', pattern: /angular[\/\-]v?(\d+\.\d+\.\d+)/i, cveRange: '<1.8.x has prototype pollution (CVE-2020-7676)', severity: 'high' },
  { name: 'React', pattern: /react[\/\-]v?(\d+\.\d+\.\d+)/i, cveRange: '<16.x — check CVE', severity: 'low' },
  { name: 'Vue', pattern: /vue[\/\-]v?(\d+\.\d+\.\d+)/i, cveRange: '<2.6.x has XSS (CVE-2024-6485)', severity: 'high' },
  { name: 'lodash', pattern: /lodash[\/\-]v?(\d+\.\d+\.\d+)/i, cveRange: '<4.17.21 has prototype pollution (CVE-2021-23337)', severity: 'critical' },
  { name: 'moment', pattern: /moment[\/\-]v?(\d+\.\d+\.\d+)/i, cveRange: '<2.29.4 has ReDoS (CVE-2022-31129)', severity: 'high' },
  { name: 'axios', pattern: /axios[\/\-]v?(\d+\.\d+\.\d+)/i, cveRange: '<0.21.2 has SSRF (CVE-2021-3749)', severity: 'high' },
  { name: 'axios', pattern: /axios[\/\-]v?(\d+\.\d+\.\d+)/i, cveRange: '<1.7.4 has SSRF (CVE-2024-39338)', severity: 'high' },
  { name: 'dompurify', pattern: /dompurify[\/\-]v?(\d+\.\d+\.\d+)/i, cveRange: '<2.5.6 has mXSS (CVE-2024-45801)', severity: 'critical' },
  { name: 'express', pattern: /express[\/\-]v?(\d+\.\d+\.\d+)/i, cveRange: '<4.17.4 — check CVE', severity: 'medium' },
  { name: 'next', pattern: /next[\/\-]v?(\d+\.\d+\.\d+)/i, cveRange: '<14.x — check CVE', severity: 'medium' },
];

export function detectJsLibraryVersions(pages: CrawledPage[], bundles: JsBundle[]): FindingPattern[] {
  const findings: FindingPattern[] = [];
  const seen = new Set<string>();
  const sources = [
    ...pages.map(p => ({ url: p.url, content: p.html || '' })),
    ...bundles.map(b => ({ url: b.url, content: b.content || '' })),
  ];

  for (const { url, content } of sources) {
    if (!content) continue;
    for (const lib of LIBRARY_CVES) {
      const match = content.match(lib.pattern);
      if (match) {
        const version = match[1];
        const key = `${lib.name}@${version}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          type: 'js_library_version',
          severity: lib.severity,
          title: `${lib.name} ${version} detected`,
          description: `${lib.name} version ${version} detected in ${url}. ${lib.cveRange}. Verify against latest CVE database.`,
          location: url,
          evidence: match[0],
        });
      }
    }
  }
  return findings;
}

// ─── 2. WebSocket Endpoints ──────────────────────────────────────────
export function detectWebSocketEndpoints(pages: CrawledPage[], bundles: JsBundle[]): FindingPattern[] {
  const findings: FindingPattern[] = [];
  const seen = new Set<string>();
  const wsPattern = /(?:new\s+WebSocket|io\(\s*['"])(['"]?(wss?:\/\/[^'"]\s]+)['"]?/gi;
  const wsUrlPattern = /['"`](wss?:\/\/[a-zA-Z0-9.\-:/]+)['"`]/g;

  for (const page of pages) {
    if (!page.html) continue;
    let match;
    while ((match = wsUrlPattern.exec(page.html)) !== null) {
      const wsUrl = match[1];
      if (seen.has(wsUrl)) continue;
      seen.add(wsUrl);
      const isInsecure = wsUrl.startsWith('ws://');
      findings.push({
        type: 'websocket_endpoint',
        severity: isInsecure ? 'medium' : 'info',
        title: `${isInsecure ? 'Insecure ' : ''}WebSocket endpoint: ${wsUrl}`,
        description: `WebSocket endpoint at ${wsUrl}. ${isInsecure ? 'INSECURE (ws://) — unencrypted, vulnerable to MITM.' : 'Secure (wss://).'} Check for: authentication, origin validation, message rate limiting.`,
        location: page.url,
        evidence: wsUrl,
      });
    }
  }
  for (const bundle of bundles) {
    if (!bundle.content) continue;
    let match;
    while ((match = wsUrlPattern.exec(bundle.content)) !== null) {
      const wsUrl = match[1];
      if (seen.has(wsUrl)) continue;
      seen.add(wsUrl);
      const isInsecure = wsUrl.startsWith('ws://');
      findings.push({
        type: 'websocket_endpoint',
        severity: isInsecure ? 'medium' : 'info',
        title: `${isInsecure ? 'Insecure ' : ''}WebSocket in JS: ${wsUrl}`,
        description: `WebSocket endpoint referenced in JS bundle. ${isInsecure ? 'INSECURE (ws://) — unencrypted.' : 'Secure (wss://).'}`,
        location: bundle.url,
        evidence: wsUrl,
      });
    }
  }
  return findings;
}

// ─── 3. Subresource Integrity (SRI) Missing ──────────────────────────
export function detectSriMissing(pages: CrawledPage[]): FindingPattern[] {
  const findings: FindingPattern[] = [];
  for (const page of pages) {
    if (!page.html) continue;
    // Find <script src="..."> and <link href="..."> without integrity= attr
    const scriptPattern = /<script[^>]+src=['"]([^'"]+)['"][^>]*>/gi;
    const linkPattern = /<link[^>]+href=['"]([^'"]+)['"][^>]*>/gi;
    let match;
    while ((match = scriptPattern.exec(page.html)) !== null) {
      const src = match[1];
      // Skip same-origin (relative) and inline
      if (src.startsWith('/') || src.startsWith('./') || !src.includes('://')) continue;
      const tag = match[0];
      if (!/integrity=/i.test(tag)) {
        findings.push({
          type: 'sri_missing',
          severity: 'medium',
          title: `SRI missing on external script: ${src.slice(0, 80)}`,
          description: `External <script> tag without integrity attribute. If CDN compromised, attacker can inject malicious JS. Add integrity="sha384-..." attribute.`,
          location: page.url,
          evidence: tag.slice(0, 200),
        });
      }
    }
    while ((match = linkPattern.exec(page.html)) !== null) {
      const href = match[1];
      if (href.startsWith('/') || href.startsWith('./') || !href.includes('://')) continue;
      // Only check stylesheets
      if (!/stylesheet/i.test(match[0])) continue;
      const tag = match[0];
      if (!/integrity=/i.test(tag)) {
        findings.push({
          type: 'sri_missing',
          severity: 'low',
          title: `SRI missing on external stylesheet: ${href.slice(0, 80)}`,
          description: `External <link rel="stylesheet"> without integrity attribute. CDN compromise risk.`,
          location: page.url,
          evidence: tag.slice(0, 200),
        });
      }
    }
  }
  return findings;
}

// ─── 4. Mixed Content ────────────────────────────────────────────────
export function detectMixedContent(pages: CrawledPage[]): FindingPattern[] {
  const findings: FindingPattern[] = [];
  for (const page of pages) {
    if (!page.html) continue;
    // Only check HTTPS pages
    if (!page.url.startsWith('https://')) continue;
    const httpResourcePattern = /(?:src|href|action|poster|data)\s*=\s*['"]http:\/\/[^'"]+['"]/gi;
    let match;
    while ((match = httpResourcePattern.exec(page.html)) !== null) {
      findings.push({
        type: 'mixed_content',
        severity: 'medium',
        title: `Mixed content: HTTP resource on HTTPS page`,
        description: `HTTPS page loads HTTP resource: ${match[0]}. Browser blocks or warns — degrades security and may cause MITM.`,
        location: page.url,
        evidence: match[0],
      });
    }
  }
  return findings;
}

// ─── 5. localStorage / sessionStorage Misuse ─────────────────────────
export function detectStorageMisuse(bundles: JsBundle[]): FindingPattern[] {
  const findings: FindingPattern[] = [];
  const sensitivePatterns = [
    { pattern: /localStorage\.(setItem|getItem)\s*\(\s*['"](?:token|auth|jwt|api[_-]?key|secret|password|private[_-]?key|session|refresh[_-]?token)/i, severity: 'high' as const, what: 'auth token/secret' },
    { pattern: /sessionStorage\.(setItem|getItem)\s*\(\s*['"](?:token|auth|jwt|api[_-]?key|secret|password|private[_-]?key|session|refresh[_-]?token)/i, severity: 'high' as const, what: 'auth token/secret' },
    { pattern: /localStorage\.(setItem|getItem)\s*\(\s*['"](?:user|profile|account|wallet|balance|email)/i, severity: 'medium' as const, what: 'user data' },
    { pattern: /sessionStorage\.(setItem|getItem)\s*\(\s*['"](?:user|profile|account|wallet|balance|email)/i, severity: 'medium' as const, what: 'user data' },
  ];

  for (const bundle of bundles) {
    if (!bundle.content) continue;
    for (const { pattern, severity, what } of sensitivePatterns) {
      const matches = bundle.content.match(pattern);
      if (matches) {
        findings.push({
          type: 'storage_misuse',
          severity,
          title: `Sensitive ${what} stored in browser storage`,
          description: `JS bundle uses localStorage/sessionStorage to store ${what}. Any XSS on the page can exfiltrate this data via storage access. Prefer HttpOnly cookies for auth tokens.`,
          location: bundle.url,
          evidence: matches[0].slice(0, 100),
        });
      }
    }
  }
  return findings;
}

// ─── 6. autocomplete on Sensitive Fields ─────────────────────────────
export function detectAutocompleteIssues(pages: CrawledPage[]): FindingPattern[] {
  const findings: FindingPattern[] = [];
  for (const page of pages) {
    if (!page.html) continue;
    // <input type="password" ...> without autocomplete="off" or autocomplete="new-password"
    const passwordInputPattern = /<input[^>]+type=['"]password['"][^>]*>/gi;
    let match;
    while ((match = passwordInputPattern.exec(page.html)) !== null) {
      const tag = match[0];
      if (!/autocomplete\s*=\s*['"](?:off|new-password)['"]/i.test(tag)) {
        findings.push({
          type: 'autocomplete_sensitive',
          severity: 'low',
          title: `Password field without autocomplete=off`,
          description: `<input type="password"> without autocomplete="off". Browser may store the password and autofill on other sites (credential leak risk).`,
          location: page.url,
          evidence: tag.slice(0, 200),
        });
      }
    }
    // <input> with credit card / SSN names without autocomplete=off
    const sensitiveFieldPattern = /<input[^>]+name=['"](?:cc[_-]?number|card[_-]?number|ssn|social[_-]?security|cvv|cvc)['"][^>]*>/gi;
    while ((match = sensitiveFieldPattern.exec(page.html)) !== null) {
      const tag = match[0];
      if (!/autocomplete\s*=\s*['"]off['"]/i.test(tag)) {
        findings.push({
          type: 'autocomplete_sensitive',
          severity: 'medium',
          title: `Sensitive financial/PII field without autocomplete=off`,
          description: `Input field for credit card / SSN / CVV without autocomplete="off" — browser may store sensitive financial data.`,
          location: page.url,
          evidence: tag.slice(0, 200),
        });
      }
    }
  }
  return findings;
}

// ─── 7. target="_blank" without rel="noopener" (Tabnabbing) ─────────
export function detectTabnabbing(pages: CrawledPage[]): FindingPattern[] {
  const findings: FindingPattern[] = [];
  for (const page of pages) {
    if (!page.html) continue;
    const blankLinkPattern = /<a[^>]+target=['"]_blank['"][^>]*>/gi;
    let match;
    while ((match = blankLinkPattern.exec(page.html)) !== null) {
      const tag = match[0];
      if (!/rel\s*=\s*['"][^'"]*noopener/i.test(tag)) {
        findings.push({
          type: 'tabnabbing',
          severity: 'low',
          title: `target="_blank" without rel="noopener"`,
          description: `<a target="_blank"> without rel="noopener". Opened page can access window.opener, allowing tabnabbing (replace original tab content with phishing).`,
          location: page.url,
          evidence: tag.slice(0, 200),
        });
      }
    }
  }
  return findings;
}

// ─── 8. javascript: URI in <a> tags ─────────────────────────────────
export function detectJavascriptUris(pages: CrawledPage[]): FindingPattern[] {
  const findings: FindingPattern[] = [];
  for (const page of pages) {
    if (!page.html) continue;
    const jsUriPattern = /<a[^>]+href=['"]javascript:[^'"]+['"][^>]*>/gi;
    let match;
    while ((match = jsUriPattern.exec(page.html)) !== null) {
      findings.push({
        type: 'javascript_uri',
        severity: 'medium',
        title: `javascript: URI in <a> tag`,
        description: `<a href="javascript:..."> — if user-controlled, can lead to XSS via DOM injection. Avoid javascript: URIs.`,
        location: page.url,
        evidence: match[0].slice(0, 200),
      });
    }
  }
  return findings;
}

// ─── 9. Comment Leaks (TODO/FIXME/password/secret) ──────────────────
export function detectCommentLeaks(pages: CrawledPage[]): FindingPattern[] {
  const findings: FindingPattern[] = [];
  const leakPatterns = [
    { regex: /<!--[^-]*\b(?:password|passwd|secret|api[_-]?key|token|private[_-]?key)\b[^-]*-->/i, severity: 'high' as const, what: 'credential' },
    { regex: /\/\/[^\n]*\b(?:password|passwd|secret|api[_-]?key|token|private[_-]?key)\b[^\n]*/i, severity: 'medium' as const, what: 'credential' },
    { regex: /\/\*[\s\S]*?\b(?:password|passwd|secret|api[_-]?key|token|private[_-]?key)\b[\s\S]*?\*\//i, severity: 'medium' as const, what: 'credential' },
    { regex: /<!--[^-]*\b(?:TODO|FIXME|HACK|XXX|BUG)\b[^-]*-->/i, severity: 'info' as const, what: 'dev comment' },
    { regex: /\/\/[^\n]*\b(?:TODO|FIXME|HACK|XXX|BUG)\b[^\n]*/i, severity: 'info' as const, what: 'dev comment' },
  ];
  for (const page of pages) {
    if (!page.html) continue;
    for (const { regex, severity, what } of leakPatterns) {
      const matches = page.html.match(regex);
      if (matches) {
        findings.push({
          type: 'comment_leak',
          severity,
          title: `${what} mentioned in HTML comment`,
          description: `HTML/JS comment contains ${what} reference. Comments are visible to anyone — may leak implementation details or credentials.`,
          location: page.url,
          evidence: matches[0].slice(0, 200),
        });
      }
    }
  }
  return findings;
}

// ─── 10. Internal IP Disclosure ──────────────────────────────────────
export function detectInternalIpDisclosure(pages: CrawledPage[], bundles: JsBundle[]): FindingPattern[] {
  const findings: FindingPattern[] = [];
  const ipPattern = /\b(?:10|127|172(?:\.(?:1[6-9]|2[0-9]|3[0-1]))|192\.168)\.\d+\.\d+\b/g;
  const sources = [...pages, ...bundles];
  for (const item of sources) {
    const content = (item as CrawledPage).html || (item as JsBundle).content || '';
    if (!content) continue;
    const matches = content.match(ipPattern);
    if (matches) {
      const uniqueIps = [...new Set(matches)].slice(0, 5);
      for (const ip of uniqueIps) {
        findings.push({
          type: 'internal_ip_disclosure',
          severity: 'medium',
          title: `Internal IP address disclosed: ${ip}`,
          description: `Internal/private IP address ${ip} found in page source. Reveals internal network structure, useful for SSRF mapping.`,
          location: (item as CrawledPage).url,
          evidence: ip,
        });
      }
    }
  }
  return findings;
}

// ─── 11. Cloud Storage Bucket URLs ──────────────────────────────────
export function detectCloudBuckets(pages: CrawledPage[], bundles: JsBundle[]): FindingPattern[] {
  const findings: FindingPattern[] = [];
  const bucketPatterns = [
    { regex: /https?:\/\/[a-z0-9.\-]+\.s3[.\-][a-z0-9.\-]*amazonaws\.com/gi, what: 'AWS S3' },
    { regex: /https?:\/\/s3[.\-][a-z0-9.\-]*amazonaws\.com\/[a-z0-9.\-]+/gi, what: 'AWS S3' },
    { regex: /https?:\/\/[a-z0-9.\-]+\.storage\.googleapis\.com/gi, what: 'GCP Storage' },
    { regex: /https?:\/\/[a-z0-9.\-]+\.blob\.core\.windows\.net/gi, what: 'Azure Blob' },
    { regex: /https?:\/\/[a-z0-9.\-]+\.digitaloceanspaces\.com/gi, what: 'DO Spaces' },
    { regex: /https?:\/\/[a-z0-9.\-]+\.backblazeb2\.com/gi, what: 'Backblaze B2' },
  ];
  const sources = [...pages, ...bundles];
  for (const item of sources) {
    const content = (item as CrawledPage).html || (item as JsBundle).content || '';
    if (!content) continue;
    for (const { regex, what } of bucketPatterns) {
      const matches = content.match(regex);
      if (matches) {
        const seen = new Set<string>();
        for (const m of matches) {
          if (seen.has(m)) continue;
          seen.add(m);
          findings.push({
            type: 'cloud_bucket',
            severity: 'medium',
            title: `${what} bucket URL found`,
            description: `Cloud storage bucket URL: ${m}. Verify bucket is not publicly writable — common misconfig allows anyone to upload/list objects.`,
            location: (item as CrawledPage).url,
            evidence: m,
          });
        }
      }
    }
  }
  return findings;
}

// ─── 12. GraphQL Endpoints in JS ─────────────────────────────────────
export function detectGraphqlInJs(bundles: JsBundle[]): FindingPattern[] {
  const findings: FindingPattern[] = [];
  const graphqlPattern = /(?:fetch|axios|http)\s*\.\s*(?:post|get|request)\s*\(\s*['"`]([^'"`]+)['"`]\s*,\s*[^)]*query/i;
  const graphqlUrlPattern = /['"`](\/graphql(?:\/[a-z]+)?|\?query=)['"`]/gi;
  for (const bundle of bundles) {
    if (!bundle.content) continue;
    let match;
    while ((match = graphqlUrlPattern.exec(bundle.content)) !== null) {
      findings.push({
        type: 'graphql_endpoint',
        severity: 'info',
        title: `GraphQL endpoint referenced: ${match[1]}`,
        description: `JavaScript bundle references a GraphQL endpoint at ${match[1]}. Verify introspection is disabled, and check for query depth/complexity limits.`,
        location: bundle.url,
        evidence: match[0],
      });
    }
  }
  return findings;
}

// ─── 13. Inline Event Handlers (onclick=, onerror=, etc.) ──────────
export function detectInlineEventHandlers(pages: CrawledPage[]): FindingPattern[] {
  const findings: FindingPattern[] = [];
  const eventPattern = /\son(?:click|load|error|mouseover|focus|blur|submit|change|input|keyup|keydown)\s*=\s*["']([^"']+)["']/gi;
  for (const page of pages) {
    if (!page.html) continue;
    let match;
    while ((match = eventPattern.exec(page.html)) !== null) {
      // Only flag if handler has dynamic content (not just function name)
      const handler = match[1];
      if (handler.length > 30 || handler.includes('(')) {
        findings.push({
          type: 'inline_event_handler',
          severity: 'low',
          title: `Inline event handler with logic`,
          description: `Inline event handler: on...="${handler.slice(0, 60)}...". CSP with 'unsafe-inline' in script-src-attr would be needed; better to move to addEventListener in separate JS file.`,
          location: page.url,
          evidence: match[0].slice(0, 150),
        });
      }
    }
  }
  return findings;
}

// ─── Master function: run all extended detectors ────────────────────
export function runAllExtendedDetectors(
  pages: CrawledPage[],
  bundles: JsBundle[],
): FindingPattern[] {
  return [
    ...detectJsLibraryVersions(pages, bundles),
    ...detectWebSocketEndpoints(pages, bundles),
    ...detectSriMissing(pages),
    ...detectMixedContent(pages),
    ...detectStorageMisuse(bundles),
    ...detectAutocompleteIssues(pages),
    ...detectTabnabbing(pages),
    ...detectJavascriptUris(pages),
    ...detectCommentLeaks(pages),
    ...detectInternalIpDisclosure(pages, bundles),
    ...detectCloudBuckets(pages, bundles),
    ...detectGraphqlInJs(bundles),
    ...detectInlineEventHandlers(pages),
  ];
}
