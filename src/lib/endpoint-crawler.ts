/**
 * Simple endpoint crawler — parse HTML/JS for /api/* patterns.
 *
 * Per Claude §3: "Атакуемая поверхность = 32K chars статичного HTML без
 * JS execution. Uniswap/MetaMask/OpenSea — SPA. Уязвимости в runtime DOM,
 * в API /v1/..., в wallet-connect flow. Их нет в первом HTML-снимке."
 *
 * This crawler discovers API endpoints from the homepage HTML + inline JS.
 * Found endpoints are passed to active-fuzzer for probing.
 *
 * Limitations (acknowledged):
 *   - Doesn't execute JS (no Playwright/browser) — only static extraction
 *   - Doesn't fetch linked JS bundles (would need additional HTTP calls)
 *   - Only sees what's in the 30K char HTML slice we already fetched
 *   - Real crawler would need authenticated session for /admin/* etc.
 */

export interface DiscoveredEndpoint {
  url: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'unknown';
  parameter: string | null;  // query param name if any
  source: 'href' | 'fetch_call' | 'axios_call' | 'form_action' | 'comment';
  confidence: number;  // 0-1
}

const API_PATTERN = /(?:https?:)?\/\/[a-z0-9.-]+\/(?:api|v[0-9]+)\/[a-z0-9/_-]+/gi;
const RELATIVE_API_PATTERN = /(?:["'`])(\/(?:api|v[0-9]+)\/[a-z0-9/_?&=-]+)(?:["'`])/gi;
const FETCH_CALL_PATTERN = /fetch\s*\(\s*['"`]([^'"`]+)['"`]/g;
const AXIOS_CALL_PATTERN = /axios\.(?:get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/gi;
const HREF_PATTERN = /href=["']([^"']+)["']/gi;
const FORM_ACTION_PATTERN = /<form[^>]*action=["']([^"']+)["']/gi;

/**
 * Crawl source code for API endpoints and parameters.
 * Returns deduplicated list of discovered endpoints.
 */
export function crawlForEndpoints(sourceCode: string, baseUrl: string): DiscoveredEndpoint[] {
  const endpoints: DiscoveredEndpoint[] = [];
  const seen = new Set<string>();

  // 1. Absolute API URLs (https://api.example.com/v1/users)
  let match: RegExpExecArray | null;
  API_PATTERN.lastIndex = 0;
  while ((match = API_PATTERN.exec(sourceCode)) !== null) {
    const url = match[0];
    if (seen.has(url)) continue;
    seen.add(url);
    endpoints.push({
      url,
      method: 'unknown',
      parameter: null,
      source: 'fetch_call',
      confidence: 0.8,
    });
  }

  // 2. Relative API paths (/api/users, /v1/data)
  RELATIVE_API_PATTERN.lastIndex = 0;
  while ((match = RELATIVE_API_PATTERN.exec(sourceCode)) !== null) {
    const path = match[1];
    const fullUrl = new URL(path, baseUrl).toString();
    if (seen.has(fullUrl)) continue;
    seen.add(fullUrl);
    endpoints.push({
      url: fullUrl,
      method: 'unknown',
      parameter: null,
      source: 'fetch_call',
      confidence: 0.7,
    });
  }

  // 3. fetch() calls
  FETCH_CALL_PATTERN.lastIndex = 0;
  while ((match = FETCH_CALL_PATTERN.exec(sourceCode)) !== null) {
    const arg = match[1];
    // Skip if it's a variable or template literal
    if (/^\$|^\+|^\${/.test(arg)) continue;
    let fullUrl: string;
    try {
      fullUrl = new URL(arg, baseUrl).toString();
    } catch { continue; }
    if (seen.has(fullUrl)) continue;
    seen.add(fullUrl);
    endpoints.push({
      url: fullUrl,
      method: 'GET',
      parameter: null,
      source: 'fetch_call',
      confidence: 0.6,
    });
  }

  // 4. axios.get/post/put/delete calls
  AXIOS_CALL_PATTERN.lastIndex = 0;
  while ((match = AXIOS_CALL_PATTERN.exec(sourceCode)) !== null) {
    const arg = match[1];
    if (/^\$|^\+|^\${/.test(arg)) continue;
    let fullUrl: string;
    try {
      fullUrl = new URL(arg, baseUrl).toString();
    } catch { continue; }
    if (seen.has(fullUrl)) continue;
    seen.add(fullUrl);
    endpoints.push({
      url: fullUrl,
      method: 'GET',
      parameter: null,
      source: 'axios_call',
      confidence: 0.6,
    });
  }

  // 5. href attributes (regular links, not necessarily API)
  HREF_PATTERN.lastIndex = 0;
  while ((match = HREF_PATTERN.exec(sourceCode)) !== null) {
    const href = match[1];
    // Skip external links, anchors, mailto, etc.
    if (/^(?:#|mailto:|tel:|javascript:|data:)/.test(href)) continue;
    if (href.startsWith('http://') || href.startsWith('https://')) {
      // External — only include if same domain as baseUrl
      try {
        const hrefUrl = new URL(href);
        const baseUrlHost = new URL(baseUrl).hostname;
        if (hrefUrl.hostname !== baseUrlHost) continue;
      } catch { continue; }
    }
    let fullUrl: string;
    try {
      fullUrl = new URL(href, baseUrl).toString();
    } catch { continue; }
    if (seen.has(fullUrl)) continue;
    seen.add(fullUrl);
    // Only include links that look like they might have parameters
    // (URLs with ?param=)
    const hasQuery = fullUrl.includes('?');
    endpoints.push({
      url: fullUrl,
      method: 'GET',
      parameter: null,
      source: 'href',
      confidence: hasQuery ? 0.5 : 0.3,
    });
  }

  // 6. Form actions (often reveal /login, /register, /search)
  FORM_ACTION_PATTERN.lastIndex = 0;
  while ((match = FORM_ACTION_PATTERN.exec(sourceCode)) !== null) {
    const action = match[1];
    let fullUrl: string;
    try {
      fullUrl = new URL(action, baseUrl).toString();
    } catch { continue; }
    if (seen.has(fullUrl)) continue;
    seen.add(fullUrl);
    endpoints.push({
      url: fullUrl,
      method: 'POST',
      parameter: null,
      source: 'form_action',
      confidence: 0.7,
    });
  }

  // Sort by confidence (high first)
  endpoints.sort((a, b) => b.confidence - a.confidence);

  return endpoints;
}
