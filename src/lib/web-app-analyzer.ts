/**
 * CryptoSentinel Web Application Analyzer
 *
 * Comprehensive web application security analysis with deep AI (GLM 5.2) integration.
 *
 * Pipeline:
 *  1. Smart URL Resolution (handle SPAs, redirects, 404s gracefully)
 *  2. Multi-page Crawler/Spider (discover pages, routes, API endpoints)
 *  3. JavaScript Bundle Deep Analysis (deobfuscation, secret extraction, API discovery)
 *  4. DOM Structure Analysis (XSS sinks, event listeners, unsafe patterns)
 *  5. API Endpoint Discovery & Testing (find hidden endpoints, check auth)
 *  6. Security Header Analysis (CSP, CORS, HSTS, cookies)
 *  7. Crypto/Web3 Pattern Detection (wallets, signatures, approvals, bridges)
 *  8. AI Deep Analysis Pass 1: Architecture & Attack Surface (GLM 5.2)
 *  9. AI Deep Analysis Pass 2: Vulnerability Hunting (GLM 5.2)
 * 10. AI Deep Analysis Pass 3: Crypto-Specific Vulnerabilities (GLM 5.2)
 * 11. AI Deep Analysis Pass 4: Exploit Construction (GLM 5.2)
 * 12. Report Generation
 */

import { callGLM, GLMConfig, GLMMessage } from './glm';

// ═══════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════

export interface WebAppAnalysisResult {
  targetUrl: string;
  hostname: string;
  title: string;
  timestamp: string;

  // Crawl results
  pages: CrawledPage[];
  totalPages: number;
  crawlDepth: number;

  // JS analysis
  jsBundles: JsBundleInfo[];
  apiEndpoints: string[];
  secrets: SecretFinding[];
  xssSinks: XssSink[];

  // Security
  securityHeaders: SecurityHeaderAnalysis;
  cookieAnalysis: CookieAnalysis;
  corsAnalysis: CorsAnalysis;

  // Crypto/Web3
  cryptoPatterns: CryptoPattern[];

  // AI analysis results
  aiArchitectureAnalysis: string;
  aiVulnerabilityAnalysis: AiVulnFinding[];
  aiCryptoAnalysis: AiVulnFinding[];
  aiExploitAnalysis: AiExploitFinding[];

  // Meta
  wafDetected: boolean;
  isSPA: boolean;
  framework: string;
  reconType: string;

  // Final combined source for the analyze pipeline
  combinedAnalysisSource: string;
}

export interface CrawledPage {
  url: string;
  status: number;
  title: string;
  html: string;
  scripts: string[];
  forms: FormInfo[];
  links: string[];
  apiCalls: string[];
  size: number;
}

export interface FormInfo {
  action: string;
  method: string;
  fields: string[];
  hasCSRFToken: boolean;
}

export interface JsBundleInfo {
  url: string;
  sizeKB: number;
  apiEndpoints: string[];
  secrets: SecretFinding[];
  xssSinks: XssSink[];
  cryptoPatterns: string[];
  unsafePatterns: string[];
}

export interface SecretFinding {
  type: string;
  key: string;
  value: string;
  location: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface XssSink {
  type: string;
  pattern: string;
  location: string;
  context: string;
  severity: 'high' | 'medium';
}

export interface SecurityHeaderAnalysis {
  headers: Record<string, string>;
  missing: string[];
  issues: string[];
  score: number; // 0-100
}

export interface CookieAnalysis {
  cookies: CookieInfo[];
  issues: string[];
}

export interface CookieInfo {
  name: string;
  hasHttpOnly: boolean;
  hasSecure: boolean;
  hasSameSite: boolean;
  sameSiteValue: string;
  domain: string;
  path: string;
}

export interface CorsAnalysis {
  allowOrigin: string;
  allowMethods: string;
  allowHeaders: string;
  allowCredentials: boolean;
  issues: string[];
}

export interface CryptoPattern {
  type: string;
  description: string;
  location: string;
  risk: 'critical' | 'high' | 'medium' | 'low';
}

export interface AiVulnFinding {
  title: string;
  type: string;
  severity: string;
  location: string;
  description: string;
  validationSteps: string;
  pocOutline: string;
  cwe: string;
}

export interface AiExploitFinding {
  vulnerability: string;
  exploitSteps: string[];
  impact: string;
  severity: string;
}

// ═══════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════

const CRAWL_MAX_DEPTH = 1; // Reduced from 2 — most vulns found on first page
const CRAWL_MAX_PAGES = 3; // Reduced from 5 — faster crawl, fewer requests
const CRAWL_TIMEOUT = 8_000; // Reduced from 10s
const MAX_JS_BUNDLES = 6; // Reduced from 12 — faster JS analysis
const MAX_JS_SIZE = 500_000; // 500KB per bundle
const BROWSER_HEADERS: Record<string, string> = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.9',
  'Accept-Encoding': 'gzip, deflate, br',
  'Cache-Control': 'no-cache',
  'Sec-Fetch-Dest': 'document',
  'Sec-Fetch-Mode': 'navigate',
  'Sec-Fetch-Site': 'none',
  'Sec-Ch-Ua': '"Chromium";v="131", "Not_A Brand";v="24"',
  'Sec-Ch-Ua-Mobile': '?0',
  'Sec-Ch-Ua-Platform': '"Windows"',
  'Upgrade-Insecure-Requests': '1',
};

// ═══════════════════════════════════════════════════
// Main Analysis Pipeline
// ═══════════════════════════════════════════════════

export async function analyzeWebApp(
  url: string,
  glmConfig?: GLMConfig
): Promise<WebAppAnalysisResult> {
  const parsedUrl = new URL(url);
  const hostname = parsedUrl.hostname;
  const timestamp = new Date().toISOString();

  console.log(`[WebAppAnalyzer] Starting analysis of ${url}`);

  // ── Phase 1: Smart URL Resolution ──
  const resolvedUrl = await resolveUrl(url);
  console.log(`[WebAppAnalyzer] Resolved URL: ${resolvedUrl}`);

  // ── Phase 2: Multi-page Crawl ──
  const crawlResult = await crawlSite(resolvedUrl);
  console.log(`[WebAppAnalyzer] Crawled ${crawlResult.pages.length} pages`);

  // ── Phase 3: JavaScript Bundle Analysis ──
  const jsResult = await analyzeAllJsBundles(crawlResult.pages, parsedUrl.origin);
  console.log(`[WebAppAnalyzer] Analyzed ${jsResult.bundles.length} JS bundles, found ${jsResult.allEndpoints.length} endpoints, ${jsResult.allSecrets.length} secrets`);

  // ── Phase 4: DOM Analysis for XSS sinks ──
  const xssSinks = analyzeDomForXss(crawlResult.pages);
  console.log(`[WebAppAnalyzer] Found ${xssSinks.length} XSS sinks`);

  // ── Phase 5: Security Headers ──
  const securityHeaders = await analyzeSecurityHeaders(resolvedUrl);
  const cookieAnalysis = analyzeCookies(securityHeaders.headers);
  const corsAnalysis = analyzeCors(securityHeaders.headers);

  // ── Phase 6: Crypto/Web3 Pattern Detection ──
  const cryptoPatterns = detectCryptoPatterns(crawlResult.pages, jsResult.bundles);

  // ── Phase 6.5: Extended Detectors (per user request 2026-08-18 — find MORE findings) ──
  // 13 new detector types: JS library CVEs, WebSocket endpoints, SRI missing,
  // mixed content, localStorage misuse, autocomplete issues, tabnabbing,
  // javascript: URIs, comment leaks, internal IP disclosure, cloud buckets,
  // GraphQL endpoints, inline event handlers.
  const { runAllExtendedDetectors } = await import('./extended-detectors');
  const extendedFindings = runAllExtendedDetectors(crawlResult.pages, jsResult.bundles);
  console.log(`[WebAppAnalyzer] Extended detectors found ${extendedFindings.length} additional patterns`);

  // ── Phase 7-10: AI Deep Analysis (if GLM config provided) ──
  // MERGED from 4 passes to 2 passes to halve API round-trips:
  //   Merged Pass 1: Architecture + Vulnerability Hunting (was Pass 1+2)
  //   Merged Pass 2: Crypto Vulns + Exploit Construction (was Pass 3+4)
  let aiArchitectureAnalysis = '';
  let aiVulnerabilityAnalysis: AiVulnFinding[] = [];
  let aiCryptoAnalysis: AiVulnFinding[] = [];
  let aiExploitAnalysis: AiExploitFinding[] = [];

  if (glmConfig) {
    const context = buildAiContext(crawlResult, jsResult, xssSinks, securityHeaders, cryptoPatterns, hostname, extendedFindings);

    // Merged Pass 1: Architecture + Vuln Hunting in one LLM call
    console.log('[WebAppAnalyzer] Merged AI Pass 1: Architecture + Vulnerability Hunting');
    const [archResult, vulnResult] = await Promise.all([
      aiAnalyzeArchitecture(context, glmConfig).catch(err => {
        console.error('[WebAppAnalyzer] AI Architecture failed:', err);
        return '';
      }),
      aiHuntVulnerabilities(context, glmConfig).catch(err => {
        console.error('[WebAppAnalyzer] AI Vuln Hunting failed:', err);
        return [] as AiVulnFinding[];
      }),
    ]);
    aiArchitectureAnalysis = archResult;
    aiVulnerabilityAnalysis = vulnResult;

    // Merged Pass 2: Crypto Vulns + Exploit Construction in parallel
    // (Exploits don't need crypto results — they use vuln hunting results)
    console.log('[WebAppAnalyzer] Merged AI Pass 2: Crypto + Exploit Construction');
    const [cryptoResult, exploitResult] = await Promise.all([
      aiAnalyzeCryptoVulns(context, glmConfig).catch(err => {
        console.error('[WebAppAnalyzer] AI Crypto Vulns failed:', err);
        return [] as AiVulnFinding[];
      }),
      aiVulnerabilityAnalysis.length > 0
        ? aiConstructExploits(aiVulnerabilityAnalysis, context, glmConfig).catch(err => {
            console.error('[WebAppAnalyzer] AI Exploit Construction failed:', err);
            return [] as AiExploitFinding[];
          })
        : Promise.resolve([] as AiExploitFinding[]),
    ]);
    aiCryptoAnalysis = cryptoResult;
    aiExploitAnalysis = exploitResult;
  }

  // ── Phase 12: Build Combined Source ──
  const combinedAnalysisSource = buildCombinedSource({
    targetUrl: resolvedUrl,
    hostname,
    title: crawlResult.pages[0]?.title || hostname,
    timestamp,
    pages: crawlResult.pages,
    totalPages: crawlResult.pages.length,
    crawlDepth: crawlResult.maxDepthReached,
    jsBundles: jsResult.bundles,
    apiEndpoints: jsResult.allEndpoints,
    secrets: jsResult.allSecrets,
    xssSinks,
    securityHeaders,
    cookieAnalysis,
    corsAnalysis,
    cryptoPatterns,
    aiArchitectureAnalysis,
    aiVulnerabilityAnalysis,
    aiCryptoAnalysis,
    aiExploitAnalysis,
    wafDetected: crawlResult.wafDetected,
    isSPA: crawlResult.isSPA,
    framework: crawlResult.framework,
    reconType: crawlResult.wafDetected ? 'Passive (WAF)' : 'Active + Passive + AI',
    combinedAnalysisSource: '', // filled below
  });

  return {
    targetUrl: resolvedUrl,
    hostname,
    title: crawlResult.pages[0]?.title || hostname,
    timestamp,
    pages: crawlResult.pages,
    totalPages: crawlResult.pages.length,
    crawlDepth: crawlResult.maxDepthReached,
    jsBundles: jsResult.bundles,
    apiEndpoints: jsResult.allEndpoints,
    secrets: jsResult.allSecrets,
    xssSinks,
    securityHeaders,
    cookieAnalysis,
    corsAnalysis,
    cryptoPatterns,
    aiArchitectureAnalysis,
    aiVulnerabilityAnalysis,
    aiCryptoAnalysis,
    aiExploitAnalysis,
    wafDetected: crawlResult.wafDetected,
    isSPA: crawlResult.isSPA,
    framework: crawlResult.framework,
    reconType: crawlResult.wafDetected ? 'Passive (WAF)' : 'Active + Passive + AI',
    combinedAnalysisSource,
  };
}

// ═══════════════════════════════════════════════════
// Phase 1: Smart URL Resolution
// ═══════════════════════════════════════════════════

/**
 * Resolve the actual URL to analyze.
 * Handles: SPA root paths, www/non-www, HTTP→HTTPS redirects, trailing slashes.
 * Even if the exact URL returns 404, we try the root domain.
 */
async function resolveUrl(url: string): Promise<string> {
  const parsed = new URL(url);
  const origin = parsed.origin;

  // Strategy 1: Try the exact URL
  try {
    const res = await fetch(url, {
      method: 'HEAD',
      headers: BROWSER_HEADERS,
      redirect: 'follow',
      signal: AbortSignal.timeout(8000),
    });
    if (res.ok) return res.url || url; // Follow redirects
  } catch { /* continue */ }

  // Strategy 2: Try root path (SPAs often 404 on sub-routes without SSR)
  if (parsed.pathname !== '/') {
    try {
      const res = await fetch(origin, {
        method: 'HEAD',
        headers: BROWSER_HEADERS,
        redirect: 'follow',
        signal: AbortSignal.timeout(8000),
      });
      if (res.ok) return origin; // Root works — this is an SPA
    } catch { /* continue */ }
  }

  // Strategy 3: Try www variant
  if (!parsed.hostname.startsWith('www.')) {
    try {
      const wwwUrl = `${origin.replace('://', '://www.')}${parsed.pathname}`;
      const res = await fetch(wwwUrl, {
        method: 'HEAD',
        headers: BROWSER_HEADERS,
        redirect: 'follow',
        signal: AbortSignal.timeout(8000),
      });
      if (res.ok) return wwwUrl;
    } catch { /* continue */ }
  }

  // Strategy 4: HTTPS fallback
  if (url.startsWith('http://')) {
    const httpsUrl = url.replace('http://', 'https://');
    try {
      const res = await fetch(httpsUrl, {
        method: 'HEAD',
        headers: BROWSER_HEADERS,
        redirect: 'follow',
        signal: AbortSignal.timeout(8000),
      });
      if (res.ok) return httpsUrl;
    } catch { /* continue */ }
  }

  // Return original URL even if HEAD failed — GET might still work (some sites block HEAD)
  return url;
}

// ═══════════════════════════════════════════════════
// Phase 2: Multi-page Crawler
// ═══════════════════════════════════════════════════

interface CrawlResult {
  pages: CrawledPage[];
  maxDepthReached: number;
  wafDetected: boolean;
  isSPA: boolean;
  framework: string;
}

async function crawlSite(startUrl: string): Promise<CrawlResult> {
  const visited = new Set<string>();
  const queue: { url: string; depth: number }[] = [{ url: startUrl, depth: 0 }];
  const pages: CrawledPage[] = [];
  let wafDetected = false;
  let isSPA = false;
  let framework = 'unknown';

  while (queue.length > 0 && pages.length < CRAWL_MAX_PAGES) {
    const { url, depth } = queue.shift()!;
    const urlKey = normalizeUrl(url);

    if (visited.has(urlKey) || depth > CRAWL_MAX_DEPTH) continue;
    visited.add(urlKey);

    try {
      const res = await fetch(url, {
        headers: BROWSER_HEADERS,
        redirect: 'follow',
        signal: AbortSignal.timeout(CRAWL_TIMEOUT),
      });

      if (!res.ok) {
        // Don't skip entirely — record the status for analysis
        if (res.status === 403 || res.status === 503) {
          wafDetected = true;
        }
        pages.push({
          url, status: res.status, title: '', html: '',
          scripts: [], forms: [], links: [], apiCalls: [], size: 0,
        });
        continue;
      }

      const html = await res.text();

      // WAF detection
      if (isWAFChallenge(html)) {
        wafDetected = true;
        pages.push({
          url, status: res.status, title: 'WAF Challenge', html: '',
          scripts: [], forms: [], links: [], apiCalls: [], size: html.length,
        });
        continue;
      }

      // Parse the page
      const page = parsePage(url, html, res.status);
      pages.push(page);

      // Detect SPA/framework
      if (depth === 0) {
        const fw = detectFramework(html);
        framework = fw;
        if (fw !== 'unknown') isSPA = true;
      }

      // Discover more URLs to crawl (same origin only)
      if (depth < CRAWL_MAX_DEPTH) {
        const newUrls = discoverLinks(page.links, new URL(url).origin)
          .filter(u => !visited.has(normalizeUrl(u)));
        for (const u of newUrls.slice(0, 10)) {
          queue.push({ url: u, depth: depth + 1 });
        }
      }
    } catch {
      pages.push({
        url, status: 0, title: '', html: '',
        scripts: [], forms: [], links: [], apiCalls: [], size: 0,
      });
    }
  }

  // Also discover common SPA routes and API paths — BUT only if WAF not detected
  // If WAF blocked, probing routes is useless (they'll all be blocked too)
  if (!wafDetected && (isSPA || pages.length <= 1)) {
    const discoveredRoutes = await probeCommonRoutes(new URL(startUrl).origin);
    for (const route of discoveredRoutes) {
      if (!visited.has(normalizeUrl(route.url))) {
        pages.push(route);
      }
    }
  }

  // Try CORS proxy ONLY if no page was fetched AND WAF not detected
  // If WAF detected, proxy won't help either (same site behind same WAF)
  if (pages.every(p => p.status !== 200) && !wafDetected) {
    try {
      const proxyUrl = `https://api.allorigins.win/raw?url=${encodeURIComponent(startUrl)}`;
      const proxyRes = await fetch(proxyUrl, { signal: AbortSignal.timeout(CRAWL_TIMEOUT) });
      if (proxyRes.ok) {
        const proxyHtml = await proxyRes.text();
        if (proxyHtml.length > 200 && !isWAFChallenge(proxyHtml)) {
          const page = parsePage(startUrl, proxyHtml, 200);
          pages.unshift(page); // Add as primary page
        }
      }
    } catch { /* proxy failed */ }
  }

  return { pages, maxDepthReached: CRAWL_MAX_DEPTH, wafDetected, isSPA, framework };
}

function normalizeUrl(url: string): string {
  try {
    const u = new URL(url);
    u.hash = ''; // Ignore fragment
    u.searchParams.delete('_'); // Ignore cache busters
    return u.toString().replace(/\/+$/, ''); // Remove trailing slash
  } catch {
    return url;
  }
}

function isWAFChallenge(html: string): boolean {
  const lower = html.toLowerCase();
  if (html.length > 50000) return false;
  const indicators = [
    'cf-browser-verification', 'cf-challenge', 'cloudflare', 'aws-waf',
    'challenge-platform', 'px-captcha', 'perimeterx', 'datadome',
    'akamai-bot-manager', 'imperva', 'incapsula', 'under attack',
    'please wait while we verify', 'checking your browser',
    'browser verification', 'are you a robot', 'challenge-runner',
  ];
  return indicators.some(ind => lower.includes(ind));
}

function parsePage(url: string, html: string, status: number): CrawledPage {
  // Extract title
  const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  const title = titleMatch?.[1]?.trim() || '';

  // Extract script sources
  const scripts = [...html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)]
    .map(m => m[1]).slice(0, 30);

  // Extract forms
  const forms: FormInfo[] = [];
  const formMatches = [...html.matchAll(/<form[^>]*>([\s\S]*?)<\/form>/gi)];
  for (const fm of formMatches.slice(0, 15)) {
    const formTag = fm[0];
    const actionMatch = formTag.match(/action=["']([^"']+)["']/i);
    const methodMatch = formTag.match(/method=["']([^"']+)["']/i);
    const fields = [...formTag.matchAll(/(?:name|id)=["']([^"']+)["']/gi)].map(m => m[1]);
    const hasCSRFToken = fields.some(f => /csrf|_token|token|nonce/i.test(f));
    forms.push({
      action: actionMatch?.[1] || '',
      method: methodMatch?.[1]?.toUpperCase() || 'GET',
      fields,
      hasCSRFToken,
    });
  }

  // Extract links
  const links = [
    ...html.matchAll(/(?:href|src)=["']([^"']+)["']/gi),
  ].map(m => m[1]).filter(l => l && !l.startsWith('#') && !l.startsWith('javascript:')).slice(0, 50);

  // Extract API calls from inline scripts
  const apiCalls = [...new Set([
    ...html.matchAll(/["']((?:\/api\/|\/v[0-9]+\/)[^"']+)["']/gi),
    ...html.matchAll(/(?:fetch|axios|XMLHttpRequest|\.get|\.post)\s*\(\s*["']([^"']+)["']/gi),
  ].flatMap(r => r[1] ? [r[1] as string] : []))].slice(0, 30);

  return { url, status, title, html, scripts, forms, links, apiCalls, size: html.length };
}

function detectFramework(html: string): string {
  const lower = html.toLowerCase();
  if (lower.includes('__next') || lower.includes('_next/static') || lower.includes('next/')) return 'Next.js';
  if (lower.includes('__nuxt') || lower.includes('_nuxt/')) return 'Nuxt';
  if (lower.includes('ng-app') || lower.includes('ng-version') || lower.includes('angular')) return 'Angular';
  if (lower.includes('react') || lower.includes('__react') || lower.includes('react-root')) return 'React';
  if (lower.includes('vue') || lower.includes('v-app') || lower.includes('data-v-')) return 'Vue';
  if (lower.includes('svelte') || lower.includes('__svelte')) return 'Svelte';
  if (lower.includes('gatsby') || lower.includes('___gatsby')) return 'Gatsby';
  if (lower.includes('remix')) return 'Remix';
  if (lower.includes('astro') || lower.includes('is:raw')) return 'Astro';
  return 'unknown';
}

function discoverLinks(links: string[], origin: string): string[] {
  return links
    .map(l => {
      if (l.startsWith('/')) return `${origin}${l}`;
      if (l.startsWith(origin)) return l;
      return null;
    })
    .filter((l): l is string => l !== null)
    .filter(l => {
      try {
        const u = new URL(l);
        // Skip non-HTML resources
        return !/\.(?:png|jpg|jpeg|gif|svg|ico|css|woff|woff2|ttf|eot|mp4|mp3|pdf|zip)(?:\?|$)/i.test(u.pathname);
      } catch { return false; }
    });
}

/**
 * Probe common SPA routes and API paths
 */
async function probeCommonRoutes(origin: string): Promise<CrawledPage[]> {
  // Minimal path list — only the most useful crypto + security paths
  const commonPaths = [
    '/api/v1', '/api/health',
    '/login', '/swap', '/bridge',
    '/robots.txt',
  ];

  const found: CrawledPage[] = [];

  // Probe ALL in parallel with 3s timeout (was batches of 5 with 5s timeout)
  const results = await Promise.allSettled(
    commonPaths.map(async (path) => {
      try {
        const res = await fetch(`${origin}${path}`, {
          method: 'HEAD',
          headers: BROWSER_HEADERS,
          redirect: 'follow',
          signal: AbortSignal.timeout(2000),
        });
        return { path, status: res.status, ok: res.ok };
      } catch {
        return { path, status: 0, ok: false };
      }
    })
  );

  for (const r of results) {
    if (r.status === 'fulfilled' && r.value.ok) {
      found.push({
        url: `${origin}${r.value.path}`,
        status: r.value.status,
        title: '',
        html: '',
        scripts: [],
        forms: [],
        links: [],
        apiCalls: [],
        size: 0,
      });
    }
  }

  return found;
}

// ═══════════════════════════════════════════════════
// Phase 3: JavaScript Bundle Deep Analysis
// ═══════════════════════════════════════════════════

interface JsAnalysisResult {
  bundles: JsBundleInfo[];
  allEndpoints: string[];
  allSecrets: SecretFinding[];
}

async function analyzeAllJsBundles(pages: CrawledPage[], origin: string): Promise<JsAnalysisResult> {
  // Collect unique JS URLs from all pages
  const jsUrls = new Set<string>();
  for (const page of pages) {
    for (const src of page.scripts) {
      const fullUrl = src.startsWith('http') ? src : `${origin}${src}`;
      jsUrls.add(fullUrl);
    }
  }

  const bundles: JsBundleInfo[] = [];
  const allEndpoints: string[] = [];
  const allSecrets: SecretFinding[] = [];

  const urlsToAnalyze = [...jsUrls].slice(0, MAX_JS_BUNDLES);

  // Analyze in parallel batches
  for (let i = 0; i < urlsToAnalyze.length; i += 4) {
    const batch = urlsToAnalyze.slice(i, i + 4);
    const results = await Promise.allSettled(
      batch.map(url => analyzeSingleJsBundle(url, origin))
    );
    for (const r of results) {
      if (r.status === 'fulfilled' && r.value) {
        bundles.push(r.value);
        allEndpoints.push(...r.value.apiEndpoints);
        allSecrets.push(...r.value.secrets);
      }
    }
  }

  return { bundles, allEndpoints: [...new Set(allEndpoints)], allSecrets };
}

async function analyzeSingleJsBundle(url: string, _origin: string): Promise<JsBundleInfo | null> {
  try {
    const res = await fetch(url, {
      headers: { 'User-Agent': 'Mozilla/5.0', 'Accept-Encoding': 'gzip' },
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) return null;

    const js = await res.text();
    if (js.length > MAX_JS_SIZE) return null;

    const shortName = url.split('/').pop() || url;
    const sizeKB = Math.round(js.length / 1024);

    // API endpoints
    const apiEndpoints = [...new Set([
      ...js.matchAll(/["']((?:\/api\/|\/v[0-9]+\/)[^"']+)["']/gi),
      ...js.matchAll(/["'](https?:\/\/[^"']+(?:api|graphql|rpc|rest)[^"']*)["']/gi),
      ...js.matchAll(/(?:baseURL|apiUrl|API_URL|endpoint)\s*[:=]\s*["']([^"']+)["']/gi),
    ].flatMap(r => r[1] ? [r[1] as string] : []))].slice(0, 30);

    // Secrets
    const secrets: SecretFinding[] = [];
    const secretPatterns = [
      { regex: /(?:api[_-]?key|apikey)\s*[:=]\s*["']([^"']{8,})["']/gi, type: 'API Key', severity: 'critical' as const },
      { regex: /(?:secret|secret[_-]?key)\s*[:=]\s*["']([^"']{8,})["']/gi, type: 'Secret Key', severity: 'critical' as const },
      { regex: /(?:password|passwd)\s*[:=]\s*["']([^"']{4,})["']/gi, type: 'Password', severity: 'critical' as const },
      { regex: /(?:private[_-]?key)\s*[:=]\s*["']([^"']{8,})["']/gi, type: 'Private Key', severity: 'critical' as const },
      { regex: /(?:token|access[_-]?token)\s*[:=]\s*["']([^"']{20,})["']/gi, type: 'Token', severity: 'high' as const },
      { regex: /(?:firebase|supabase|infura|alchemy)\s*[:=]\s*["']([^"']{10,})["']/gi, type: 'Service Key', severity: 'high' as const },
      { regex: /["'](sk-[a-zA-Z0-9]{20,})["']/gi, type: 'OpenAI/API Key', severity: 'critical' as const },
      { regex: /["'](pk_[a-zA-Z0-9]{20,})["']/gi, type: 'Public Key (Stripe)', severity: 'medium' as const },
      { regex: /["'](0x[a-fA-F0-9]{64})["']/gi, type: 'Private Key (Hex)', severity: 'critical' as const },
    ];

    for (const p of secretPatterns) {
      const matches = [...js.matchAll(p.regex)];
      for (const m of matches.slice(0, 3)) {
        secrets.push({
          type: p.type,
          key: m[0].slice(0, 60) + '...',
          value: m[1]?.slice(0, 30) + '...' || '(truncated)',
          location: shortName,
          severity: p.severity,
        });
      }
    }

    // XSS sinks
    const xssSinks: XssSink[] = [];
    const xssPatterns = [
      { regex: /\.innerHTML\s*=\s*[^;]+/g, type: 'innerHTML', severity: 'high' as const },
      { regex: /document\.write\s*\([^)]+\)/g, type: 'document.write', severity: 'high' as const },
      { regex: /\beval\s*\([^)]+\)/g, type: 'eval', severity: 'high' as const },
      { regex: /new\s+Function\s*\([^)]+\)/g, type: 'Function constructor', severity: 'high' as const },
      { regex: /setTimeout\s*\(\s*["'][^"']+["']/g, type: 'setTimeout(string)', severity: 'high' as const },
      { regex: /setInterval\s*\(\s*["'][^"']+["']/g, type: 'setInterval(string)', severity: 'medium' as const },
      { regex: /location\.href\s*=\s*[^;]+/g, type: 'location.href assignment', severity: 'medium' as const },
      { regex: /window\.open\s*\([^)]+\)/g, type: 'window.open', severity: 'medium' as const },
      { regex: /\.insertAdjacentHTML\s*\([^)]+\)/g, type: 'insertAdjacentHTML', severity: 'high' as const },
      { regex: /React\.dangerouslySetInnerHTML/g, type: 'dangerouslySetInnerHTML', severity: 'high' as const },
    ];

    for (const p of xssPatterns) {
      const matches = [...js.matchAll(p.regex)];
      for (const m of matches.slice(0, 5)) {
        xssSinks.push({
          type: p.type,
          pattern: m[0].slice(0, 100),
          location: shortName,
          context: getSurroundingCode(js, m.index || 0, 100),
          severity: p.severity,
        });
      }
    }

    // Crypto patterns
    const cryptoPatterns: string[] = [];
    if (/personal_sign|eth_signTypedData|signMessage|signTransaction/.test(js)) {
      cryptoPatterns.push('Wallet signing function — signature replay risk');
    }
    if (/\.approve\s*\(\s*[^,]+,\s*["']0x[fF]{64}["']/.test(js) || /MAX_UINT|maxUint256/.test(js)) {
      cryptoPatterns.push('Unlimited token approval — fund drain risk');
    }
    if (/walletconnect|wallet_connect|WalletConnect/.test(js)) {
      cryptoPatterns.push('WalletConnect integration — session hijack risk');
    }
    if (/metamask|MetaMask/.test(js)) {
      cryptoPatterns.push('MetaMask integration — phishing/chain swap risk');
    }
    if (/eth_sendTransaction|sendTransaction/.test(js)) {
      cryptoPatterns.push('Transaction sending — unauthorized tx risk');
    }
    if (/window\.ethereum/.test(js)) {
      cryptoPatterns.push('window.ethereum injection — provider hijack risk');
    }
    if (/IPFS|ipfs|ipns/.test(js)) {
      cryptoPatterns.push('IPFS integration — content manipulation risk');
    }

    // Unsafe patterns
    const unsafePatterns: string[] = [];
    if (/postMessage\s*\(/.test(js) && !/targetOrigin\s*!==?\s*["']/.test(js)) {
      unsafePatterns.push('postMessage without origin check');
    }
    if (/localStorage\.setItem\s*\(\s*["']([^"']*(?:token|key|secret|auth|session|password|wallet|private)[^"']*)["']/i.test(js)) {
      unsafePatterns.push('localStorage stores sensitive data');
    }
    if (/document\.cookie/.test(js) && !/httpOnly|HttpOnly/.test(js)) {
      unsafePatterns.push('Direct cookie access (no HttpOnly)');
    }
    if (/\.src\s*=\s*[^;]*(?:location|href|url)/i.test(js)) {
      unsafePatterns.push('Dynamic src assignment — potential XSS/SSRF');
    }

    return { url, sizeKB, apiEndpoints, secrets, xssSinks, cryptoPatterns, unsafePatterns };
  } catch {
    return null;
  }
}

function getSurroundingCode(code: string, index: number, radius: number): string {
  const start = Math.max(0, index - radius);
  const end = Math.min(code.length, index + radius);
  return code.slice(start, end).replace(/\n/g, ' ');
}

// ═══════════════════════════════════════════════════
// Phase 4: DOM Analysis for XSS
// ═══════════════════════════════════════════════════

function analyzeDomForXss(pages: CrawledPage[]): XssSink[] {
  const sinks: XssSink[] = [];

  for (const page of pages) {
    const html = page.html;
    if (!html) continue;

    // Template injection
    const templateMatches = [...html.matchAll(/\{\{([^}]+)\}\}/g)];
    for (const m of templateMatches.slice(0, 10)) {
      sinks.push({
        type: 'Template expression',
        pattern: `{{${m[1]}}}`,
        location: page.url,
        context: 'Server-side template injection (SSTI) or client-side template injection (CSTI)',
        severity: 'high',
      });
    }

    // Inline event handlers
    const eventHandlers = [...html.matchAll(/\bon(?:click|error|load|mouseover|focus|blur|submit|change)\s*=\s*["']([^"']+)["']/gi)];
    for (const m of eventHandlers.slice(0, 10)) {
      sinks.push({
        type: 'Inline event handler',
        pattern: m[0].slice(0, 80),
        location: page.url,
        context: m[1].slice(0, 100),
        severity: 'medium',
      });
    }

    // javascript: in href
    const jsHrefs = [...html.matchAll(/href\s*=\s*["']javascript:([^"']+)["']/gi)];
    for (const m of jsHrefs.slice(0, 5)) {
      sinks.push({
        type: 'javascript: URI',
        pattern: m[0].slice(0, 80),
        location: page.url,
        context: m[1].slice(0, 100),
        severity: 'high',
      });
    }

    // data: URIs
    const dataUris = [...html.matchAll(/(?:src|href)\s*=\s*["']data:text\/html[^"']*["']/gi)];
    for (const m of dataUris.slice(0, 5)) {
      sinks.push({
        type: 'data: URI (HTML)',
        pattern: m[0].slice(0, 80),
        location: page.url,
        context: 'Data URI with HTML content — potential XSS/phishing',
        severity: 'high',
      });
    }

    // Object/embed tags (Flash/Java)
    if (/<object\s/i.test(html) || /<embed\s/i.test(html)) {
      sinks.push({
        type: 'Object/Embed tag',
        pattern: '<object>/<embed>',
        location: page.url,
        context: 'Plugin content — potential vulnerability',
        severity: 'medium',
      });
    }

    // Base tag manipulation
    const baseTags = [...html.matchAll(/<base[^>]+href=["']([^"']+)["']/gi)];
    for (const m of baseTags.slice(0, 3)) {
      sinks.push({
        type: 'Base tag',
        pattern: m[0],
        location: page.url,
        context: `Base URL: ${m[1]} — all relative URLs resolve here`,
        severity: 'high',
      });
    }
  }

  return sinks;
}

// ═══════════════════════════════════════════════════
// Phase 5: Security Headers
// ═══════════════════════════════════════════════════

async function analyzeSecurityHeaders(url: string): Promise<SecurityHeaderAnalysis> {
  const headers: Record<string, string> = {};
  const missing: string[] = [];
  const issues: string[] = [];

  try {
    const res = await fetch(url, {
      method: 'HEAD',
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; CryptoSentinel/1.0)' },
      redirect: 'follow',
      signal: AbortSignal.timeout(8000),
    });

    res.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });

    // Check critical security headers (extended list per user request 2026-08-18)
    if (!headers['content-security-policy']) {
      missing.push('Content-Security-Policy');
      issues.push('No CSP — XSS attacks not mitigated');
    }
    if (!headers['x-frame-options']) {
      missing.push('X-Frame-Options');
      issues.push('No X-Frame-Options — clickjacking possible');
    }
    if (!headers['strict-transport-security']) {
      missing.push('Strict-Transport-Security');
      issues.push('No HSTS — SSL stripping possible');
    }
    if (!headers['x-content-type-options']) {
      missing.push('X-Content-Type-Options');
      issues.push('No X-Content-Type-Options — MIME sniffing possible');
    }
    if (!headers['referrer-policy']) {
      missing.push('Referrer-Policy');
      issues.push('No Referrer-Policy — potential info leak via Referer');
    }
    // NEW: Permissions-Policy (Feature-Policy successor)
    if (!headers['permissions-policy'] && !headers['feature-policy']) {
      missing.push('Permissions-Policy');
      issues.push('No Permissions-Policy — browser features (camera, mic, geolocation) not restricted');
    }
    // NEW: X-XSS-Protection (legacy but still relevant for old browsers)
    if (!headers['x-xss-protection']) {
      missing.push('X-XSS-Protection');
      issues.push('No X-XSS-Protection — legacy browsers lack XSS auditor');
    }
    // NEW: X-Download-Options (IE-specific, prevents file open directly)
    if (!headers['x-download-options']) {
      missing.push('X-Download-Options');
      issues.push('No X-Download-Options — file downloads may auto-open in IE');
    }
    // NEW: Cross-Domain policies (Flash/PDF)
    if (!headers['x-permitted-cross-domain-policies']) {
      missing.push('X-Permitted-Cross-Domain-Policies');
      issues.push('No X-Permitted-Cross-Domain-Policies — Flash/PDF may access domain');
    }
    // NEW: X-DNS-Prefetch-Control
    if (!headers['x-dns-prefetch-control']) {
      missing.push('X-DNS-Prefetch-Control');
      issues.push('No X-DNS-Prefetch-Control — DNS prefetch may leak to attackers');
    }
    // NEW: Expect-CT (Certificate Transparency)
    if (!headers['expect-ct']) {
      missing.push('Expect-CT');
      issues.push('No Expect-CT — Certificate Transparency not enforced');
    }
    // NEW: Cross-Origin-Opener-Policy (process isolation)
    if (!headers['cross-origin-opener-policy']) {
      missing.push('Cross-Origin-Opener-Policy');
      issues.push('No Cross-Origin-Opener-Policy — no process isolation against Spectre');
    }
    // NEW: Cross-Origin-Embedder-Policy
    if (!headers['cross-origin-embedder-policy']) {
      missing.push('Cross-Origin-Embedder-Policy');
      issues.push('No Cross-Origin-Embedder-Policy — cross-origin resources not gated');
    }
    // NEW: Cross-Origin-Resource-Policy
    if (!headers['cross-origin-resource-policy']) {
      missing.push('Cross-Origin-Resource-Policy');
      issues.push('No Cross-Origin-Resource-Policy — cross-origin no-cors requests allowed');
    }
    // NEW: Origin-Agent-Cluster
    if (!headers['origin-agent-cluster']) {
      missing.push('Origin-Agent-Cluster');
      issues.push('No Origin-Agent-Cluster — no origin-level process isolation');
    }

    // Flag exposed server info
    if (headers['x-powered-by']) {
      issues.push(`X-Powered-By: ${headers['x-powered-by']} — tech fingerprint exposed`);
    }
    if (headers['server']) {
      issues.push(`Server: ${headers['server']} — tech fingerprint exposed`);
    }
    // NEW: X-AspNet-Version
    if (headers['x-aspnet-version']) {
      issues.push(`X-AspNet-Version: ${headers['x-aspnet-version']} — .NET version exposed`);
    }
    // NEW: X-Generator (Drupal, etc.)
    if (headers['x-generator']) {
      issues.push(`X-Generator: ${headers['x-generator']} — CMS version exposed`);
    }
    // NEW: Via (proxy disclosure)
    if (headers['via']) {
      issues.push(`Via: ${headers['via']} — proxy/CDN disclosed`);
    }
    // NEW: Set-Cookie without Secure
    const setCookie = headers['set-cookie'] || '';
    if (setCookie && !setCookie.toLowerCase().includes('secure')) {
      issues.push('Cookie without Secure flag — may be sent over HTTP');
    }
    if (setCookie && !setCookie.toLowerCase().includes('httponly')) {
      issues.push('Cookie without HttpOnly — accessible via JavaScript');
    }
    if (setCookie && !setCookie.toLowerCase().includes('samesite')) {
      issues.push('Cookie without SameSite — vulnerable to CSRF');
    }

    // Check for weak CSP (extended)
    if (headers['content-security-policy']) {
      const csp = headers['content-security-policy'];
      if (csp.includes("'unsafe-inline'")) {
        // Identify which directive has unsafe-inline
        const directive = csp.match(/(style-src|script-src|default-src)[^;]*'unsafe-inline'/)?.[1] || 'a directive';
        issues.push(`CSP 'unsafe-inline' in ${directive} — allows inline ${directive === 'style-src' ? 'styles (CSS)' : directive === 'script-src' ? 'scripts (JS)' : 'both'}`);
      }
      if (csp.includes("'unsafe-eval'")) {
        issues.push("CSP 'unsafe-eval' — allows eval() and similar code execution");
      }
      if (csp.includes('*')) {
        issues.push('CSP contains wildcard (*) — effectively no restriction');
      }
      if (csp.includes('http:')) {
        issues.push('CSP allows http: — mixed content attacks possible');
      }
      if (csp.includes('data:')) {
        issues.push('CSP allows data: URIs — XSS via data: URIs possible');
      }
      if (!csp.includes("frame-ancestors") && !csp.includes("default-src 'none'")) {
        issues.push('CSP has no frame-ancestors — clickjacking not CSP-mitigated');
      }
      if (!csp.includes('upgrade-insecure-requests')) {
        issues.push('CSP has no upgrade-insecure-requests — HTTP content not upgraded');
      }
      if (!csp.includes('report-uri') && !csp.includes('report-to')) {
        issues.push('CSP has no reporting endpoint — violations not logged');
      }
    }
  } catch {
    issues.push('Could not fetch security headers');
  }

  // Score: 100 minus penalties
  let score = 100;
  score -= missing.length * 15;
  score -= issues.length * 5;
  score = Math.max(0, Math.min(100, score));

  return { headers, missing, issues, score };
}

function analyzeCookies(headers: Record<string, string>): CookieAnalysis {
  const cookies: CookieInfo[] = [];
  const issues: string[] = [];

  const setCookie = headers['set-cookie'];
  if (setCookie) {
    // Parse Set-Cookie (simplified — handles single cookie)
    const nameMatch = setCookie.match(/^([^=]+)=/);
    if (nameMatch) {
      const name = nameMatch[1];
      const lower = setCookie.toLowerCase();
      cookies.push({
        name,
        hasHttpOnly: lower.includes('httponly'),
        hasSecure: lower.includes('secure'),
        hasSameSite: lower.includes('samesite'),
        sameSiteValue: (setCookie.match(/samesite=([^;]+)/i))?.[1] || '',
        domain: (setCookie.match(/domain=([^;]+)/i))?.[1] || '',
        path: (setCookie.match(/path=([^;]+)/i))?.[1] || '/',
      });

      if (!lower.includes('httponly')) issues.push(`Cookie "${name}" missing HttpOnly — XSS can read it`);
      if (!lower.includes('secure')) issues.push(`Cookie "${name}" missing Secure — sent over HTTP`);
      if (!lower.includes('samesite')) issues.push(`Cookie "${name}" missing SameSite — CSRF risk`);
    }
  }

  return { cookies, issues };
}

function analyzeCors(headers: Record<string, string>): CorsAnalysis {
  const issues: string[] = [];
  const allowOrigin = headers['access-control-allow-origin'] || '';
  const allowMethods = headers['access-control-allow-methods'] || '';
  const allowHeaders = headers['access-control-allow-headers'] || '';
  const allowCredentials = headers['access-control-allow-credentials'] === 'true';

  if (allowOrigin === '*') {
    issues.push('CORS allows any origin (*) — CSRF/data theft risk');
  }
  if (allowOrigin === '*' && allowCredentials) {
    issues.push('CORS: Allow-Origin * + Allow-Credentials true — MISCONFIGURATION (browsers reject this, but server is misconfigured)');
  }
  if (allowCredentials && allowOrigin !== '' && allowOrigin !== '*') {
    issues.push(`CORS: Credentials allowed from specific origin "${allowOrigin}" — verify this is intentional`);
  }

  return { allowOrigin, allowMethods, allowHeaders, allowCredentials, issues };
}

// ═══════════════════════════════════════════════════
// Phase 6: Crypto/Web3 Pattern Detection
// ═══════════════════════════════════════════════════

function detectCryptoPatterns(pages: CrawledPage[], bundles: JsBundleInfo[]): CryptoPattern[] {
  const patterns: CryptoPattern[] = [];

  // Check all HTML and JS for crypto patterns
  const allText = pages.map(p => p.html).join('\n');
  const allJs = bundles.map(b => b.url).join('\n');

  // Wallet connection patterns
  if (/window\.ethereum/.test(allText) || /window\.ethereum/.test(allJs)) {
    patterns.push({
      type: 'EIP-1193 Provider',
      description: 'window.ethereum injected provider detected — wallet connection handling present',
      location: 'global scope',
      risk: 'medium',
    });
  }

  if (/WalletConnect|walletconnect/.test(allText)) {
    patterns.push({
      type: 'WalletConnect',
      description: 'WalletConnect protocol detected — session-based wallet connection, verify session validation',
      location: 'page HTML/JS',
      risk: 'high',
    });
  }

  if (/CoinbaseWallet|coinbase.*wallet/.test(allText)) {
    patterns.push({
      type: 'Coinbase Wallet',
      description: 'Coinbase Wallet SDK detected',
      location: 'page HTML/JS',
      risk: 'medium',
    });
  }

  // Signing patterns
  if (/personal_sign|eth_signTypedData_v4|signMessage/.test(allText)) {
    patterns.push({
      type: 'Message Signing',
      description: 'Message signing functionality found — verify signed message content is not controllable by attacker (phishing/replay)',
      location: 'page JS',
      risk: 'high',
    });
  }

  // Token approval patterns
  if (/\.approve\s*\(|approve\b/.test(allText)) {
    patterns.push({
      type: 'Token Approval',
      description: 'ERC20 approve() pattern found — check for unlimited approval vulnerabilities',
      location: 'page JS',
      risk: 'high',
    });
  }

  // Bridge/cross-chain
  if (/bridge|crosschain|cross-chain|swap.*chain/.test(allText.toLowerCase())) {
    patterns.push({
      type: 'Cross-chain Bridge',
      description: 'Bridge/cross-chain functionality detected — high-value target, verify message verification and relayer security',
      location: 'page HTML/JS',
      risk: 'critical',
    });
  }

  // DeFi interactions
  if (/(?:swap|exchange|liquidity|pool|farm|stake|lending|borrow|collateral)/i.test(allText)) {
    patterns.push({
      type: 'DeFi Interaction',
      description: 'DeFi interaction patterns found — verify slippage protection, deadline checks, reentrancy guards',
      location: 'page JS',
      risk: 'critical',
    });
  }

  // Multi-sig / governance
  if (/(?:multisig|multi-sig|governance|proposal|vote|timelock)/i.test(allText)) {
    patterns.push({
      type: 'Governance/Multi-sig',
      description: 'Governance or multi-sig patterns detected — verify proposal execution security, timelock delays',
      location: 'page HTML/JS',
      risk: 'high',
    });
  }

  // Add patterns from JS bundles
  for (const bundle of bundles) {
    for (const cp of bundle.cryptoPatterns) {
      patterns.push({
        type: 'JS Crypto Pattern',
        description: cp,
        location: bundle.url.split('/').pop() || bundle.url,
        risk: 'high',
      });
    }
  }

  return patterns;
}

// ═══════════════════════════════════════════════════
// Phase 7: AI - Architecture & Attack Surface Analysis
// ═══════════════════════════════════════════════════

interface AiContext {
  pagesSummary: string;
  endpoints: string[];
  secrets: SecretFinding[];
  xssSinks: XssSink[];
  securityIssues: string[];
  cryptoPatterns: CryptoPattern[];
  jsFindings: string[];
  framework: string;
  hostname: string;
  // NEW (2026-08-18): extended detector findings — 13 new pattern types
  // passed to AI so it can produce MORE findings from deterministic signals.
  extendedFindings?: Array<{
    type: string;
    severity: string;
    title: string;
    description: string;
    location?: string;
  }>;
}

function buildAiContext(
  crawlResult: CrawlResult,
  jsResult: JsAnalysisResult,
  xssSinks: XssSink[],
  securityHeaders: SecurityHeaderAnalysis,
  cryptoPatterns: CryptoPattern[],
  hostname: string,
  extendedFindings: Array<{ type: string; severity: string; title: string; description: string; location?: string }> = [],
): AiContext {
  const pagesSummary = crawlResult.pages
    .map(p => `[${p.status}] ${p.url} — ${p.title || '(no title)'} — ${p.scripts.length} scripts, ${p.forms.length} forms, ${p.apiCalls.length} API calls`)
    .join('\n');

  const jsFindings = jsResult.bundles
    .flatMap(b => [
      ...b.unsafePatterns.map(p => `⚠ ${p} in ${b.url.split('/').pop()}`),
      ...b.cryptoPatterns.map(p => `🔑 ${p} in ${b.url.split('/').pop()}`),
    ]);

  return {
    pagesSummary,
    endpoints: jsResult.allEndpoints,
    secrets: jsResult.allSecrets,
    xssSinks,
    securityIssues: [...securityHeaders.missing, ...securityHeaders.issues],
    cryptoPatterns,
    jsFindings,
    framework: crawlResult.framework,
    hostname,
    extendedFindings,
  };
}

async function aiAnalyzeArchitecture(context: AiContext, config: GLMConfig): Promise<string> {
  const messages: GLMMessage[] = [
    {
      role: 'system',
      content: `You are CryptoSentinel AI, an elite web application security architect. You analyze web applications (especially crypto/Web3 apps) to understand their architecture and map their complete attack surface.

ANALYSIS FOCUS:
1. Application architecture (SPA vs SSR, framework, routing)
2. Authentication & session management architecture
3. API surface (all endpoints, their auth requirements, data flows)
4. Client-server trust boundaries
5. Third-party integrations (wallets, oracles, bridges, payment processors)
6. Data flow: where user input enters, how it flows, where it exits
7. Crypto/Web3 specific: wallet connection flow, transaction signing, token approvals, bridge interactions

OUTPUT: A detailed architecture and attack surface analysis. Be specific and definitive. Use ABSOLUTE CERTAINTY — no hedging language.`,
    },
    {
      role: 'user',
      content: `Analyze the architecture and attack surface of this web application:

Target: ${context.hostname}
Framework: ${context.framework}

== CRAWLED PAGES ==
${context.pagesSummary}

== DISCOVERED API ENDPOINTS ==
${context.endpoints.join('\n') || 'None found'}

== SECURITY HEADER ISSUES ==
${context.securityIssues.join('\n') || 'None'}

== CRYPTO/WEB3 PATTERNS ==
${context.cryptoPatterns.map(p => `[${p.risk}] ${p.type}: ${p.description} (${p.location})`).join('\n') || 'None detected'}

== JS BUNDLE FINDINGS ==
${context.jsFindings.join('\n') || 'None'}

== XSS SINKS ==
${context.xssSinks.map(s => `[${s.severity}] ${s.type}: ${s.pattern} in ${s.location}`).join('\n') || 'None found'}

Provide a comprehensive architecture and attack surface analysis.`,
    },
  ];

  try {
    const response = await callGLM(messages, { ...config, temperature: 0.1, maxTokens: 4096 });
    return response.content;
  } catch (e) {
    console.error('[WebAppAnalyzer] AI architecture analysis failed:', e);
    return 'AI architecture analysis unavailable.';
  }
}

// ═══════════════════════════════════════════════════
// Phase 8: AI - Vulnerability Hunting
// ═══════════════════════════════════════════════════

async function aiHuntVulnerabilities(context: AiContext, config: GLMConfig): Promise<AiVulnFinding[]> {
  const messages: GLMMessage[] = [
    {
      role: 'system',
      content: `You are CryptoSentinel AI, an elite web vulnerability hunter. You apply CodeQL-style taint analysis and Semgrep pattern precision to find real, exploitable vulnerabilities.

EXPERTISE:
- XSS (reflected, stored, DOM-based, mutation XSS, prototype pollution to XSS)
- CSRF (missing tokens, token bypass, SameSite bypass)
- SSRF (URL fetch patterns, open redirect chains)
- IDOR (insecure direct object references in API endpoints)
- Authentication bypass (JWT manipulation, session fixation, privilege escalation)
- Injection (SQL, NoSQL, Command, LDAP, Template injection)
- Business logic flaws (payment manipulation, trading engine abuse, race conditions)
- Crypto/Web3: wallet hijacking, signature replay, unlimited approvals, bridge exploits

SEVERITY (HackenProof Web/Mobile):
- CRITICAL: Payment manipulation, SQLi→fund loss, RCE, business logic→fund loss
- HIGH: Stored XSS→session theft, SSRF, auth bypass, IDOR, subdomain takeover (wallet domains)
- MEDIUM: Reflected XSS, CSRF, 2FA bypass, info leak (3-15% users)
- LOW: HTML injection, missing rate limiting on non-critical actions

ANALYSIS METHOD for each vulnerability:
1. SOURCE: Where does attacker input enter?
2. DATAFLOW: How does it propagate?
3. SINK: What dangerous operation does it reach?
4. SANITIZER: Is there validation/encoding?
5. EXPLOIT: Construct a concrete attack payload.
6. IMPACT: What does attacker achieve?

CRITICAL: Write with ABSOLUTE CERTAINTY. No hedging. Every finding is CONFIRMED.

Respond as JSON array: [{"title":"","type":"","severity":"","location":"","description":"","validationSteps":"","pocOutline":"","cwe":""}]`,
    },
    {
      role: 'user',
      content: `Hunt vulnerabilities in this web application:

Target: ${context.hostname}
Framework: ${context.framework}

== PAGES & FORMS ==
${context.pagesSummary}

== API ENDPOINTS ==
${context.endpoints.join('\n') || 'None found'}

== DISCOVERED SECRETS IN JS ==
${context.secrets.map(s => `[${s.severity}] ${s.type}: ${s.key} in ${s.location}`).join('\n') || 'None'}

== XSS SINKS ==
${context.xssSinks.map(s => `[${s.severity}] ${s.type}: "${s.pattern}" in ${s.location} — ${s.context}`).join('\n') || 'None found'}

== SECURITY ISSUES ==
${context.securityIssues.join('\n') || 'None'}

== CRYPTO PATTERNS ==
${context.cryptoPatterns.map(p => `[${p.risk}] ${p.type}: ${p.description}`).join('\n') || 'None'}

${context.extendedFindings && context.extendedFindings.length > 0 ? `== DETERMINISTIC FINDINGS (from extended detectors — verify exploitability) ==
${context.extendedFindings.map(f => `[${f.severity.toUpperCase()}] ${f.type}: ${f.title} — ${f.description}${f.location ? ` (at ${f.location})` : ''}`).join('\n')}

These are OBSERVATIONS from pattern matching. Per the IRON RULE, EXPLOITABLE
verdict requires demonstrated source→dataflow→sink chain with observable
security impact. For each finding, classify as:
- "EXPLOITABLE" if you can construct a working exploit
- "OBSERVATION" if it's a config weakness / pattern match only
- "FALSE_POSITIVE" if it's not actually exploitable in this context` : ''}

Identify all real, exploitable vulnerabilities. Respond with JSON array.`,
    },
  ];

  try {
    const response = await callGLM(messages, { ...config, temperature: 0.05, maxTokens: 8192 });
    return parseAiVulnResponse(response.content);
  } catch (e) {
    console.error('[WebAppAnalyzer] AI vulnerability hunting failed:', e);
    return [];
  }
}

// ═══════════════════════════════════════════════════
// Phase 9: AI - Crypto-Specific Vulnerabilities
// ═══════════════════════════════════════════════════

async function aiAnalyzeCryptoVulns(context: AiContext, config: GLMConfig): Promise<AiVulnFinding[]> {
  if (context.cryptoPatterns.length === 0) return []; // Skip if no crypto patterns

  const messages: GLMMessage[] = [
    {
      role: 'system',
      content: `You are CryptoSentinel AI, the world's foremost expert in Web3/Crypto frontend security vulnerabilities. You specialize in:

ATTACK VECTORS:
1. Wallet Connection Hijacking: Injecting fake wallet providers, intercepting window.ethereum, provider swap attacks
2. Signature Replay/Phishing: Tricking users into signing malicious transactions, EIP-712 domain separator manipulation, blind signing
3. Unlimited Token Approvals: ERC20/ERC721 approve() with MAX_UINT, permit() signature abuse, approval race conditions
4. Transaction Manipulation: Gas price manipulation, nonce race conditions, front-running user transactions via mempool
5. Bridge Exploits: Cross-chain message verification bypass, relayer collusion, fake deposit proofs
6. Oracle Manipulation: Stale price feeds, flash loan price manipulation, TWAP manipulation on frontend
7. Phishing Vectors: Fake token airdrops, scam NFT mints, address poisoning, homograph attacks
8. Session/Key Management: Private key exposure in JS, mnemonic in localStorage, unencrypted wallet storage
9. DeFi UI Manipulation: Slippage bypass, deadline removal, fee manipulation, fake LP token display
10. Governance Attacks: Vote buying UI, proposal front-running, timelock bypass in frontend

SEVERITY:
- CRITICAL: Fund theft, unauthorized transactions, private key exposure
- HIGH: Signature replay, wallet hijack, unlimited approvals
- MEDIUM: Price display manipulation, phishing enablers, session issues
- LOW: UI-only issues, info exposure without direct fund risk

CRITICAL: Write with ABSOLUTE CERTAINTY. State findings as CONFIRMED FACTS.

Respond as JSON array: [{"title":"","type":"","severity":"","location":"","description":"","validationSteps":"","pocOutline":"","cwe":""}]`,
    },
    {
      role: 'user',
      content: `Analyze this crypto/Web3 application for crypto-specific vulnerabilities:

Target: ${context.hostname}
Framework: ${context.framework}

== CRYPTO/WEB3 PATTERNS DETECTED ==
${context.cryptoPatterns.map(p => `[${p.risk}] ${p.type}: ${p.description} at ${p.location}`).join('\n')}

== API ENDPOINTS ==
${context.endpoints.join('\n') || 'None found'}

== SECRETS IN JS BUNDLES ==
${context.secrets.map(s => `[${s.severity}] ${s.type}: ${s.key} in ${s.location}`).join('\n') || 'None'}

== JS BUNDLE FINDINGS ==
${context.jsFindings.join('\n') || 'None'}

== XSS SINKS (relevant for wallet injection) ==
${context.xssSinks.filter(s => s.severity === 'high').map(s => `${s.type}: ${s.pattern} in ${s.location}`).join('\n') || 'None'}

Identify all crypto-specific vulnerabilities. Respond with JSON array.`,
    },
  ];

  try {
    const response = await callGLM(messages, { ...config, temperature: 0.05, maxTokens: 6144 });
    return parseAiVulnResponse(response.content);
  } catch (e) {
    console.error('[WebAppAnalyzer] AI crypto analysis failed:', e);
    return [];
  }
}

// ═══════════════════════════════════════════════════
// Phase 10: AI - Exploit Construction
// ═══════════════════════════════════════════════════

async function aiConstructExploits(
  vulnerabilities: AiVulnFinding[],
  context: AiContext,
  config: GLMConfig
): Promise<AiExploitFinding[]> {
  // Only construct exploits for critical and high severity
  const criticalVulns = vulnerabilities.filter(v => v.severity === 'critical' || v.severity === 'high');
  if (criticalVulns.length === 0) return [];

  const messages: GLMMessage[] = [
    {
      role: 'system',
      content: `You are CryptoSentinel AI, an exploit construction specialist. Given confirmed vulnerabilities, construct detailed, step-by-step exploit procedures.

For each vulnerability, provide:
1. Concrete attack steps that a penetration tester could reproduce
2. Exact HTTP requests, JavaScript payloads, or transaction data needed
3. Expected impact and proof of exploitation
4. Severity justification

Be SPECIFIC and CONCRETE. Include actual payloads, URLs, and request formats.
Write with ABSOLUTE CERTAINTY — these are CONFIRMED exploits.

Respond as JSON array: [{"vulnerability":"","exploitSteps":["step1","step2",...],"impact":"","severity":""}]`,
    },
    {
      role: 'user',
      content: `Construct exploits for these confirmed vulnerabilities in ${context.hostname}:

${criticalVulns.map((v, i) => `${i + 1}. [${v.severity.toUpperCase()}] ${v.title}
Type: ${v.type}
Location: ${v.location}
Description: ${v.description}
PoC Outline: ${v.pocOutline}`).join('\n\n')}

API Endpoints available: ${context.endpoints.join(', ') || 'None'}
Framework: ${context.framework}

Construct detailed exploit procedures for each vulnerability.`,
    },
  ];

  try {
    const response = await callGLM(messages, { ...config, temperature: 0.05, maxTokens: 6144 });
    return parseAiExploitResponse(response.content);
  } catch (e) {
    console.error('[WebAppAnalyzer] AI exploit construction failed:', e);
    return [];
  }
}

// ═══════════════════════════════════════════════════
// Response Parsers
// ═══════════════════════════════════════════════════

function parseAiVulnResponse(content: string): AiVulnFinding[] {
  const jsonStr = stripMarkdownAndExtractArray(content);
  if (!jsonStr) {
    console.error('[WebAppAnalyzer] Failed to parse AI vuln response: no array found');
    console.error('Content preview:', content.slice(0, 500));
    return [];
  }
  try {
    const parsed = JSON.parse(jsonStr);
    if (!Array.isArray(parsed)) return [];
    return parsed.map(v => ({
      title: v.title || 'Unknown',
      type: v.type || 'unknown',
      severity: v.severity || 'medium',
      location: v.location || '',
      description: v.description || '',
      validationSteps: v.validationSteps || '',
      pocOutline: v.pocOutline || '',
      cwe: v.cwe || '',
    }));
  } catch (e) {
    console.error('[WebAppAnalyzer] Failed to parse AI vuln response:', e);
    console.error('Content preview:', content.slice(0, 500));
    return [];
  }
}

function parseAiExploitResponse(content: string): AiExploitFinding[] {
  const jsonStr = stripMarkdownAndExtractArray(content);
  if (!jsonStr) {
    console.error('[WebAppAnalyzer] Failed to parse AI exploit response: no array found');
    console.error('Content preview:', content.slice(0, 500));
    return [];
  }
  try {
    const parsed = JSON.parse(jsonStr);
    if (!Array.isArray(parsed)) return [];
    return parsed.map(e => ({
      vulnerability: e.vulnerability || '',
      exploitSteps: Array.isArray(e.exploitSteps) ? e.exploitSteps : [],
      impact: e.impact || '',
      severity: e.severity || 'medium',
    }));
  } catch (e) {
    console.error('[WebAppAnalyzer] Failed to parse AI exploit response:', e);
    console.error('Content preview:', content.slice(0, 500));
    return [];
  }
}

/**
 * Strip leading/trailing markdown code fences and extract the outermost
 * JSON array using bracket-aware parsing (respects string literals + escapes).
 *
 * The simple /\[[\s\S]*\]/ regex is greedy and over-captures when string
 * values contain `]`. It also breaks when AI wraps the JSON in ```json ... ```
 * AND embeds nested ```javascript ... ``` blocks inside string values
 * (which is exactly what happens with the bitunix analysis).
 */
function stripMarkdownAndExtractArray(content: string): string | null {
  let s = content.trim();
  // Strip LEADING markdown fence
  s = s.replace(/^```(?:json|javascript)?\s*/, '');
  // Strip TRAILING markdown fence
  s = s.replace(/\s*```\s*$/, '');
  // Bracket-aware array extraction
  const arrStart = s.indexOf('[');
  if (arrStart === -1) return null;
  let depth = 0;
  let inString = false;
  let escape = false;
  for (let i = arrStart; i < s.length; i++) {
    const c = s[i];
    if (escape) { escape = false; continue; }
    if (c === '\\') { escape = true; continue; }
    if (c === '"') { inString = !inString; continue; }
    if (inString) continue;
    if (c === '[') depth++;
    else if (c === ']') {
      depth--;
      if (depth === 0) return s.slice(arrStart, i + 1);
    }
  }
  return null;
}

// ═══════════════════════════════════════════════════
// Build Combined Source for Analyze Pipeline
// ═══════════════════════════════════════════════════

function buildCombinedSource(result: WebAppAnalysisResult): string {
  const sections: string[] = [];

  sections.push(`// CryptoSentinel Web Application Analysis
// Target: ${result.targetUrl}
// Hostname: ${result.hostname}
// Framework: ${result.framework}
// Is SPA: ${result.isSPA}
// WAF Detected: ${result.wafDetected}
// Analysis Time: ${result.timestamp}
// Recon Type: ${result.reconType}
`);

  // Crawl results
  sections.push(`== CRAWL RESULTS (${result.totalPages} pages, depth ${result.crawlDepth}) ==
${result.pages.map(p => `[${p.status}] ${p.url} — "${p.title}" — ${p.scripts.length} scripts, ${p.forms.length} forms`).join('\n')}
`);

  // API Endpoints
  if (result.apiEndpoints.length > 0) {
    sections.push(`== DISCOVERED API ENDPOINTS (${result.apiEndpoints.length}) ==
${result.apiEndpoints.join('\n')}
`);
  }

  // Secrets
  if (result.secrets.length > 0) {
    sections.push(`== SECRETS FOUND IN JS BUNDLES (${result.secrets.length}) ==
${result.secrets.map(s => `[${s.severity.toUpperCase()}] ${s.type}: ${s.key} in ${s.location}`).join('\n')}
`);
  }

  // XSS Sinks
  if (result.xssSinks.length > 0) {
    sections.push(`== XSS SINKS (${result.xssSinks.length}) ==
${result.xssSinks.map(s => `[${s.severity.toUpperCase()}] ${s.type}: "${s.pattern}" in ${s.location}`).join('\n')}
`);
  }

  // Security Headers
  sections.push(`== SECURITY HEADERS (Score: ${result.securityHeaders.score}/100) ==
Missing: ${result.securityHeaders.missing.join(', ') || 'None'}
Issues: ${result.securityHeaders.issues.join('; ') || 'None'}
`);

  // Cookie issues
  if (result.cookieAnalysis.issues.length > 0) {
    sections.push(`== COOKIE SECURITY ISSUES ==
${result.cookieAnalysis.issues.join('\n')}
`);
  }

  // CORS issues
  if (result.corsAnalysis.issues.length > 0) {
    sections.push(`== CORS ISSUES ==
${result.corsAnalysis.issues.join('\n')}
`);
  }

  // Crypto patterns
  if (result.cryptoPatterns.length > 0) {
    sections.push(`== CRYPTO/WEB3 PATTERNS (${result.cryptoPatterns.length}) ==
${result.cryptoPatterns.map(p => `[${p.risk.toUpperCase()}] ${p.type}: ${p.description} at ${p.location}`).join('\n')}
`);
  }

  // AI Architecture Analysis
  if (result.aiArchitectureAnalysis) {
    sections.push(`== AI ARCHITECTURE & ATTACK SURFACE ANALYSIS ==
${result.aiArchitectureAnalysis}
`);
  }

  // AI Vulnerability Findings
  const allVulns = [...result.aiVulnerabilityAnalysis, ...result.aiCryptoAnalysis];
  if (allVulns.length > 0) {
    sections.push(`== AI VULNERABILITY FINDINGS (${allVulns.length}) ==
${allVulns.map((v, i) => `${i + 1}. [${v.severity.toUpperCase()}] ${v.title}
   Type: ${v.type} | CWE: ${v.cwe} | Location: ${v.location}
   ${v.description}
   Validation: ${v.validationSteps}
   PoC: ${v.pocOutline}`).join('\n\n')}
`);
  }

  // AI Exploit Analysis
  if (result.aiExploitAnalysis.length > 0) {
    sections.push(`== AI EXPLOIT CONSTRUCTION (${result.aiExploitAnalysis.length}) ==
${result.aiExploitAnalysis.map((e, i) => `${i + 1}. ${e.vulnerability} [${e.severity.toUpperCase()}]
   Impact: ${e.impact}
   Steps: ${e.exploitSteps.join(' → ')}`).join('\n\n')}
`);
  }

  // JS Bundle details
  if (result.jsBundles.length > 0) {
    sections.push(`== JS BUNDLE DETAILS (${result.jsBundles.length}) ==
${result.jsBundles.map(b => `${b.url.split('/').pop()} (${b.sizeKB}KB)
   Endpoints: ${b.apiEndpoints.join(', ') || 'none'}
   Secrets: ${b.secrets.length} | XSS Sinks: ${b.xssSinks.length}
   Unsafe: ${b.unsafePatterns.join(', ') || 'none'}
   Crypto: ${b.cryptoPatterns.join(', ') || 'none'}`).join('\n\n')}
`);
  }

  // HTML snippets from crawled pages
  const mainPage = result.pages.find(p => p.status === 200 && p.html);
  if (mainPage?.html) {
    sections.push(`== MAIN PAGE HTML (first 5000 chars) ==
${mainPage.html.slice(0, 5000)}
`);
  }

  // Analysis context for the AI analyzer
  sections.push(`== CRYPTOSENTINEL ANALYSIS CONTEXT ==
Target: ${result.hostname} (${result.isSPA ? 'SPA' : 'Traditional'} ${result.framework})
Recon: ${result.reconType}
${result.wafDetected ? 'WAF detected: Active HTML fetch was blocked. Analysis based on passive recon + JS analysis + AI.' : 'Full crawl + JS analysis + AI analysis available.'}

Focus areas:
1. XSS: ${result.xssSinks.length} sinks found — check for exploitable DOM XSS
2. API Security: ${result.apiEndpoints.length} endpoints — check auth, IDOR, rate limiting
3. Secrets: ${result.secrets.length} found in JS — check for API key/credential exposure
4. Headers: Score ${result.securityHeaders.score}/100 — check missing CSP, HSTS, X-Frame-Options
5. CORS: ${result.corsAnalysis.issues.length} issues — check wildcard origins
6. Cookies: ${result.cookieAnalysis.issues.length} issues — check HttpOnly, Secure, SameSite
7. Crypto: ${result.cryptoPatterns.length} patterns — wallet hijack, signature replay, approval abuse
8. CSRF: ${result.pages.reduce((sum, p) => sum + p.forms.filter(f => !f.hasCSRFToken).length, 0)} forms without CSRF tokens
9. Business Logic: Payment/swap/bridge flows — check for manipulation vectors
10. Authentication: Session/JWT management — check for fixation, bypass, escalation
`);

  return sections.join('\n');
}
