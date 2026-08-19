/**
 * CryptoSentinel — Deep BFS Crawler
 *
 * Replaces the shallow "3 sitemap pages" crawl with a real breadth-first
 * spider that discovers ALL internal pages, forms, parameters, and JS
 * bundles on the target site.
 *
 * The previous fetch-url crawl visited ~5-10 URLs (homepage, sitemap.xml
 * + 3 sitemap pages, 17 common paths via HEAD only, 8 JS bundles). That
 * missed most of the site — security-relevant pages (login, register,
 * reset, api/*, /admin, /dashboard) live INSIDE the site, not in
 * sitemaps. The user explicitly asked us to "literally search everywhere
 * on the site where it might be" — that requires following internal
 * links discovered during HTML parsing.
 *
 * Algorithm:
 *  1. Seed: target URL + common paths (login, admin, api, etc.)
 *  2. BFS queue (FIFO). Each page → parse HTML → extract internal links
 *     (a[href], form action, fetch() calls in inline JS).
 *  3. Per-page payload: title, forms (action+method+fields), URL params,
 *     API endpoints seen in JS, script srcs, meta tags.
 *  4. Cap: 30 pages (configurable), 8s per-page timeout, hard 90s total
 *     wall-clock budget so we never block the analysis pipeline.
 *  5. After BFS: download and parse up to 10 unique JS bundles for
 *     hardcoded secrets / API endpoints.
 *
 * Output: a single big string ("recon report") that gets fed to the AI
 * analyzer, plus a structured `discoveredEndpoints` array passed to the
 * active validator for direct payload testing.
 */
import { isSsrfBlocked } from './ssrf';

export interface CrawledPage {
  url: string;
  path: string;
  status: number;
  title: string;
  html: string;       // first 5000 chars — keeps AI context rich but bounded
  forms: FormInfo[];
  params: string[];   // query param names seen in this page's URL
  endpoints: string[];// API endpoints referenced in this page's HTML
  scripts: string[];  // external script srcs
  metaTags: string[];
  wafBlocked: boolean;
}

export interface FormInfo {
  action: string;
  method: string;
  fields: string[];   // input names
}

export interface CrawlResult {
  pages: CrawledPage[];
  jsBundles: JsBundleInfo[];
  securityHeaders: Record<string, string>;
  reconText: string;          // big blob fed to AI
  discoveredEndpoints: string[]; // URLs ready for active validation
  discoveredForms: FormInfo[];
  discoveredParams: string[];   // unique param names across all pages
  robotsTxt: string;
  sitemapUrls: string[];
  wafDetected: boolean;
}

export interface JsBundleInfo {
  url: string;
  size: number;
  endpoints: string[];
  secrets: string[];
  inlineAnalysis: string;
}

const BROWSER_HEADERS: Record<string, string> = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.9,*/*;q=0.8',
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

const MAX_PAGES = 30;            // was 100 — too many caused rate-limiting
const MAX_JS_BUNDLES = 10;       // was 25 — same reason
const PER_PAGE_TIMEOUT = 8_000;
const TOTAL_BUDGET_MS = 90_000;  // 90s hard cap (was 5 min — too long)
// With 10 parallel × 8s, 30 pages = 3 batches × 8s = 24s.
// 90s leaves headroom for slow proxies + Wayback fallback.
const COMMON_SEED_PATHS = [
  '/', '/login', '/signin', '/register', '/signup', '/auth',
  '/admin', '/dashboard', '/account', '/settings', '/profile',
  '/api', '/api/v1', '/api/v2', '/api/docs', '/api/swagger',
  '/api/openapi.json', '/api/health', '/api/status',
  '/graphql', '/docs', '/swagger-ui.html', '/redoc',
  '/reset', '/reset-password', '/forgot-password', '/verify',
  '/2fa', '/mfa', '/oauth', '/oauth/callback',
  '/wallet', '/connect', '/swap', '/trade', '/bridge',
  '/withdraw', '/deposit', '/transfer', '/stake', '/governance',
  '/.well-known/security.txt', '/.well-known/openid-configuration',
  '/robots.txt', '/sitemap.xml',
];

function isWAFChallenge(html: string): boolean {
  const lower = html.toLowerCase();
  if (html.length > 50000) return false;
  const indicators = [
    'cf-browser-verification', 'cf-challenge', 'cloudflare', 'aws-waf',
    'challenge-platform', 'px-captcha', 'perimeterx', 'datadome',
    'akamai-bot-manager', 'imperva', 'incapsula', 'under attack',
    'please wait while we verify', 'checking your browser',
    'browser verification', 'are you a robot', 'are you human',
    'challenge-runner', 'hcaptcha', 'recaptcha',
  ];
  return indicators.some(ind => lower.includes(ind));
}

function isSameOrigin(url: string, origin: string): boolean {
  try {
    const u = new URL(url);
    if (u.origin === origin) return true;
    // Also accept sibling subdomains (blog.bitunix.com, support.bitunix.com,
    // api.bitunix.com, openapidoc.bitunix.com, etc. when origin is
    // www.bitunix.com). Crypto exchanges commonly host their docs, blog,
    // support, API docs on sibling subdomains — these are part of the
    // same site and should be crawled.
    const originHost = new URL(origin).hostname;
    const originParts = originHost.split('.');
    if (originParts.length >= 2) {
      // Get eTLD+1 (last 2 parts, e.g. bitunix.com)
      const eTldPlus1 = originParts.slice(-2).join('.');
      if (u.hostname.endsWith('.' + eTldPlus1) || u.hostname === eTldPlus1) {
        return true;
      }
    }
    return false;
  } catch { return false; }
}

function normalizeUrl(raw: string, baseUrl: string): string | null {
  try {
    const u = new URL(raw, baseUrl);
    // Strip fragment
    u.hash = '';
    // Only http/https
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return u.toString();
  } catch { return null; }
}

function parsePage(html: string, url: string): {
  title: string; forms: FormInfo[]; endpoints: string[];
  scripts: string[]; metaTags: string[]; links: string[];
} {
  const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  const title = titleMatch?.[1]?.trim() || url;

  // Forms with all input names
  const forms: FormInfo[] = [];
  for (const formMatch of html.matchAll(/<form\b[^>]*>([\s\S]*?)<\/form>/gi)) {
    const formTag = formMatch.input!.slice(formMatch.index ?? 0, (formMatch.index ?? 0) + formMatch[0].length);
    const actionMatch = formTag.match(/action=["']([^"']+)["']/i);
    const methodMatch = formTag.match(/method=["']([^"']+)["']/i);
    const fields: string[] = [];
    for (const inputMatch of formTag.matchAll(/<(?:input|textarea|select)\b[^>]*name=["']([^"']+)["']/gi)) {
      if (inputMatch[1]) fields.push(inputMatch[1]);
    }
    forms.push({
      action: actionMatch?.[1] || url,
      method: (methodMatch?.[1] || 'get').toLowerCase(),
      fields,
    });
  }

  // All internal links (a[href], area[href], link[href] for html pages)
  const links = new Set<string>();
  for (const m of html.matchAll(/(?:href|src)=["']([^"']+)["']/gi)) {
    const href = m[1];
    if (!href || href.startsWith('#') || href.startsWith('javascript:') ||
        href.startsWith('mailto:') || href.startsWith('tel:') ||
        href.startsWith('data:')) continue;
    links.add(href);
  }

  // Script srcs
  const scripts = [...new Set(
    [...html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)]
      .map(m => m[1]).filter(Boolean)
  )].slice(0, 30);

  // API endpoints in inline JS / fetch calls
  const endpoints = [...new Set([
    ...html.matchAll(/["']((?:\/api\/|\/v[0-9]+\/)[^"'\s]+)["']/gi),
    ...html.matchAll(/["'](\/_next\/data\/[^"']+)["']/gi),
    ...html.matchAll(/["'](https?:\/\/[^"']*(?:api|graphql|rpc)[^"']*)["']/gi),
  ].flatMap(r => r[1] ? [r[1]] : []))].slice(0, 50);

  // Meta tags
  const metaTags = [...html.matchAll(/<meta[^>]+(?:name|property|http-equiv)=["']([^"']+)["'][^>]*content=["']([^"']+)["']/gi)]
    .map(m => `${m[1]}: ${m[2]}`).slice(0, 20);

  return { title, forms, endpoints, scripts, metaTags, links: [...links] };
}

async function fetchPage(url: string): Promise<{ status: number; html: string; headers: Record<string, string> } | null> {
  // Direct fetch first
  try {
    const res = await fetch(url, {
      headers: BROWSER_HEADERS,
      redirect: 'follow',
      signal: AbortSignal.timeout(PER_PAGE_TIMEOUT),
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    const html = await res.text();

    // Geo-block (bitunix returns 469 "Restricted Access") or WAF challenge
    // → fall through to proxy fallback
    const isWafBlock = res.status === 403 || res.status === 429 ||
                       res.status === 469 || res.status === 503 ||
                       isWAFChallenge(html);
    if (!isWafBlock && res.ok) {
      return { status: res.status, html, headers };
    }
    // WAF / geo-block — try proxies below
    console.log(`[deep-crawler] Direct fetch status=${res.status} for ${url}, trying proxies...`);
  } catch {}

  // MULTI-PROXY FALLBACK (PARALLEL) — when target is WAF/geo-blocked,
  // fire all proxies at once and use the first good response. Previous
  // version was sequential: 3 proxies × 8s each = 24s worst case per
  // page. Parallel: ~8s max (the slowest proxy wins, but we use the
  // first good response). Critical for sites with 30 pages — saves
  // up to 8 minutes of crawl time.
  const PROXIES = [
    `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`,
    `https://api.codetabs.com/v1/proxy/?url=${encodeURIComponent(url)}`,
    `https://corsproxy.io/?url=${encodeURIComponent(url)}`,
  ];

  const proxyResults = await Promise.allSettled(
    PROXIES.map(async (proxyUrl) => {
      const res = await fetch(proxyUrl, {
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
        signal: AbortSignal.timeout(PER_PAGE_TIMEOUT),
        redirect: 'follow',
      });
      if (!res.ok) return null;
      const html = await res.text();
      if (html.length < 200 || isWAFChallenge(html)) return null;
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
      return { status: 200, html, headers: { ...headers, 'x-fetched-via-proxy': '1' } };
    })
  );
  for (const r of proxyResults) {
    if (r.status === 'fulfilled' && r.value) return r.value;
  }

  // WAYBACK MACHINE FALLBACK — use archived snapshot from web.archive.org
  // This works even when all live proxies are blocked — we get historical
  // content. For security analysis of stable pages (login, dashboard, API
  // docs), the snapshot is usually close enough to the live version.
  try {
    const waybackCheck = await fetch(
      `https://archive.org/wayback/available?url=${encodeURIComponent(url)}`,
      { signal: AbortSignal.timeout(5_000) }
    );
    if (waybackCheck.ok) {
      const wb = await waybackCheck.json();
      const snapUrl = wb?.archived_snapshots?.closest?.url;
      if (snapUrl) {
        const snapRes = await fetch(snapUrl, {
          headers: { 'User-Agent': 'Mozilla/5.0' },
          signal: AbortSignal.timeout(PER_PAGE_TIMEOUT),
          redirect: 'follow',
        });
        if (snapRes.ok) {
          const rawHtml = await snapRes.text();
          if (rawHtml.length > 200 && !isWAFChallenge(rawHtml)) {
            // Strip wayback URL wrappers so we get clean original URLs.
            // Wayback rewrites all hrefs to TWO forms:
            //   - absolute: https://web.archive.org/web/TIMESTAMP[suffix_]/https://original.com/path
            //   - relative: /web/TIMESTAMP[suffix_]/https://original.com/path
            // The suffix is 2 letters + underscore (im_, jm_, cs_, if_, etc.)
            // indicating the rewritten content type (image/js/css/iframe).
            // We want: https://original.com/path (so isSameOrigin + queue logic works).
            // IMPORTANT: do NOT consume the trailing https:// of the original URL.
            const cleanHtml = rawHtml
              .replace(/(?:https?:)?\/\/web\.archive\.org\/web\/\d+(?:[a-z]{2}_)?\//gi, '')
              .replace(/\/web\/\d+(?:[a-z]{2}_)?\//gi, '')
              // Strip wayback's own toolbar/scripts
              .replace(/<script[^>]*src="[^"]*web-static\.archive\.org[^"]*"[^>]*><\/script>/gi, '')
              .replace(/<script[^>]*>\s*__wm\.[\s\S]*?<\/script>/gi, '')
              .replace(/<script[^>]*>\s*window\.RufflePlayer[\s\S]*?<\/script>/gi, '')
              .replace(/<!-- BEGIN WAYBACK TOOLBAR[\s\S]*?END WAYBACK TOOLBAR -->/gi, '')
              .replace(/<!-- BEGIN WAYBACK FOOTER[\s\S]*?END WAYBACK FOOTER -->/gi, '');
            const headers: Record<string, string> = {};
            snapRes.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
            return { status: 200, html: cleanHtml, headers: { ...headers, 'x-fetched-via-wayback': '1' } };
          }
        }
      }
    }
  } catch {}

  return null;
}

function buildReconText(result: CrawlResult): string {
  const lines: string[] = [];
  lines.push(`== DEEP CRAWL REPORT (${result.pages.length} pages, ${result.jsBundles.length} JS bundles) ==`);
  lines.push(`Target: ${result.pages[0]?.url || 'unknown'}`);
  lines.push(`WAF detected: ${result.wafDetected}`);
  lines.push(`Discovered endpoints: ${result.discoveredEndpoints.length}`);
  lines.push(`Discovered forms: ${result.discoveredForms.length}`);
  lines.push(`Discovered unique params: ${result.discoveredParams.length}`);
  lines.push('');

  // Security headers (from homepage)
  if (Object.keys(result.securityHeaders).length > 0) {
    lines.push('== SECURITY HEADERS (homepage) ==');
    for (const [k, v] of Object.entries(result.securityHeaders)) {
      lines.push(`  ${k}: ${v.slice(0, 200)}`);
    }
    const missing: string[] = [];
    if (!result.securityHeaders['content-security-policy']) missing.push('CSP missing — XSS risk');
    if (!result.securityHeaders['x-frame-options']) missing.push('X-Frame-Options missing — clickjacking risk');
    if (!result.securityHeaders['strict-transport-security']) missing.push('HSTS missing — MITM risk');
    if (!result.securityHeaders['x-content-type-options']) missing.push('X-Content-Type-Options missing — MIME sniffing risk');
    if (result.securityHeaders['access-control-allow-origin'] === '*') missing.push('CORS Allow-Origin: * — any-origin API access');
    if (missing.length > 0) {
      lines.push('  [MISSING/INSECURE]');
      for (const m of missing) lines.push(`    - ${m}`);
    }
    lines.push('');
  }

  // robots.txt
  if (result.robotsTxt) {
    lines.push('== ROBOTS.TXT ==');
    lines.push(result.robotsTxt.slice(0, 2000));
    lines.push('');
  }

  // Sitemap
  if (result.sitemapUrls.length > 0) {
    lines.push(`== SITEMAP (${result.sitemapUrls.length} URLs discovered) ==`);
    for (const u of result.sitemapUrls.slice(0, 30)) lines.push(`  - ${u}`);
    lines.push('');
  }

  // Per-page details
  for (const page of result.pages) {
    lines.push(`--- PAGE: ${page.path} [${page.status}] ---`);
    lines.push(`  Title: ${page.title}`);
    if (page.forms.length > 0) {
      lines.push(`  Forms (${page.forms.length}):`);
      for (const f of page.forms) {
        lines.push(`    ${f.method.toUpperCase()} ${f.action} — fields: ${f.fields.join(', ') || '(none)'}`);
      }
    }
    if (page.params.length > 0) lines.push(`  URL params: ${page.params.join(', ')}`);
    if (page.endpoints.length > 0) {
      lines.push(`  API endpoints seen in this page (${page.endpoints.length}):`);
      for (const e of page.endpoints.slice(0, 15)) lines.push(`    - ${e}`);
    }
    if (page.scripts.length > 0) {
      lines.push(`  Scripts (${page.scripts.length}):`);
      for (const s of page.scripts.slice(0, 10)) lines.push(`    - ${s}`);
    }
    if (page.metaTags.length > 0) {
      lines.push(`  Meta tags:`);
      for (const m of page.metaTags.slice(0, 10)) lines.push(`    ${m}`);
    }
    if (page.html && !page.wafBlocked) {
      lines.push(`  HTML snippet (first 2000 chars):`);
      lines.push(page.html.slice(0, 2000));
    }
    lines.push('');
  }

  // JS bundle analysis
  if (result.jsBundles.length > 0) {
    lines.push(`== JS BUNDLE ANALYSIS (${result.jsBundles.length} bundles) ==`);
    for (const js of result.jsBundles) {
      lines.push(`\n--- ${js.url} (${(js.size/1024).toFixed(0)} KB) ---`);
      if (js.endpoints.length > 0) lines.push(`  Endpoints: ${js.endpoints.join(', ')}`);
      if (js.secrets.length > 0) {
        lines.push(`  ⚠️ POTENTIAL SECRETS:`);
        for (const s of js.secrets) lines.push(`    - ${s}`);
      }
      if (js.inlineAnalysis) lines.push(`  Patterns: ${js.inlineAnalysis}`);
    }
    lines.push('');
  }

  // Summary of all discovered endpoints (for active validation)
  lines.push(`== ALL DISCOVERED ENDPOINTS (for active validation) ==`);
  for (const ep of result.discoveredEndpoints.slice(0, 100)) lines.push(`  - ${ep}`);
  lines.push('');
  lines.push(`== ALL DISCOVERED FORMS ==`);
  for (const f of result.discoveredForms) {
    lines.push(`  ${f.method.toUpperCase()} ${f.action} — fields: ${f.fields.join(', ')}`);
  }

  return lines.join('\n');
}

async function fetchRobotsAndSitemap(origin: string): Promise<{ robotsTxt: string; sitemapUrls: string[] }> {
  let robotsTxt = '';
  const sitemapUrls: string[] = [];

  // robots.txt
  try {
    const res = await fetch(`${origin}/robots.txt`, {
      headers: { 'User-Agent': 'CryptoSentinel/1.0' },
      signal: AbortSignal.timeout(5000),
    });
    if (res.ok) {
      robotsTxt = await res.text();
      // Extract Sitemap: directives
      for (const m of robotsTxt.matchAll(/Sitemap:\s*(.+)/gi)) {
        const s = m[1].trim();
        if (s.startsWith('http')) sitemapUrls.push(s);
      }
      // Disallow paths are interesting crawl seeds
      const disallowed = [...robotsTxt.matchAll(/Disallow:\s*(.+)/gi)].map(m => m[1].trim());
      for (const d of disallowed) {
        if (d && d !== '/' && d.length > 1) {
          sitemapUrls.push(`${origin}${d.startsWith('/') ? d : '/' + d}`);
        }
      }
    }
  } catch {}

  // sitemap.xml
  try {
    const res = await fetch(`${origin}/sitemap.xml`, {
      headers: { 'User-Agent': 'CryptoSentinel/1.0' },
      signal: AbortSignal.timeout(5000),
    });
    if (res.ok) {
      const xml = await res.text();
      for (const m of xml.matchAll(/<loc>([^<]+)<\/loc>/gi)) {
        const u = m[1].trim();
        if (u.startsWith('http')) sitemapUrls.push(u);
      }
    }
  } catch {}

  return { robotsTxt, sitemapUrls: [...new Set(sitemapUrls)] };
}

async function analyzeJsBundle(scriptUrl: string, origin: string): Promise<JsBundleInfo | null> {
  const fullUrl = scriptUrl.startsWith('http') ? scriptUrl : `${origin}${scriptUrl}`;
  let js: string | null = null;

  // Try direct fetch first
  try {
    const res = await fetch(fullUrl, {
      headers: { 'User-Agent': 'Mozilla/5.0', 'Accept-Encoding': 'gzip' },
      signal: AbortSignal.timeout(10_000),
    });
    if (res.ok) {
      const text = await res.text();
      if (text.length > 100 && !/cf-challenge|access restricted/i.test(text)) {
        js = text;
      }
    }
  } catch {}

  // PROXY FALLBACK for JS bundles too — bitunix static.bitunix.com is also
  // served through Cloudflare and may be geo-blocked from VPS
  if (!js) {
    const PROXIES = [
      `https://api.allorigins.win/raw?url=${encodeURIComponent(fullUrl)}`,
      `https://api.codetabs.com/v1/proxy/?url=${encodeURIComponent(fullUrl)}`,
    ];
    for (const proxyUrl of PROXIES) {
      try {
        const res = await fetch(proxyUrl, {
          headers: { 'User-Agent': 'Mozilla/5.0' },
          signal: AbortSignal.timeout(10_000),
        });
        if (!res.ok) continue;
        const text = await res.text();
        if (text.length < 100) continue;
        if (/cf-challenge|access restricted/i.test(text)) continue;
        js = text;
        break;
      } catch {}
    }
  }

  // Last resort: Wayback Machine for the JS bundle
  if (!js) {
    try {
      const waybackCheck = await fetch(
        `https://archive.org/wayback/available?url=${encodeURIComponent(fullUrl)}`,
        { signal: AbortSignal.timeout(5_000) }
      );
      if (waybackCheck.ok) {
        const wb = await waybackCheck.json();
        const snapUrl = wb?.archived_snapshots?.closest?.url;
        if (snapUrl) {
          const snapRes = await fetch(snapUrl, {
            headers: { 'User-Agent': 'Mozilla/5.0' },
            signal: AbortSignal.timeout(10_000),
            redirect: 'follow',
          });
          if (snapRes.ok) {
            const text = await snapRes.text();
            if (text.length > 100) js = text;
          }
        }
      }
    } catch {}
  }

  if (!js) return null;
  try {
    const endpoints = [...new Set([
      ...js.matchAll(/["']((?:\/api\/|\/v[0-9]+\/)[^"'\s]+)["']/gi),
      ...js.matchAll(/["'](https?:\/\/[^"']*(?:api|graphql|rpc)[^"']*)["']/gi),
    ].flatMap(r => r[1] ? [r[1]] : []))].slice(0, 30);

    const secrets: string[] = [];
    const secretPatterns = [
      /(?:api[_-]?key|apikey|secret|token|password|private[_-]?key)\s*[:=]\s*["']([^"']{8,})["']/gi,
      /\b(sk-[\w-]{20,})\b/gi, // OpenAI / Stripe style
      /\b(eyJ[\w-]+\.[\w-]+\.[\w-]+)\b/g, // JWT
      /\b(AKIA[\w]{16})\b/g, // AWS access key
      /\b(ghp_[\w]{36,})\b/g, // GitHub PAT
    ];
    for (const p of secretPatterns) {
      for (const m of js.matchAll(p)) {
        const val = m[1] || m[0];
        secrets.push(val.slice(0, 50) + (val.length > 50 ? '…' : ''));
      }
    }

    const inlineAnalysis: string[] = [];
    if (/\beval\s*\(|new\s+Function\s*\(/.test(js)) inlineAnalysis.push('eval/Function — code injection risk');
    if (/\.innerHTML\s*=|document\.write\s*\(/.test(js)) inlineAnalysis.push('innerHTML/document.write — XSS risk');
    if (/postMessage\s*\(/.test(js) && !/targetOrigin\s*!==?\s*["']/.test(js)) inlineAnalysis.push('postMessage without origin check — message hijack risk');
    if (/localStorage\.setItem\s*\(\s*["']([^"']*(?:token|key|secret|auth|session|password|wallet|private)[^"']*)["']/i.test(js)) inlineAnalysis.push('localStorage stores sensitive key');
    if (/personal_sign|eth_signTypedData|signMessage/.test(js)) inlineAnalysis.push('Signing function — signature replay risk');

    return {
      url: fullUrl,
      size: js.length,
      endpoints,
      secrets: [...new Set(secrets)].slice(0, 10),
      inlineAnalysis: inlineAnalysis.join('; '),
    };
  } catch { return null; }
}

/**
 * Main entry point — performs deep BFS crawl of the target site.
 *
 * @param targetUrl - URL to crawl
 * @returns CrawlResult with all pages, JS bundles, and recon text
 */
export async function deepCrawl(targetUrl: string): Promise<CrawlResult> {
  const parsed = new URL(targetUrl);
  const origin = parsed.origin;

  // SSRF safety check — never crawl internal/private IPs
  // CRITICAL BUG FIX: isSsrfBlocked() returns an OBJECT {blocked: boolean, reason}
  // Checking `if (isSsrfBlocked(...))` is ALWAYS TRUE because the object is truthy.
  // This caused EVERY URL (including bitunix.com) to throw 'SSRF safety check failed'.
  // The deep crawler never ran — only the legacy shallow fallback ran (3 sitemap pages).
  // Now correctly check the .blocked property.
  const ssrfCheck = isSsrfBlocked(targetUrl);
  if (ssrfCheck.blocked) {
    throw new Error(`SSRF safety check failed: ${ssrfCheck.reason || 'blocked'} — cannot crawl this URL`);
  }

  const startTime = Date.now();
  const budgetMs = TOTAL_BUDGET_MS;

  // Pre-fetch robots.txt + sitemap.xml in parallel
  const { robotsTxt, sitemapUrls } = await fetchRobotsAndSitemap(origin);

  // Seed queue: target URL + common paths + sitemap URLs
  const seedUrls = new Set<string>();
  seedUrls.add(targetUrl);
  for (const p of COMMON_SEED_PATHS) {
    seedUrls.add(`${origin}${p}`);
  }
  for (const s of sitemapUrls.slice(0, 15)) {
    if (isSameOrigin(s, origin)) seedUrls.add(s);
  }

  const visited = new Set<string>();
  const queue: string[] = [...seedUrls];
  const pages: CrawledPage[] = [];
  const allEndpoints = new Set<string>();
  const allForms: FormInfo[] = [];
  const allParams = new Set<string>();
  const scriptUrls = new Set<string>();
  let securityHeaders: Record<string, string> = {};
  let wafDetected = false;

  // PARALLEL BFS LOOP — fetch pages in batches of 10 at a time.
  // Was 50 — too many caused allorigins proxy to rate-limit us,
  // resulting in 4-min crawl times. 10 parallel is balanced: fast
  // (3 batches × 8s = 24s for 30 pages) without triggering rate limits.
  const PARALLEL_BATCH = 10;

  while (queue.length > 0 && pages.length < MAX_PAGES) {
    // Time budget check
    if (Date.now() - startTime > budgetMs) {
      console.log(`[deep-crawler] Time budget ${budgetMs}ms exceeded — stopping at ${pages.length} pages`);
      break;
    }

    // Take next batch of URLs from the queue
    const batch: string[] = [];
    while (batch.length < PARALLEL_BATCH && queue.length > 0 && pages.length + batch.length < MAX_PAGES) {
      const url = queue.shift()!;
      if (visited.has(url)) continue;
      visited.add(url);
      batch.push(url);
    }
    if (batch.length === 0) break;

    // Fetch all pages in this batch IN PARALLEL
    const batchResults = await Promise.allSettled(
      batch.map(async (url) => ({ url, page: await fetchPage(url) }))
    );

    for (const result of batchResults) {
      if (result.status !== 'fulfilled') continue;
      const { url, page } = result.value;
      if (!page) continue;

      // First successful page → record security headers
      if (pages.length === 0 && Object.keys(securityHeaders).length === 0) {
        securityHeaders = page.headers;
      }

      if (page.status >= 400 && page.status !== 401 && page.status !== 403) continue;

      // Skip empty / WAF challenge pages
      if (page.html.length < 100) continue;
      if (isWAFChallenge(page.html)) {
        wafDetected = true;
        pages.push({
          url, path: new URL(url).pathname, status: page.status,
          title: '[WAF challenge page]', html: '',
          forms: [], params: [], endpoints: [], scripts: [], metaTags: [],
          wafBlocked: true,
        });
        continue;
      }

      const parsedPage = parsePage(page.html, url);
      const pagePath = new URL(url).pathname + new URL(url).search;

      // Collect URL params
      const pageParams: string[] = [];
      try {
        new URL(url).searchParams.forEach((_, key) => {
          pageParams.push(key);
          allParams.add(key);
        });
      } catch {}

      // Collect endpoints
      for (const ep of parsedPage.endpoints) {
        const full = ep.startsWith('http') ? ep : `${origin}${ep}`;
        allEndpoints.add(full);
      }
      for (const f of parsedPage.forms) {
        allForms.push({ ...f, action: f.action.startsWith('http') ? f.action : `${origin}${f.action.startsWith('/') ? f.action : '/' + f.action}` });
      }
      for (const s of parsedPage.scripts) {
        if (s.startsWith('http')) scriptUrls.add(s);
        else if (s.startsWith('/')) scriptUrls.add(`${origin}${s}`);
      }

      pages.push({
        url, path: pagePath, status: page.status,
        title: parsedPage.title,
        html: page.html.slice(0, 5000),
        forms: parsedPage.forms,
        params: pageParams,
        endpoints: parsedPage.endpoints,
        scripts: parsedPage.scripts,
        metaTags: parsedPage.metaTags,
        wafBlocked: false,
      });

      // Enqueue internal links discovered in this page
      for (const link of parsedPage.links) {
        const normalized = normalizeUrl(link, url);
        if (!normalized) continue;
        if (!isSameOrigin(normalized, origin)) continue;
        // Skip non-HTML resources
        const path = new URL(normalized).pathname.toLowerCase();
        if (/\.(jpg|jpeg|png|gif|svg|ico|webp|mp4|mp3|pdf|zip|css|woff|woff2|ttf|eot)(\?|$)/.test(path)) continue;
        if (visited.has(normalized)) continue;
        if (queue.length < 200) queue.push(normalized); // cap queue
      }
    }
  }

  // Download and analyze JS bundles in parallel (cap)
  const jsBundleUrls = [...scriptUrls].slice(0, MAX_JS_BUNDLES);
  const jsResults = await Promise.allSettled(
    jsBundleUrls.map(u => analyzeJsBundle(u, origin))
  );
  const jsBundles: JsBundleInfo[] = jsResults
    .filter((r): r is PromiseFulfilledResult<JsBundleInfo> => r.status === 'fulfilled' && r.value !== null)
    .map(r => r.value);

  // Endpoints from JS bundles → add to discovered endpoints
  for (const js of jsBundles) {
    for (const ep of js.endpoints) {
      const full = ep.startsWith('http') ? ep : `${origin}${ep}`;
      allEndpoints.add(full);
    }
  }

  const result: CrawlResult = {
    pages,
    jsBundles,
    securityHeaders,
    reconText: '', // filled below
    discoveredEndpoints: [...allEndpoints],
    discoveredForms: allForms,
    discoveredParams: [...allParams],
    robotsTxt,
    sitemapUrls,
    wafDetected,
  };
  result.reconText = buildReconText(result);
  return result;
}
