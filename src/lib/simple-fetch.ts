/**
 * CryptoSentinel — ROBUST URL Fetcher
 *
 * Tested against bitunix.com + chrome.coin98.com from VPS:
 *   - Direct fetch (Chrome UA) works for bitunix (175KB, 0.3s)
 *   - r.jina.ai reader works for BOTH (bypasses Cloudflare WAF, ~4s)
 *   - allorigins/codetabs/corsproxy.io all FAILED from VPS
 *
 * Strategy:
 *  1. Direct fetch with Chrome UA (10s) — returns HTML + headers
 *  2. If fails OR real WAF challenge → r.jina.ai reader (10s)
 *     - Returns clean MARKDOWN of the page (bypasses WAF)
 *     - Loses HTTP headers, but content is enough for AI analysis
 *  3. If both fail → clear HTTP 408 error to user
 *
 * Total: max 20s. User always gets a response.
 *
 * WAF DETECTION FIX: previous version falsely flagged any HTML
 * containing the word "cloudflare" as WAF challenge — but bitunix
 * has <script src="...cloudflareinsights.com/beacon.min.js"> which
 * is just the Cloudflare Insights analytics, NOT a WAF challenge.
 * Now we look for ACTUAL WAF challenge indicators: specific page
 * titles like "Just a moment..." / "Access restricted" / status 403.
 */
import { isSsrfBlocked } from './ssrf';

const FETCH_TIMEOUT = 10_000;
// GT (Ground Truth) docker containers on localhost may take longer to start
// (juice-shop Node.js boot is ~30s). Allow 60s for localhost targets.
const FETCH_TIMEOUT_GT = 60_000;

const BROWSER_HEADERS: Record<string, string> = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.9',
  'Accept-Encoding': 'gzip, deflate, br',
  'Cache-Control': 'no-cache',
  'Sec-Fetch-Dest': 'document',
  'Sec-Fetch-Mode': 'navigate',
  'Sec-Fetch-Site': 'none',
};

const GOOGLEBOT_HEADERS: Record<string, string> = {
  'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.9',
};

export interface RobustFetchResult {
  sourceCode: string;       // Text for AI analysis
  contractName: string;
  url: string;
  title: string;
  fetched: boolean;
  method: 'direct' | 'googlebot' | 'jina' | 'failed';
  error?: string;
}

/**
 * REAL WAF challenge detection — only flag actual WAF challenge pages,
 * not just pages that mention "cloudflare" in script src (e.g., the
 * Cloudflare Insights analytics beacon).
 *
 * Indicators of REAL WAF challenge:
 *  - HTTP status 403, 429, 469, 503
 *  - Page title is "Just a moment..." (Cloudflare)
 *  - Page title is "Access restricted" (geo-block)
 *  - Body contains cf-challenge, please-wait-while-we-verify
 *  - Very short body (< 5KB) AND mentions WAF vendor
 */
function isRealWafChallenge(html: string, status: number): boolean {
  // Status-based: 403/429/469/503 are typical WAF block codes
  if (status === 403 || status === 429 || status === 469 || status === 503) {
    // But only if body looks like a challenge page (short + vendor mention)
    if (html.length < 10000) {
      const lower = html.toLowerCase();
      if (lower.includes('just a moment') ||
          lower.includes('access restricted') ||
          lower.includes('cf-challenge') ||
          lower.includes('cf-browser-verification') ||
          lower.includes('checking your browser') ||
          lower.includes('please wait while we verify')) {
        return true;
      }
    }
  }
  // Title-based: "Just a moment..." is the Cloudflare challenge page title
  const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  if (titleMatch) {
    const title = titleMatch[1].trim().toLowerCase();
    if (title.includes('just a moment') ||
        title.includes('access restricted') ||
        title.includes('attention required') ||
        title.includes('please wait')) {
      return true;
    }
  }
  return false;
}

function extractQuickRecon(html: string, hostname: string) {
  const lines: string[] = [];

  const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  const title = titleMatch?.[1]?.trim() || hostname;

  const scriptSrcs = [...html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)]
    .map(m => m[1]).slice(0, 20);
  const apiEndpoints = [...new Set([
    ...html.matchAll(/["']((?:\/api\/|\/v[0-9]+\/)[^"'\s]+)["']/gi),
    ...html.matchAll(/["'](https?:\/\/[^"']*(?:api|graphql|rpc)[^"']*)["']/gi),
  ].flatMap(r => r[1] ? [r[1]] : []))].slice(0, 30);
  const formActions = [...html.matchAll(/<form[^>]+action=["']([^"']+)["']/gi)]
    .map(m => m[1]).slice(0, 10);
  const internalLinks = [...new Set([...html.matchAll(/href=["']([^"']+)["']/gi)]
    .map(m => m[1]).filter(h => h.startsWith('/') || h.includes(hostname)).slice(0, 50))];

  lines.push(`Title: ${title}`);
  lines.push(`Scripts found: ${scriptSrcs.length}`);
  for (const s of scriptSrcs) lines.push(`  - ${s}`);
  lines.push(`API endpoints in HTML: ${apiEndpoints.length}`);
  for (const e of apiEndpoints) lines.push(`  - ${e}`);
  lines.push(`Forms: ${formActions.length}`);
  for (const f of formActions) lines.push(`  - ${f}`);
  lines.push(`Internal links: ${internalLinks.length}`);
  for (const l of internalLinks.slice(0, 20)) lines.push(`  - ${l}`);

  // Crypto/wallet patterns
  const lowerHtml = html.toLowerCase();
  const cryptoPatterns: string[] = [];
  if (lowerHtml.includes('metamask')) cryptoPatterns.push('MetaMask integration');
  if (lowerHtml.includes('walletconnect')) cryptoPatterns.push('WalletConnect');
  if (lowerHtml.includes('web3')) cryptoPatterns.push('Web3');
  if (lowerHtml.includes('ethereum')) cryptoPatterns.push('Ethereum');
  if (lowerHtml.includes('personal_sign') || lowerHtml.includes('signmessage')) cryptoPatterns.push('Message signing (signature replay risk)');
  if (lowerHtml.includes('approve') && (lowerHtml.includes('erc20') || lowerHtml.includes('token'))) cryptoPatterns.push('Token approval pattern (unlimited approval risk)');
  if (cryptoPatterns.length > 0) {
    lines.push(`Crypto patterns: ${cryptoPatterns.join(', ')}`);
  }

  // XSS sinks
  if (/\.innerHTML\s*=|document\.write\s*\(/.test(html)) lines.push('XSS sink: innerHTML/document.write present');
  if (/\beval\s*\(|new\s+Function\s*\(/.test(html)) lines.push('XSS sink: eval/Function present');
  if (/postMessage\s*\(/.test(html) && !/targetOrigin\s*!==?\s*["']/.test(html)) lines.push('postMessage without origin check — message hijack risk');

  // localStorage sensitive data
  const lsMatch = html.match(/localStorage\.setItem\s*\(\s*["']([^"']*(?:token|key|secret|auth|session|password|wallet|private)[^"']*)["']/i);
  if (lsMatch) lines.push(`localStorage stores sensitive key: "${lsMatch[1]}"`);

  // Hardcoded secrets (quick scan)
  const secretMatch = html.match(/(?:api[_-]?key|secret|token|password|private[_-]?key)\s*[=:]\s*["']([^"']{8,})["']/i);
  if (secretMatch) lines.push(`POSSIBLE hardcoded secret: "${secretMatch[1].slice(0, 30)}..."`);

  return { title, recon: lines.join('\n') };
}

async function tryDirectFetch(url: string, headers: Record<string, string>): Promise<{ html: string; headers: Record<string, string>; status: number } | null> {
  try {
    // Use longer timeout for GT (localhost) targets — juice-shop is slow to boot
    const isGt = url.startsWith('http://localhost') || url.startsWith('http://127.0.0.1');
    const timeout = isGt ? FETCH_TIMEOUT_GT : FETCH_TIMEOUT;
    const res = await fetch(url, {
      headers,
      redirect: 'follow',
      signal: AbortSignal.timeout(timeout),
    });
    const respHeaders: Record<string, string> = {};
    res.headers.forEach((v, k) => { respHeaders[k.toLowerCase()] = v; });
    const html = await res.text();
    if (html.length < 100) return null;
    // REAL WAF check — not just "cloudflare" word in script src
    if (isRealWafChallenge(html, res.status)) {
      console.log(`[robust-fetch] Direct fetch returned WAF challenge (status ${res.status}, html ${html.length} bytes)`);
      return null;
    }
    return { html, headers: respHeaders, status: res.status };
  } catch (e) {
    console.log(`[robust-fetch] Direct fetch failed: ${String(e).slice(0, 100)}`);
    return null;
  }
}

async function tryJinaReader(url: string): Promise<{ markdown: string } | null> {
  try {
    // r.jina.ai is a reader service that bypasses WAF (Cloudflare, AWS WAF, etc.)
    // Returns clean MARKDOWN of the page content. Loses HTTP headers but
    // gets the actual content even for WAF-protected sites.
    const jinaUrl = `https://r.jina.ai/${url}`;
    const res = await fetch(jinaUrl, {
      headers: { 'User-Agent': 'Mozilla/5.0', 'Accept': 'text/plain' },
      signal: AbortSignal.timeout(FETCH_TIMEOUT),
    });
    if (!res.ok) return null;
    const text = await res.text();
    if (text.length < 100) return null;
    // r.jina.ai returns JSON error if blocked — check
    if (text.includes('AuthenticationRequiredError') || text.includes('"code":401')) {
      return null;
    }
    return { markdown: text };
  } catch (e) {
    console.log(`[robust-fetch] r.jina.ai failed: ${String(e).slice(0, 100)}`);
    return null;
  }
}

function buildSecurityHeadersSection(headers: Record<string, string>): string {
  const lines: string[] = [];
  if (headers['content-security-policy']) lines.push(`CSP: ${headers['content-security-policy'].slice(0, 300)}`);
  else lines.push('CSP: MISSING (XSS risk)');
  if (headers['x-frame-options']) lines.push(`X-Frame-Options: ${headers['x-frame-options']}`);
  else lines.push('X-Frame-Options: MISSING (clickjacking risk)');
  if (headers['strict-transport-security']) lines.push(`HSTS: ${headers['strict-transport-security']}`);
  else lines.push('HSTS: MISSING (MITM risk)');
  if (headers['x-content-type-options']) lines.push(`X-Content-Type-Options: ${headers['x-content-type-options']}`);
  else lines.push('X-Content-Type-Options: MISSING (MIME sniffing risk)');
  if (headers['access-control-allow-origin'] === '*') lines.push('CORS: Allow-Origin: * (any-origin API access)');
  if (headers['server']) lines.push(`Server: ${headers['server']} (tech fingerprint)`);
  if (headers['x-powered-by']) lines.push(`X-Powered-By: ${headers['x-powered-by']} (tech fingerprint)`);
  // Cookie security
  const setCookie = headers['set-cookie'];
  if (setCookie) {
    const issues: string[] = [];
    if (!setCookie.toLowerCase().includes('httponly')) issues.push('Missing HttpOnly (XSS can steal)');
    if (!setCookie.toLowerCase().includes('secure')) issues.push('Missing Secure (sent over HTTP)');
    if (!setCookie.toLowerCase().includes('samesite')) issues.push('Missing SameSite (CSRF risk)');
    if (issues.length > 0) lines.push(`Cookie issues: ${issues.join(', ')}`);
  }
  return lines.join('\n');
}

/**
 * Main entry — robust URL fetcher with WAF bypass.
 * Returns within 20s max. Either success data OR clear error.
 */
export async function robustFetchUrl(targetUrl: string): Promise<RobustFetchResult> {
  const parsed = new URL(targetUrl);
  const hostname = parsed.hostname.replace(/\./g, '_');
  const urlStr = parsed.toString();

  // SSRF check
  const ssrfCheck = isSsrfBlocked(targetUrl);
  if (ssrfCheck.blocked) {
    return {
      sourceCode: '',
      contractName: hostname,
      url: urlStr,
      title: hostname,
      fetched: false,
      method: 'failed',
      error: `URL blocked by SSRF protection: ${ssrfCheck.reason}`,
    };
  }

  // Strategy 1: Direct fetch with Chrome UA (best — gets HTML + headers)
  console.log(`[robust-fetch] Strategy 1: direct fetch for ${urlStr}`);
  let directResult = await tryDirectFetch(urlStr, BROWSER_HEADERS);

  // Strategy 1b: If Chrome UA failed, try Googlebot UA (sometimes bypasses WAF)
  if (!directResult) {
    console.log(`[robust-fetch] Chrome UA failed, trying Googlebot UA...`);
    directResult = await tryDirectFetch(urlStr, GOOGLEBOT_HEADERS);
    if (directResult) directResult.headers['x-fetched-via'] = 'googlebot';
  }

  if (directResult) {
    // Success — build full analysis source
    const recon = extractQuickRecon(directResult.html, parsed.hostname);
    const secHeaders = buildSecurityHeadersSection(directResult.headers);

    const sourceCode = `// Target: ${urlStr}
// Fetched via: direct (${directResult.headers['x-fetched-via'] || 'chrome'})
// HTTP status: ${directResult.status}
// Title: ${recon.title}
// Fetched at: ${new Date().toISOString()}

== SECURITY HEADERS ==
${secHeaders}

== PAGE RECON ==
${recon.recon}

== HTML CONTENT (first 30000 chars) ==
${directResult.html.slice(0, 30000)}

== HACKENPROOF PRIORITY ==
CRITICAL: Payment manipulation, SQL Injection, RCE, Business logic with fund loss
HIGH: Stored XSS, SSRF, Sensitive data exposure, Auth Bypass, IDOR
MEDIUM: Reflected XSS, 2FA bypass, CSRF
LOW: HTML Injection, Rate limiting missing on non-critical

== ACTIVE VALIDATION ENABLED ==
The system will send REAL HTTP requests with payloads to discovered
endpoints/params to confirm exploitability. Report findings you are
confident the active validators can confirm with a real HTTP probe.
`;

    return {
      sourceCode,
      contractName: hostname,
      url: urlStr,
      title: recon.title,
      fetched: true,
      method: directResult.headers['x-fetched-via'] === 'googlebot' ? 'googlebot' : 'direct',
    };
  }

  // Strategy 2: r.jina.ai reader (bypasses WAF, returns markdown)
  console.log(`[robust-fetch] Direct failed, trying r.jina.ai reader...`);
  const jinaResult = await tryJinaReader(urlStr);

  if (jinaResult) {
    // Success via Jina — we have markdown but no HTTP headers
    // AI can still analyze the content for vulnerabilities
    const sourceCode = `// Target: ${urlStr}
// Fetched via: r.jina.ai (WAF bypass reader)
// Note: HTTP headers NOT available (jina returns markdown content only)
// Fetched at: ${new Date().toISOString()}

== PAGE CONTENT (Markdown, via r.jina.ai reader) ==
${jinaResult.markdown.slice(0, 30000)}

== HACKENPROOF PRIORITY ==
CRITICAL: Payment manipulation, SQL Injection, RCE, Business logic with fund loss
HIGH: Stored XSS, SSRF, Sensitive data exposure, Auth Bypass, IDOR
MEDIUM: Reflected XSS, 2FA bypass, CSRF
LOW: HTML Injection, Rate limiting missing on non-critical

== ACTIVE VALIDATION ENABLED ==
The system will send REAL HTTP requests with payloads to discovered
endpoints/params to confirm exploitability. Report findings you are
confident the active validators can confirm with a real HTTP probe.

== NOTE ON WAF-PROTECTED TARGETS ==
This target is behind a WAF (Cloudflare/AWS WAF/etc.) — direct HTTP
fetches return 403/challenge page. Content was retrieved via r.jina.ai
reader service which bypasses WAF. Active validation may be limited
because direct HTTP requests to the target will be WAF-blocked.
`;

    // Extract title from markdown (first line typically)
    const titleMatch = jinaResult.markdown.match(/^Title:\s*(.+)$/m);
    const title = titleMatch?.[1]?.trim() || hostname;

    return {
      sourceCode,
      contractName: hostname,
      url: urlStr,
      title,
      fetched: true,
      method: 'jina',
    };
  }

  // All strategies failed
  return {
    sourceCode: '',
    contractName: hostname,
    url: urlStr,
    title: hostname,
    fetched: false,
    method: 'failed',
    error: `Could not fetch ${urlStr} — all strategies failed (direct + googlebot + jina).

Tried:
1. Direct fetch (Chrome UA + Googlebot UA) — failed (WAF-blocked or unreachable)
2. r.jina.ai reader — failed (rate-limited or blocked)

The site may be:
- Behind a strict WAF (Cloudflare, AWS WAF) that blocks ALL non-browser requests
- Geo-blocking our VPS region (Brazil)
- Requiring authentication

Suggestions:
- Try a different URL
- Paste the page source code directly into the analyzer
- Use a GitHub URL for smart contract analysis`,
  };
}
