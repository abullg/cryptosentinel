/**
 * CryptoSentinel — SIMPLE URL Fetcher
 *
 * Previous versions were over-engineered with deep BFS, multi-proxy
 * parallel fallbacks, Wayback Machine, JS bundle analysis — all of
 * which added failure points. User reported endless hangs and errors.
 *
 * This version is DEAD SIMPLE:
 *  1. Direct fetch (10s timeout)
 *  2. If fails OR WAF-blocked → allorigins proxy (10s timeout)
 *  3. If both fail → return HTTP 408 with clear error message
 *
 * Total time: max 20s. User always gets a response within 30s.
 *
 * Returned data is enough for AI to analyze:
 *  - Page HTML (first 30K chars)
 *  - Security headers
 *  - Title
 *  - Quick recon (scripts found, forms found, endpoints found in HTML)
 *
 * No deep BFS. No JS bundle downloads. No Wayback. No rate-limited
 * multi-proxy chains. Just ONE successful fetch and we're done.
 */
import { isSsrfBlocked } from './ssrf';

const BROWSER_HEADERS: Record<string, string> = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.9',
};

const FETCH_TIMEOUT = 10_000; // 10s per fetch attempt

export interface SimpleFetchResult {
  sourceCode: string;       // Recon text for AI analysis
  contractName: string;
  url: string;
  title: string;
  fetched: boolean;
  method: 'direct' | 'proxy' | 'failed';
  error?: string;
}

function isWafChallenge(html: string): boolean {
  if (html.length > 50000) return false;
  const lower = html.toLowerCase();
  return [
    'cf-challenge', 'cloudflare', 'aws-waf', 'perimeterx',
    'datadome', 'akamai-bot-manager', 'imperva', 'incapsula',
    'under attack', 'checking your browser', 'access restricted',
    'please wait while we verify',
  ].some(ind => lower.includes(ind));
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

  lines.push(`Title: ${title}`);
  lines.push(`Scripts found: ${scriptSrcs.length}`);
  for (const s of scriptSrcs) lines.push(`  - ${s}`);
  lines.push(`API endpoints in HTML: ${apiEndpoints.length}`);
  for (const e of apiEndpoints) lines.push(`  - ${e}`);
  lines.push(`Forms: ${formActions.length}`);
  for (const f of formActions) lines.push(`  - ${f}`);

  // Detect crypto/wallet patterns
  const lowerHtml = html.toLowerCase();
  const cryptoPatterns: string[] = [];
  if (lowerHtml.includes('metamask')) cryptoPatterns.push('MetaMask integration');
  if (lowerHtml.includes('walletconnect')) cryptoPatterns.push('WalletConnect');
  if (lowerHtml.includes('web3')) cryptoPatterns.push('Web3');
  if (lowerHtml.includes('personal_sign') || lowerHtml.includes('signmessage')) cryptoPatterns.push('Message signing (signature replay risk)');
  if (cryptoPatterns.length > 0) {
    lines.push(`Crypto patterns: ${cryptoPatterns.join(', ')}`);
  }

  // Detect XSS sinks in inline JS
  if (/\.innerHTML\s*=|document\.write\s*\(/.test(html)) lines.push('XSS sink: innerHTML/document.write present');
  if (/\beval\s*\(/.test(html)) lines.push('XSS sink: eval() present');
  if (/postMessage\s*\(/.test(html)) lines.push('postMessage present (verify origin check)');

  // localStorage usage
  const lsMatch = html.match(/localStorage\.setItem\s*\(\s*["']([^"']*(?:token|key|secret|auth|session|password|wallet|private)[^"']*)["']/i);
  if (lsMatch) lines.push(`localStorage stores sensitive key: "${lsMatch[1]}"`);

  return { title, recon: lines.join('\n'), scriptSrcs, apiEndpoints, formActions };
}

async function tryDirectFetch(url: string): Promise<{ html: string; headers: Record<string, string>; status: number } | null> {
  try {
    const res = await fetch(url, {
      headers: BROWSER_HEADERS,
      redirect: 'follow',
      signal: AbortSignal.timeout(FETCH_TIMEOUT),
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    const html = await res.text();
    if (html.length < 100) return null;
    if (isWafChallenge(html)) return null;
    return { html, headers, status: res.status };
  } catch { return null; }
}

async function tryProxyFetch(url: string): Promise<{ html: string; headers: Record<string, string> } | null> {
  // Single proxy — allorigins. No multi-proxy parallel (caused rate-limiting).
  // No Wayback (too slow). Just one proxy, one try.
  try {
    const proxyUrl = `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`;
    const res = await fetch(proxyUrl, {
      headers: { 'User-Agent': 'Mozilla/5.0' },
      signal: AbortSignal.timeout(FETCH_TIMEOUT),
    });
    if (!res.ok) return null;
    const html = await res.text();
    if (html.length < 100) return null;
    if (isWafChallenge(html)) return null;
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    return { html, headers };
  } catch { return null; }
}

/**
 * Main entry — simple, fast, reliable URL fetcher.
 * Returns within 30s max. Either success data OR clear error.
 */
export async function simpleFetchUrl(targetUrl: string): Promise<SimpleFetchResult> {
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

  // Step 1: Direct fetch (10s)
  console.log(`[simple-fetch] Direct fetch for ${urlStr}`);
  let result = await tryDirectFetch(urlStr);

  // Step 2: If direct failed or WAF-blocked, try allorigins proxy (10s)
  if (!result) {
    console.log(`[simple-fetch] Direct failed, trying allorigins proxy...`);
    result = await tryProxyFetch(urlStr);
  }

  // Step 3: If both failed, return clear error
  if (!result) {
    return {
      sourceCode: '',
      contractName: hostname,
      url: urlStr,
      title: hostname,
      fetched: false,
      method: 'failed',
      error: `Could not fetch ${urlStr} within 20s. The site may be:
1. Behind a WAF (Cloudflare, AWS WAF) that blocks our requests
2. Geo-blocking our VPS region
3. Too slow to respond

Suggestions:
- Try a different URL
- Paste the page source code directly into the analyzer
- Use a GitHub URL for smart contract analysis`,
    };
  }

  // Build recon text for AI
  const recon = extractQuickRecon(result.html, parsed.hostname);

  // Security headers analysis
  const secHeaders: string[] = [];
  const h = result.headers;
  if (h['content-security-policy']) secHeaders.push(`CSP: ${h['content-security-policy'].slice(0, 200)}`);
  else secHeaders.push('CSP: MISSING (XSS risk)');
  if (h['x-frame-options']) secHeaders.push(`X-Frame-Options: ${h['x-frame-options']}`);
  else secHeaders.push('X-Frame-Options: MISSING (clickjacking risk)');
  if (h['strict-transport-security']) secHeaders.push(`HSTS: present`);
  else secHeaders.push('HSTS: MISSING (MITM risk)');
  if (h['x-content-type-options']) secHeaders.push(`X-Content-Type-Options: ${h['x-content-type-options']}`);
  if (h['access-control-allow-origin'] === '*') secHeaders.push('CORS: Allow-Origin: * (any-origin access)');
  if (h['server']) secHeaders.push(`Server: ${h['server']}`);
  if (h['x-powered-by']) secHeaders.push(`X-Powered-By: ${h['x-powered-by']} (tech fingerprint)`);

  // Cookie analysis
  const setCookie = h['set-cookie'];
  if (setCookie) {
    const cookieIssues: string[] = [];
    if (!setCookie.toLowerCase().includes('httponly')) cookieIssues.push('Missing HttpOnly');
    if (!setCookie.toLowerCase().includes('secure')) cookieIssues.push('Missing Secure');
    if (!setCookie.toLowerCase().includes('samesite')) cookieIssues.push('Missing SameSite');
    if (cookieIssues.length > 0) secHeaders.push(`Cookie issues: ${cookieIssues.join(', ')}`);
  }

  const method = result.headers['x-fetched-via-proxy'] ? 'proxy' : 'direct';

  // Build the analysis source for AI
  const sourceCode = `// Target: ${urlStr}
// Fetched via: ${method}
// HTTP status: ${result.status}
// Title: ${recon.title}
// Fetched at: ${new Date().toISOString()}

== SECURITY HEADERS ==
${secHeaders.join('\n')}

== PAGE RECON ==
${recon.recon}

== HTML CONTENT (first 30000 chars) ==
${result.html.slice(0, 30000)}

== HACKENPROOF PRIORITY ==
CRITICAL: Payment manipulation, SQL Injection, RCE, Business logic with fund loss
HIGH: Stored XSS, SSRF, Sensitive data exposure, Auth Bypass, IDOR
MEDIUM: Reflected XSS, 2FA bypass, CSRF
LOW: HTML Injection, Rate limiting missing on non-critical

== ACTIVE VALIDATION ==
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
    method,
  };
}
