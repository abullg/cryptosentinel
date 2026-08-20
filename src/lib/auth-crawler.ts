/**
 * Authenticated crawler — login to DVWA and crawl vulnerable endpoints.
 *
 * DVWA structure:
 *   GET  /login.php           → get PHPSESSID + user_token (CSRF)
 *   POST /login.php           → username=admin&password=password&user_token=TOKEN&Login=Login
 *   GET  /vulnerabilities/sqli/   → form with id parameter (SQLi)
 *   GET  /vulnerabilities/xss_r/  → form with name parameter (reflected XSS)
 *   GET  /vulnerabilities/xss_s/  → stored XSS
 *   GET  /vulnerabilities/exec/   → command execution
 *   GET  /vulnerabilities/fi/     → file inclusion
 *   GET  /vulnerabilities/csrf/    → CSRF
 *   GET  /vulnerabilities/captcha/ → weak captcha
 *   GET  /vulnerabilities/brute/   → brute force
 *   GET  /vulnerabilities/upload/ → file upload
 *
 * After login, the crawler discovers all /vulnerabilities/* endpoints,
 * extracts form parameters, and returns them for the active fuzzer.
 */

export interface AuthEndpoint {
  url: string;
  method: 'GET' | 'POST';
  parameters: { name: string; type: 'query' | 'body'; required: boolean }[];
  vulnerabilityType: string;  // sqli, xss, csrf, etc.
  cookies: string;
}

export interface AuthCrawlResult {
  loggedIn: boolean;
  cookies: string;
  endpoints: AuthEndpoint[];
  securityLevel: 'low' | 'medium' | 'high' | 'impossible';
}

const DVWA_ENDPOINTS = [
  { path: '/vulnerabilities/sqli/', param: 'id', vulnType: 'sqli', method: 'GET' as const },
  { path: '/vulnerabilities/sqli_blind/', param: 'id', vulnType: 'sqli_blind', method: 'GET' as const },
  { path: '/vulnerabilities/xss_r/', param: 'name', vulnType: 'reflected_xss', method: 'GET' as const },
  { path: '/vulnerabilities/xss_s/', param: 'mtxMessage', vulnType: 'stored_xss', method: 'POST' as const },
  { path: '/vulnerabilities/exec/', param: 'ip', vulnType: 'command_injection', method: 'POST' as const },
  { path: '/vulnerabilities/fi/', param: 'page', vulnType: 'file_inclusion', method: 'GET' as const },
  { path: '/vulnerabilities/csrf/', param: 'password_new', vulnType: 'csrf', method: 'GET' as const },
  { path: '/vulnerabilities/brute/', param: 'username', vulnType: 'brute_force', method: 'GET' as const },
  { path: '/vulnerabilities/captcha/', param: 'recaptcha_response_field', vulnType: 'weak_captcha', method: 'GET' as const },
  { path: '/vulnerabilities/upload/', param: 'uploaded', vulnType: 'file_upload', method: 'POST' as const },
];

/**
 * Login to DVWA and get session cookie.
 * Returns cookies string or null if login failed.
 */
async function loginDvwa(baseUrl: string): Promise<string | null> {
  console.log(`[auth-crawler] Logging into DVWA at ${baseUrl}/login.php`);

  // Step 1: GET /login.php to get PHPSESSID + user_token
  const loginPageRes = await fetch(`${baseUrl}/login.php`, {
    headers: { 'User-Agent': 'CryptoSentinel-AuthCrawler/1.0' },
    signal: AbortSignal.timeout(10_000),
    redirect: 'manual',
  });

  // Extract Set-Cookie headers (PHPSESSID)
  const setCookie = loginPageRes.headers.get('set-cookie') || '';
  const phpsessid = setCookie.match(/PHPSESSID=([^;]+)/)?.[1] || '';
  if (!phpsessid) {
    console.warn('[auth-crawler] No PHPSESSID cookie received');
    return null;
  }
  console.log(`[auth-crawler] Got PHPSESSID: ${phpsessid.slice(0, 8)}...`);

  // Extract user_token from HTML
  const loginHtml = await loginPageRes.text();
  const userToken = loginHtml.match(/user_token'\s*value\s*=\s*'([^']+)'/i)?.[1]
    || loginHtml.match(/name="user_token"\s+value="([^"]+)"/i)?.[1]
    || '';
  if (!userToken) {
    console.warn('[auth-crawler] No user_token found in login page');
    // Try login without token (DVWA low security doesn't always require it)
  }
  console.log(`[auth-crawler] Got user_token: ${userToken ? userToken.slice(0, 8) + '...' : '(none)'}`);

  // Step 2: POST /login.php with credentials
  const loginBody = new URLSearchParams({
    username: 'admin',
    password: 'password',
    Login: 'Login',
    ...(userToken ? { user_token: userToken } : {}),
  }).toString();

  const loginRes = await fetch(`${baseUrl}/login.php`, {
    method: 'POST',
    headers: {
      'User-Agent': 'CryptoSentinel-AuthCrawler/1.0',
      'Content-Type': 'application/x-www-form-urlencoded',
      'Cookie': `PHPSESSID=${phpsessid}; security=low`,
    },
    body: loginBody,
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000),
  });

  // Check if login succeeded (302 redirect to index.php = success)
  const location = loginRes.headers.get('location') || '';
  if (loginRes.status === 302 && location.includes('index.php')) {
    console.log(`[auth-crawler] ✓ Login successful (302 → ${location})`);
    return `PHPSESSID=${phpsessid}; security=low`;
  }

  // Check response body for "Welcome" or "login_failed"
  const loginRespHtml = await loginRes.text();
  if (loginRespHtml.includes('Welcome') || loginRespHtml.includes('You have logged in')) {
    console.log('[auth-crawler] ✓ Login successful (Welcome message)');
    return `PHPSESSID=${phpsessid}; security=low`;
  }

  console.warn(`[auth-crawler] Login failed — status ${loginRes.status}, location ${location}`);
  return null;
}

/**
 * Set DVWA security level to 'low' (most vulnerable).
 * GET /security.php with security=low cookie.
 */
async function setSecurityLow(baseUrl: string, cookies: string): Promise<void> {
  try {
    await fetch(`${baseUrl}/security.php`, {
      headers: {
        'User-Agent': 'CryptoSentinel-AuthCrawler/1.0',
        'Cookie': cookies,
      },
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    // Non-critical — DVWA might accept security=low from cookie alone
  }
}

/**
 * Crawl DVWA authenticated endpoints and return form parameters.
 *
 * @param baseUrl DVWA base URL (e.g. http://localhost:3002)
 * @returns AuthCrawlResult with endpoints + cookies
 */
export async function crawlDvwa(baseUrl: string): Promise<AuthCrawlResult> {
  // Step 1: Login
  const cookies = await loginDvwa(baseUrl);
  if (!cookies) {
    return {
      loggedIn: false,
      cookies: '',
      endpoints: [],
      securityLevel: 'low',
    };
  }

  // Step 2: Set security to low
  await setSecurityLow(baseUrl, cookies);

  // Step 3: Crawl each known endpoint
  const endpoints: AuthEndpoint[] = [];
  for (const ep of DVWA_ENDPOINTS) {
    const url = `${baseUrl}${ep.path}`;
    try {
      const res = await fetch(url, {
        headers: {
          'User-Agent': 'CryptoSentinel-AuthCrawler/1.0',
          'Cookie': cookies,
        },
        signal: AbortSignal.timeout(10_000),
      });
      const html = await res.text();

      // Check if endpoint exists (200 + has form)
      if (res.status === 200 && html.includes('<form')) {
        endpoints.push({
          url,
          method: ep.method,
          parameters: [{ name: ep.param, type: ep.method === 'POST' ? 'body' : 'query', required: true }],
          vulnerabilityType: ep.vulnType,
          cookies,
        });
        console.log(`[auth-crawler]   ✓ Found endpoint: ${ep.path} (param: ${ep.param})`);
      } else {
        console.log(`[auth-crawler]   ✗ Endpoint not accessible: ${ep.path} (status ${res.status})`);
      }
    } catch (e) {
      console.warn(`[auth-crawler]   ✗ Failed to fetch ${ep.path}: ${String(e).slice(0, 80)}`);
    }
  }

  console.log(`[auth-crawler] Crawl complete: ${endpoints.length}/${DVWA_ENDPOINTS.length} endpoints found`);

  return {
    loggedIn: true,
    cookies,
    endpoints,
    securityLevel: 'low',
  };
}

/**
 * Generic auth crawler — detect target type and use appropriate login.
 */
export async function crawlAuthenticated(
  baseUrl: string,
): Promise<AuthCrawlResult> {
  if (baseUrl.includes('3002') || baseUrl.includes('dvwa')) {
    return crawlDvwa(baseUrl);
  }
  // Add juice-shop, crAPI, etc. auth handlers here later
  return { loggedIn: false, cookies: '', endpoints: [], securityLevel: 'low' };
}
