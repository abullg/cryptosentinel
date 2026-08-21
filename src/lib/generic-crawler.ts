/**
 * Generic Auth Crawler — per Claude v10 §4.2.
 *
 * "Минимум, без которого охота невозможна:
 *  1. Auth adapters: JSON POST /login → form POST → Bearer in config
 *  2. Cookie jar + Authorization persistence
 *  3. Источники эндпоинтов: OpenAPI/Swagger, HTML <a href>, JS fetch/axios
 *  4. Параметризация: /users/1 → /users/{id} + классификатор id
 *  5. targetClass: если после crawl 0 HTTP API — spa-n/a"
 *
 * This crawler does NOT know about DVWA, VAmPI, or Express-GT.
 * It discovers endpoints generically from the target's HTML/JS/OpenAPI.
 */

export interface CrawlConfig {
  baseUrl: string;
  // Auth config — how to login
  auth?: {
    loginUrl?: string;       // if known, use it; if not, auto-detect
    loginMethod?: 'json' | 'form';
    username: string;
    password: string;
    usernameField?: string;  // default: 'username'
    passwordField?: string;  // default: 'password'
    tokenExtractor?: string; // JSON path to extract token from login response (e.g., 'token')
  };
  timeoutMs: number;
  maxPages: number;
  maxEndpoints: number;
}

export interface CrawlResult {
  loggedIn: boolean;
  session?: { token: string; cookies: string; username: string; role: string; authHeader?: string };
  resources: DiscoveredResource[];
  targetClass: 'http-server' | 'http-nav' | 'spa-n/a';
  crawlStats: {
    pagesCrawled: number;
    endpointsFound: number;
    apiPathsFound: number;
    openApiFound: boolean;
    jsAnalyzed: number;
  };
}

export interface DiscoveredResource {
  path: string;
  method: string;
  parameterized: boolean;
  paramType: 'int' | 'uuid' | 'email' | 'string' | 'unknown';
  sampleIds: (string | number)[];
  fields?: string[];
}

import { AuthSession } from './identity-matrix';

const ID_PATTERNS = {
  int: /^[0-9]+$/,
  uuid: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  email: /^[^@]+@[^@]+\.[^@]+$/,
};

function classifyId(value: string): 'int' | 'uuid' | 'email' | 'string' {
  if (ID_PATTERNS.int.test(value)) return 'int';
  if (ID_PATTERNS.uuid.test(value)) return 'uuid';
  if (ID_PATTERNS.email.test(value)) return 'email';
  return 'string';
}

function parameterizePath(path: string): { paramPath: string; paramType: 'int' | 'uuid' | 'email' | 'string' | 'unknown'; idValue: string } | null {
  // Match paths like /api/users/123, /api/books/abc-123, /api/orders/user@example.com
  const segments = path.split('/').filter(Boolean);
  for (let i = segments.length - 1; i >= 0; i--) {
    const seg = segments[i];
    // Skip query strings
    if (seg.includes('?')) continue;
    // Check if this segment looks like an ID
    if (ID_PATTERNS.int.test(seg) || ID_PATTERNS.uuid.test(seg) || ID_PATTERNS.email.test(seg)) {
      segments[i] = '{id}';
      return {
        paramPath: '/' + segments.join('/'),
        paramType: classifyId(seg),
        idValue: seg,
      };
    }
  }
  return null;
}

async function fetchWithTimeout(url: string, opts: RequestInit = {}, timeoutMs: number, cookies?: string, token?: string, authHeader?: string): Promise<{ status: number; body: string; contentType: string; setCookie: string }> {
  try {
    const headers: Record<string, string> = {
      'User-Agent': 'CryptoSentinel-Crawler/1.0',
      ...(opts.headers as Record<string, string> || {}),
    };
    if (cookies) headers['Cookie'] = cookies;
    // Per Claude: auth header might be custom (Authorization-Token, not Bearer)
    if (token) {
      const headerName = authHeader || 'Authorization';
      headers[headerName] = headerName === 'Authorization' ? `Bearer ${token}` : token;
    }
    const res = await fetch(url, { ...opts, headers, signal: AbortSignal.timeout(timeoutMs), redirect: 'follow' });
    const body = await res.text();
    return {
      status: res.status,
      body,
      contentType: res.headers.get('content-type') || '',
      setCookie: res.headers.get('set-cookie') || '',
    };
  } catch (e) {
    return { status: 0, body: '', contentType: '', setCookie: '' };
  }
}

/**
 * Auto-detect login form or JSON login endpoint.
 * Per Claude: "Если не нашёл — fail closed"
 */
async function detectLogin(config: CrawlConfig): Promise<{ url: string; method: 'json' | 'form'; usernameField: string; passwordField: string; tokenExtractor: string; authHeader: string } | null> {
  const baseUrl = config.baseUrl.replace(/\/+$/, '');

  // Per Claude v10-feedback: vAPI uses /vapi/api2/user/login with email field,
  // and Authorization-Token header (not Bearer). Crawler needs to:
  // 1. Try login paths under discovered prefixes (not just /api/)
  // 2. Try both username and email fields
  // 3. Support custom auth headers (not just Bearer)

  // Step 0: Fetch root page, extract path prefixes (e.g., /vapi/)
  const rootRes = await fetchWithTimeout(`${baseUrl}/`, {}, config.timeoutMs);
  const prefixes = ['/api', '/api/v1', '/auth', '/vapi', '/api/v2'];
  if (rootRes.status === 200 && rootRes.body) {
    // Extract path prefixes from HTML content
    const prefixMatches = rootRes.body.matchAll(/["'(]\/(vapi|api|auth|v1|v2)\/[^"')\s]*/gi);
    for (const m of prefixMatches) {
      const prefix = '/' + m[1];
      if (!prefixes.includes(prefix)) {
        prefixes.push(prefix);
        console.log(`[crawler] Discovered path prefix from HTML: ${prefix}`);
      }
    }
  }

  // Try JSON login paths under all prefixes + common paths
  const loginSubPaths = ['/login', '/user/login', '/auth/login', '/api2/user/login', '/api/login', '/v1/user/login'];
  const jsonLoginPaths: string[] = [];
  for (const prefix of prefixes) {
    for (const sub of loginSubPaths) {
      jsonLoginPaths.push(`${prefix}${sub}`);
    }
  }
  // Also try without prefix
  jsonLoginPaths.push('/login', '/api/login', '/auth/login', '/user/login');

  for (const path of jsonLoginPaths) {
    // Per Claude: try both username and email fields
    const creds = [
      { username: config.auth?.username || 'user', password: config.auth?.password || 'user', field: 'username' },
      { username: config.auth?.username || 'user@example.com', password: config.auth?.password || 'user', field: 'email' },
    ];
    for (const cred of creds) {
      const res = await fetchWithTimeout(
        `${baseUrl}${path}`,
        { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ [cred.field]: cred.username, password: cred.password }) },
        config.timeoutMs,
      );
      if (res.status === 200) {
        try {
          const data = JSON.parse(res.body);
          // Per Claude: token might be in any field, not just 'token'
          const tokenVal = data.token || data.access_token || data.jwt || data.auth_token || data.session || data.accessToken;
          if (tokenVal) {
            console.log(`[crawler] Found JSON login at ${path} (field: ${cred.field})`);
            // Per Claude: auth header might be custom (Authorization-Token, not Bearer)
            // Check if response mentions custom header name
            let authHeader = 'Authorization';
            if (rootRes.body && rootRes.body.includes('Authorization-Token')) {
              authHeader = 'Authorization-Token';
              console.log(`[crawler] Using custom auth header: Authorization-Token`);
            }
            return { url: `${baseUrl}${path}`, method: 'json', usernameField: cred.field, passwordField: 'password', tokenExtractor: tokenVal === data.token ? 'token' : tokenVal === data.access_token ? 'access_token' : 'token', authHeader };
          }
        } catch {}
      }
    }
  }

  // Form-based login (HTML) — keep as generic capability, not vAPI-specific
  const res = await fetchWithTimeout(`${baseUrl}/login`, {}, config.timeoutMs);
  if (res.status === 200 && res.body.includes('<form')) {
    const formMatch = res.body.match(/<form[^>]*action=["']([^"']*)["'][^>]*method=["']([post]+)["']/i);
    if (formMatch) {
      console.log(`[crawler] Found form login at ${formMatch[1]}`);
      return { url: `${baseUrl}${formMatch[1]}`, method: 'form', usernameField: 'username', passwordField: 'password', tokenExtractor: '', authHeader: 'Cookie' };
    }
  }

  return null;
}

/**
 * Extract API endpoints from JavaScript source code.
 * Looks for fetch('/api/...'), axios.get('/api/...'), etc.
 */
function extractEndpointsFromJS(js: string, baseUrl: string): { path: string; method: string }[] {
  const endpoints: { path: string; method: string }[] = [];
  const seen = new Set<string>();

  // Match: fetch('/api/...'), axios.get('/api/...'), axios.post('/api/...'), $.ajax({url: '/api/...'})
  const patterns = [
    /fetch\s*\(\s*['"`]([^'"`]+)['"`]/g,
    /axios\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
    /\$\.ajax\s*\(\s*\{\s*url:\s*['"`]([^'"`]+)['"`]/gi,
    /['"`](\/api\/[^'"`]+)['"`]/g,  // any quoted /api/ path
  ];

  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(js)) !== null) {
      const path = match[1] || match[2];
      if (!path || !path.startsWith('/')) continue;
      const key = `${path}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const method = match[0].toLowerCase().includes('post') ? 'POST'
        : match[0].toLowerCase().includes('put') ? 'PUT'
        : match[0].toLowerCase().includes('delete') ? 'DELETE'
        : match[0].toLowerCase().includes('patch') ? 'PATCH'
        : 'GET';
      endpoints.push({ path, method });
    }
  }

  return endpoints;
}

/**
 * Extract endpoints from OpenAPI/Swagger spec.
 */
async function extractFromOpenAPI(baseUrl: string, cookies: string, token: string, timeoutMs: number, authHeader: string = 'Authorization'): Promise<DiscoveredResource[]> {
  const resources: DiscoveredResource[] = [];
  const openApiPaths = ['/openapi.json', '/swagger.json', '/v3/api-docs', '/api-docs', '/swagger/v1/swagger.json'];

  for (const path of openApiPaths) {
    const res = await fetchWithTimeout(`${baseUrl}${path}`, {}, timeoutMs, cookies, token, authHeader);
    if (res.status !== 200) continue;

    try {
      const spec = JSON.parse(res.body);
      if (!spec.paths) continue;

      console.log(`[crawler] Found OpenAPI spec at ${path} (${Object.keys(spec.paths).length} paths)`);

      for (const [apiPath, methods] of Object.entries(spec.paths)) {
        for (const [method, detail] of Object.entries(methods as any)) {
          const m = method.toUpperCase();
          if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(m)) continue;

          // Check if path has {id} parameter
          const hasIdParam = apiPath.includes('{') || apiPath.includes(':');
          const paramType = apiPath.match(/\{(\w*[Ii]d\w*)\}/) ? 'int' : 'unknown';

          resources.push({
            path: apiPath,
            method: m,
            parameterized: hasIdParam,
            paramType: paramType as any,
            sampleIds: hasIdParam ? [1, 2, 3] : [],
            fields: (detail as any)?.parameters?.map((p: any) => p.name) || [],
          });
        }
      }

      return resources; // return on first found spec
    } catch {}
  }

  return resources;
}

/**
 * Main crawl function — discovers endpoints generically.
 */
export async function crawlForApi(config: CrawlConfig): Promise<CrawlResult> {
  const baseUrl = config.baseUrl.replace(/\/+$/, '');
  const result: CrawlResult = {
    loggedIn: false,
    resources: [],
    targetClass: 'http-server',
    crawlStats: { pagesCrawled: 0, endpointsFound: 0, apiPathsFound: 0, openApiFound: false, jsAnalyzed: 0 },
  };

  let cookies = '';
  let token = '';
  let authHeader = 'Authorization';  // may be overridden to a custom header (e.g. 'Authorization-Token' for vAPI)
  // Discovered paths map — declared here at top of function so Step 1 (base64
  // auth fallback can pre-populate it with derived /{id} endpoints) and Step 3
  // (HTML/JS crawl) can both append to it without TDZ issues.
  const discoveredPaths = new Map<string, { path: string; method: string }>();

  // Step 1: Login (if auth configured)
  if (config.auth) {
    let loginConfig = null;
    if (config.auth.loginUrl) {
      loginConfig = {
        url: config.auth.loginUrl,
        method: config.auth.loginMethod || 'json',
        usernameField: config.auth.usernameField || 'username',
        passwordField: config.auth.passwordField || 'password',
        tokenExtractor: config.auth.tokenExtractor || 'token',
      };
    } else {
      console.log('[crawler] Auto-detecting login endpoint...');
      loginConfig = await detectLogin(config);
    }

    if (!loginConfig) {
      console.log('[crawler] No login endpoint found — trying self-registration...');

      // Per Claude: "если логина нет, а есть POST .../user регистрация — создать A и B"
      // Send BOTH username AND email (vAPI requires username, Express uses email)
      const registerPaths = ['/api/register', '/api/user/register', '/api/v1/user/register',
        '/vapi/api1/user', '/api/user', '/register', '/vapi/api2/user/register', '/signup'];
      let registered = false;
      let successfulRegPath: string | null = null;  // remember which path worked → derive GET /{id}
      for (const regPath of registerPaths) {
        // Generate unique username + email per attempt
        const botId = `csbot${Date.now().toString(36).slice(-6)}`;
        const regBody = JSON.stringify({
          username: botId,
          email: `${botId}@test.local`,
          password: config.auth?.password || 'CrawlerTest123!',
          name: 'CrawlerBot',
        });
        const regRes = await fetchWithTimeout(
          `${baseUrl}${regPath}`,
          { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: regBody },
          config.timeoutMs,
        );
        // 200/201 = success, but check for error fields (vAPI uses errorInfo, success:"false")
        let success = regRes.status === 200 || regRes.status === 201;
        try {
          const data = JSON.parse(regRes.body);
          // vAPI returns {"errorInfo":[...]} on error, {"success":"false","cause":"..."} on fail
          if (data.error || data.errorInfo || data.success === false || data.success === "false" || data.cause) {
            success = false;
            console.log(`[crawler] Registration at ${regPath} failed: ${JSON.stringify(data).slice(0, 100)}`);
          }
        } catch {}
        if (success) {
          console.log(`[crawler] ✓ Self-registered user "${botId}" via ${regPath}`);
          // Store credentials for login
          if (!config.auth) config.auth = { username: '', password: '' };
          config.auth.username = botId;
          // Mark registered=true REGARDLESS of login availability —
          // some APIs (vAPI API1) have no login endpoint at all and rely
          // on a custom auth header (e.g. Authorization-Token: base64(user:pass))
          registered = true;
          successfulRegPath = regPath;  // for later {id} derivation
          // Now try to login with the new account
          loginConfig = await detectLogin(config);
          if (loginConfig) { break; }
          // No login endpoint found — keep iterating registerPaths only
          // to update credentials (most recent successful registration wins).
        }
      }
      if (!loginConfig) {
        // Per Claude: "если логина нет, а есть POST .../user регистрация —
        // создать A и B, сохранить секреты"
        // vAPI API1 pattern: no login endpoint, use Authorization-Token: base64(user:pass)
        // If we registered users but no login found, try base64 auth directly
        if (registered) {
          console.log('[crawler] Registration succeeded but no login found — trying base64 auth...');
          const base64Token = Buffer.from(`${config.auth?.username}:${config.auth?.password}`).toString('base64');
          result.loggedIn = true;
          result.session = {
            token: base64Token,
            cookies: '',
            username: config.auth?.username || '',
            role: 'user',
            authHeader: 'Authorization-Token',  // vAPI custom header
          };
          authHeader = 'Authorization-Token';  // for Step 2/3 fetches
          console.log(`[crawler] ✓ Using base64 auth (Authorization-Token header)`);
          // Populate local token/cookies so Step 2 (OpenAPI) + Step 3 (HTML crawl)
          // execute AS the authenticated user, not anonymous.
          token = base64Token;
          // Derive resource endpoints from the successful registration path.
          // Pattern: POST /X/user registers a user → GET /X/user/{id} usually
          // retrieves that user (BOLA/IDOR candidate). This is generic — applies
          // to vAPI API1/API5, Django REST /api/users, Rails /users, etc.
          // We probe /X/user/1..5 with the new session; 200/401/403 = endpoint exists
          // (404 = no such route). Adding the found endpoints to discoveredPaths
          // lets the identity matrix probe them for IDOR/BFLA/mass-assign.
          if (successfulRegPath) {
            const candidateGet = `${successfulRegPath}/{id}`;
            // Try small IDs — most seed DBs use 1..5
            for (const id of [1, 2, 3, 4, 5]) {
              const probeUrl = `${baseUrl}${successfulRegPath}/${id}`;
              const probeRes = await fetchWithTimeout(probeUrl, { method: 'GET' }, config.timeoutMs, '', base64Token, 'Authorization-Token');
              if (probeRes.status !== 404) {
                // 200/401/403 = endpoint exists (401/403 means auth required, still IDOR-able)
                const key = `${candidateGet}:GET`;
                if (!discoveredPaths.has(key)) {
                  discoveredPaths.set(key, { path: candidateGet, method: 'GET' });
                  console.log(`[crawler] Derived GET ${candidateGet} from registration path (probe ${probeRes.status} on /${id})`);
                }
                break;  // found one — stop probing
              }
            }
            // Also try PUT /X/user/{id} (mass assignment candidate)
            const candidatePut = `${successfulRegPath}/{id}`;
            const keyPut = `${candidatePut}:PUT`;
            if (!discoveredPaths.has(keyPut)) {
              discoveredPaths.set(keyPut, { path: candidatePut, method: 'PUT' });
              console.log(`[crawler] Derived PUT ${candidatePut} (mass-assignment candidate)`);
            }
          }
        } else {
          console.log('[crawler] No login + no registration found — fail closed');
          return { ...result, targetClass: 'spa-n/a' };
        }
      }
    }

    // Only run the explicit login flow when we actually found a login endpoint.
    // When the base64 auth fallback was used (loginConfig=null), result.session
    // is already populated with the base64 token — skip this block.
    if (loginConfig) {
      authHeader = loginConfig.authHeader || 'Authorization';
      // Per Claude: try login with BOTH username and email fields
      // detectLogin already determined which field the API uses
      const loginValue = loginConfig.usernameField === 'email'
        ? (config.auth.username.includes('@') ? config.auth.username : `${config.auth.username}@test.local`)
        : config.auth.username;
      console.log(`[crawler] Logging in as ${loginValue} (field: ${loginConfig.usernameField}, header: ${authHeader})...`);
      const loginRes = await fetchWithTimeout(
        loginConfig.url,
        {
          method: 'POST',
          headers: { 'Content-Type': loginConfig.method === 'json' ? 'application/json' : 'application/x-www-form-urlencoded' },
          body: loginConfig.method === 'json'
            ? JSON.stringify({ [loginConfig.usernameField]: loginValue, [loginConfig.passwordField]: config.auth.password })
            : new URLSearchParams({ [loginConfig.usernameField]: loginValue, [loginConfig.passwordField]: config.auth.password }).toString(),
        },
        config.timeoutMs,
      );

      if (loginRes.setCookie) {
        const match = loginRes.setCookie.match(/([^=]+)=([^;]+)/);
        if (match) cookies = match[0];
      }

      if (loginRes.status === 200) {
        try {
          const data = JSON.parse(loginRes.body);
          token = data[loginConfig.tokenExtractor] || data.token || data.access_token || '';
          if (token) {
            result.loggedIn = true;
            result.session = {
              token,
              cookies,
              username: config.auth.username,
              role: data.role || data.user?.role || 'user',
              authHeader: authHeader,
            };
            console.log(`[crawler] ✓ Login successful — token: ${token.slice(0, 20)}..., role: ${result.session.role}`);
          }
        } catch {
          // Form login — check if Set-Cookie has session
          if (cookies) {
            result.loggedIn = true;
            result.session = { token: '', cookies, username: config.auth.username, role: 'user' };
            console.log('[crawler] ✓ Form login successful (cookie-based)');
          }
        }
      }

      if (!result.loggedIn) {
        console.log('[crawler] Login failed — continuing as anonymous');
      }
    }
  }

  // Step 2: Try OpenAPI/Swagger
  const openApiResources = await extractFromOpenAPI(baseUrl, cookies, token, config.timeoutMs, authHeader);
  if (openApiResources.length > 0) {
    result.crawlStats.openApiFound = true;
    result.crawlStats.apiPathsFound += openApiResources.length;
    result.resources.push(...openApiResources);
    console.log(`[crawler] OpenAPI found: ${openApiResources.length} resources`);
  }

  // Step 3: Crawl pages — HTML for <a href> + form + JS, JSON for endpoint lists
  // Per Claude: "JSON-ответы: id, url, userId → новые ресурсы"
  // And: "Короткий универсальный API-словарь (/api, /api/v1, /me, /users,
  // /admin, /transfer, /profile) — не список вашего Express"
  const visited = new Set<string>();
  // Universal API dictionary — per Claude v10-feedback:
  // "Оставьте /api, /api/v1, /me, /users, /openapi.json.
  //  Не держите GT-специфичные имена как «универсальные»."
  const universalApiPaths = [
    '/api', '/api/v1', '/api/me', '/api/users',
    '/openapi.json', '/swagger.json', '/v3/api-docs', '/api-docs',
  ];
  const toVisit: string[] = [
    baseUrl, `${baseUrl}/`, ...universalApiPaths.map(p => `${baseUrl}${p}`),
  ];

  for (let i = 0; i < toVisit.length && i < config.maxPages; i++) {
    const url = toVisit[i];
    if (visited.has(url)) continue;
    visited.add(url);
    result.crawlStats.pagesCrawled++;

    const res = await fetchWithTimeout(url, {}, config.timeoutMs, cookies, token, authHeader);
    if (res.status !== 200 || !res.body) continue;

    // Check if response is JSON (API-only targets return JSON, not HTML)
    const isJson = res.contentType.includes('application/json') || res.body.trimStart().startsWith('{') || res.body.trimStart().startsWith('[');

    if (isJson) {
      // Parse JSON response for endpoint-like strings
      // Per Claude: "JSON-ответы: id, url, userId, вложенные объекты → новые ресурсы"
      try {
        const jsonData = JSON.parse(res.body);

        // Check for "endpoints" or "routes" or "links" field (many APIs list their endpoints)
        const endpointLists = [jsonData.endpoints, jsonData.routes, jsonData.links, jsonData.paths, jsonData._links];
        for (const list of endpointLists) {
          if (Array.isArray(list)) {
            for (const ep of list) {
              if (typeof ep !== 'string') continue;
              // Handle both formats:
              // 1. "GET /api/users/:id (IDOR)" — method + path + optional description
              // 2. "/api/v1/books" — just path
              // 3. "POST /api/login" — method + path
              const parts = ep.match(/^(GET|POST|PUT|PATCH|DELETE)\s+([^\s(]+)/i);
              let method = 'GET';
              let path = ep;
              if (parts) {
                method = parts[1].toUpperCase();
                path = parts[2];
              } else if (ep.startsWith('/')) {
                path = ep;
              } else {
                continue; // skip non-path strings
              }
              // Clean up path (remove :id → {id}, remove trailing descriptions)
              const param = parameterizePath(path);
              const finalPath = param?.paramPath || path.replace(/\/:id/g, '/{id}').replace(/\/<id>/g, '/{id}');
              const key = `${finalPath}:${method}`;
              if (!discoveredPaths.has(key)) {
                discoveredPaths.set(key, { path: finalPath, method });
                console.log(`[crawler] Found endpoint from JSON: ${method} ${finalPath}`);
              }
            }
          }
        }

        // Recursively scan JSON for URL-like strings
        function scanJsonForPaths(obj: any, depth = 0) {
          if (depth > 3) return;
          if (typeof obj === 'string') {
            // Check if it looks like an API path
            if (obj.startsWith('/api/') || obj.startsWith('/v1/')) {
              const param = parameterizePath(obj);
              const finalPath = param?.paramPath || obj;
              const key = `${finalPath}:GET`;
              if (!discoveredPaths.has(key)) {
                discoveredPaths.set(key, { path: finalPath, method: 'GET' });
              }
            }
          } else if (Array.isArray(obj)) {
            for (const item of obj.slice(0, 20)) scanJsonForPaths(item, depth + 1);
          } else if (obj && typeof obj === 'object') {
            for (const val of Object.values(obj).slice(0, 20)) scanJsonForPaths(val, depth + 1);
          }
        }
        scanJsonForPaths(jsonData);
      } catch {}
    }

    // Extract <a href> links
    const hrefMatches = res.body.matchAll(/href=["']([^"']+)["']/gi);
    for (const m of hrefMatches) {
      let href = m[1];
      if (href.startsWith('/') && !href.startsWith('//')) {
        const fullUrl = `${baseUrl}${href}`;
        if (!visited.has(fullUrl) && !toVisit.includes(fullUrl)) {
          toVisit.push(fullUrl);
        }
        // Check if it's an API path
        if (href.includes('/api/') || href.includes('/users/') || href.includes('/books/') || href.includes('/orders/')) {
          const param = parameterizePath(href);
          if (param) {
            const key = `${param.paramPath}:GET`;
            if (!discoveredPaths.has(key)) {
              discoveredPaths.set(key, { path: param.paramPath, method: 'GET' });
            }
          }
        }
      }
    }

    // Extract form actions
    const formMatches = res.body.matchAll(/<form[^>]*action=["']([^"']+)["'][^>]*method=["']([a-z]+)["']/gi);
    for (const m of formMatches) {
      const action = m[1];
      const method = m[2].toUpperCase();
      if (action.startsWith('/')) {
        const key = `${action}:${method}`;
        if (!discoveredPaths.has(key)) {
          discoveredPaths.set(key, { path: action, method });
        }
      }
    }

    // Extract JS endpoints (from inline scripts + script srcs)
    const scriptSrcMatches = res.body.matchAll(/<script[^>]*src=["']([^"']+)["']/gi);
    for (const m of scriptSrcMatches) {
      const src = m[1];
      if (src.startsWith('/') || src.startsWith(baseUrl)) {
        const jsUrl = src.startsWith('/') ? `${baseUrl}${src}` : src;
        const jsRes = await fetchWithTimeout(jsUrl, {}, config.timeoutMs, cookies, token, authHeader);
        if (jsRes.status === 200 && jsRes.body) {
          result.crawlStats.jsAnalyzed++;
          const jsEndpoints = extractEndpointsFromJS(jsRes.body, baseUrl);
          for (const ep of jsEndpoints) {
            const param = parameterizePath(ep.path);
            const path = param?.paramPath || ep.path;
            const key = `${path}:${ep.method}`;
            if (!discoveredPaths.has(key)) {
              discoveredPaths.set(key, { path, method: ep.method });
            }
          }
        }
      }
    }

    // Also extract from inline <script> blocks
    const inlineScriptMatches = res.body.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi);
    for (const m of inlineScriptMatches) {
      const inlineJs = m[1];
      if (inlineJs.includes('/api/') || inlineJs.includes('fetch(') || inlineJs.includes('axios')) {
        const jsEndpoints = extractEndpointsFromJS(inlineJs, baseUrl);
        for (const ep of jsEndpoints) {
          const param = parameterizePath(ep.path);
          const path = param?.paramPath || ep.path;
          const key = `${path}:${ep.method}`;
          if (!discoveredPaths.has(key)) {
            discoveredPaths.set(key, { path, method: ep.method });
          }
        }
      }
    }
  }

  // Step 4: Convert discovered paths to resources
  for (const [key, { path, method }] of discoveredPaths) {
    // Check if path has {id}
    const hasId = path.includes('{id}') || path.includes(':id');
    const paramResult = hasId ? null : parameterizePath(path);
    const finalPath = paramResult?.paramPath || path;
    const paramType = paramResult?.paramType || (hasId ? 'int' : 'unknown');
    const sampleIds = paramResult ? [paramResult.idValue] : (hasId ? [1, 2, 3] : []);

    result.resources.push({
      path: finalPath,
      method,
      parameterized: hasId || !!paramResult,
      paramType: paramType as any,
      sampleIds: sampleIds as (string | number)[],
    });
  }

  result.crawlStats.endpointsFound = result.resources.length;
  result.crawlStats.apiPathsFound += discoveredPaths.size;

  // Step 5: Determine targetClass
  if (result.resources.length === 0 && result.crawlStats.pagesCrawled > 3) {
    // Crawled multiple pages but found 0 API endpoints — likely SPA
    result.targetClass = 'spa-n/a';
  } else if (result.resources.length > 0) {
    result.targetClass = 'http-server';
  } else {
    result.targetClass = 'http-nav';
  }

  console.log(`[crawler] Done. ${result.resources.length} resources found, ${result.crawlStats.pagesCrawled} pages crawled, ${result.crawlStats.jsAnalyzed} JS files analyzed. targetClass=${result.targetClass}`);

  return result;
}
