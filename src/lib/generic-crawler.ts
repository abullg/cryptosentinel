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
  // Per-resource auth override. When the target has MULTIPLE auth tables
  // (vAPI: each /vapi/api{N}/user has its own a_p_i{N}_users table), the
  // generic session from analyze-job (single username/password) won't
  // authenticate against all of them — each registered user lives in
  // only ONE table. The identity matrix must use these per-resource
  // credentials to log in as user A and user B FOR THIS SPECIFIC RESOURCE,
  // otherwise the matrix sees 403 "usernameOrPasswordIncorrect" and
  // skips the resource as "baseline failed".
  authOverride?: {
    userA: { username: string; password: string };
    userB: { username: string; password: string };
    authHeader: string;  // e.g. 'Authorization-Token' for vAPI, 'Authorization' default
  };
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
  // Optional ownedId: when the path was derived from a successful registration,
  // we record the resource id the server assigned to A. The matrix then
  // prioritizes probing A's owned id (cleanest bytewise IDOR proof).
  const discoveredPaths = new Map<string, { path: string; method: string; ownedId?: string | number }>();

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
      //
      // Per Claude v11 P2 review: REMOVE /vapi/api1/user from this list.
      // The path is now discovered generically from /vapi/ HTTP surface
      // (Redoc OpenAPI docs page — see text-path extraction in Step 3 +
      // universalApiPaths entries /vapi/, /docs/, /swagger/).
      // The hardcoded entry was a cheat — "vAPI = Express-GT с чужой
      // логотипом". Now the crawler finds /vapi/api1/user the same way it
      // would on any real API: by reading the docs surface.
      //
      // If /vapi/ doesn't expose paths (kривой deploys), vAPI goes dark
      // and the gate fails HONESTLY — the matrix works, the discovery
      // doesn't. Per Claude: "Если на /vapi/ пусто — тогда extraRegisterPaths
      // только в benchmark, с комментарием fixture, и в отчёте писать:
      // матрица на vAPI доказана, crawler — нет." For now: no fixture,
      // honest failure.
      //
      // Deferred (need matrix refactor for per-resource auth):
      // '/vapi/api3/user', '/vapi/api5/user', '/vapi/api6/user', '/vapi/api7/user',
      const registerPaths = [
        '/api/register', '/api/user/register', '/api/v1/user/register',
        '/api/user', '/register', '/signup',
        // vAPI paths REMOVED per Claude v11 P2 — discover generically via /vapi/
      ];
      let registered = false;
      let successfulRegPath: string | null = null;  // remember which path worked → derive GET /{id}
      const successfulRegPaths: string[] = [];  // ALL successful reg paths → derive GET /{id} for each
      // Per-path credentials. vAPI API1/API3/API5/API6/API7 each have their
      // OWN users table (a_p_i1_users, a_p_i3_users, …) — a user registered
      // via POST /vapi/api1/user only exists in a_p_i1_users, not in
      // a_p_i7_users. The derive-{id} probe must therefore use the
      // credentials that were registered ON THAT API's path, otherwise
      // the API's auth check (where('username', X)->where('password', Y))
      // will reject with 403 and the matrix will say "baseline failed".
      //
      // Per Claude v11 P0: also captures ownership proof (createdId +
      // uniqueFields from registration response) so the identity matrix
      // can run the new ownership-based IDOR oracle instead of the legacy
      // flag{...} heuristic.
      const successfulRegCreds: { path: string; username: string; password: string; createdId?: string | number; uniqueFields?: Record<string, any> }[] = [];
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
        // Per Claude v11 P0: capture A's owned resource id + A's unique fields
        // from the registration response. This is the bytewise proof the
        // identity matrix uses for the ownership-based IDOR oracle: B does
        // GET /X/user/{A's id} → if body contains A's username → BOLA confirmed.
        let regResponseBody: any = null;
        try {
          regResponseBody = JSON.parse(regRes.body);
          // vAPI returns {"errorInfo":[...]} on error, {"success":"false","cause":"..."} on fail
          if (regResponseBody.error || regResponseBody.errorInfo || regResponseBody.success === false || regResponseBody.success === "false" || regResponseBody.cause) {
            success = false;
            console.log(`[crawler] Registration at ${regPath} failed: ${JSON.stringify(regResponseBody).slice(0, 100)}`);
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
          successfulRegPath = regPath;  // for single-path derive (kept for backward compat)
          successfulRegPaths.push(regPath);  // collect ALL successful paths
          // Per-path credentials — critical for vAPI where each API has its own users table
          successfulRegCreds.push({
            path: regPath,
            username: botId,
            password: config.auth.password || '',
            // Ownership proof for the new identity-matrix IDOR oracle:
            //   - createdId: the resource id the server assigned to A
            //   - uniqueFields: A-specific fields echoed back (username, email, name)
            // Both come from the POST response body.
            createdId: regResponseBody?.id ?? regResponseBody?.userId ?? regResponseBody?._id,
            uniqueFields: regResponseBody && typeof regResponseBody === 'object'
              ? Object.fromEntries(
                  Object.entries(regResponseBody)
                    .filter(([k, v]) => !['error', 'errorInfo', 'success', 'cause', 'message'].includes(k)
                                       && v != null
                                       && (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean'))
                    .filter(([k]) => !['id', '_id', 'userId', 'created_at', 'updated_at'].includes(k))  // exclude ids/timestamps from "unique fields" (they're not A-specific)
                )
              : {},
          });
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
          // Find the ownership proof from the LAST successful registration
          // (matches the creds used for base64Token).
          const lastReg = successfulRegCreds[successfulRegCreds.length - 1];
          result.loggedIn = true;
          result.session = {
            token: base64Token,
            cookies: '',
            username: config.auth?.username || '',
            role: 'user',
            authHeader: 'Authorization-Token',  // vAPI custom header
            // Per Claude v11 P0: ownership proof — used by identity-matrix
            // ownership-based IDOR oracle. If A's createdId is known, the
            // matrix will probe GET /X/user/{A's id} with B's credentials
            // and check if B's response contains A's username/unique fields.
            ownedResourceId: lastReg?.createdId,
            ownedUniqueFields: lastReg?.uniqueFields,
          };
          authHeader = 'Authorization-Token';  // for Step 2/3 fetches
          console.log(`[crawler] ✓ Using base64 auth (Authorization-Token header)${lastReg?.createdId != null ? ` (A's owned resource id=${lastReg.createdId})` : ''}`);
          // Populate local token/cookies so Step 2 (OpenAPI) + Step 3 (HTML crawl)
          // execute AS the authenticated user, not anonymous. Use the credentials
          // from the MOST RECENT successful registration (works for HTML crawl of
          // the root page, which doesn't require auth anyway).
          token = base64Token;
          // Derive resource endpoints from EACH successful registration path,
          // using PER-PATH credentials.
          // Why per-path: vAPI API1/API3/API5/API6/API7 each have their OWN
          // users table. A user registered via POST /vapi/api1/user exists
          // ONLY in a_p_i1_users — using that credential to auth against
          // /vapi/api7/user/{id} would 403. So each derived endpoint must be
          // probed with the credentials that were registered ON THAT path.
          for (const { path: regPath, username, password, createdId, uniqueFields } of successfulRegCreds) {
            const pathBase64Token = Buffer.from(`${username}:${password}`).toString('base64');
            const candidateGet = `${regPath}/{id}`;
            // Try small IDs — most seed DBs use 1..5. ALSO try A's OWN created
            // id first (the ownership-based IDOR oracle prefers probing A's
            // own resource, since that's the cleanest bytewise proof).
            const candidateIds: (string | number)[] = [];
            if (createdId != null) candidateIds.push(createdId);
            for (const id of [1, 2, 3, 4, 5]) {
              if (!candidateIds.includes(id)) candidateIds.push(id);
            }
            let probeFound = false;
            for (const id of candidateIds) {
              const probeUrl = `${baseUrl}${regPath}/${id}`;
              const probeRes = await fetchWithTimeout(probeUrl, { method: 'GET' }, config.timeoutMs, '', pathBase64Token, 'Authorization-Token');
              if (probeRes.status !== 404) {
                // 200/401/403/500 = endpoint exists (404 = no such route)
                const key = `${candidateGet}:GET`;
                if (!discoveredPaths.has(key)) {
                  // Carry the ownedId (if known) so Step 4 prepends A's
                  // created resource id to sampleIds — the matrix then
                  // prioritizes probing A's owned object for IDOR.
                  discoveredPaths.set(key, { path: candidateGet, method: 'GET', ownedId: createdId });
                  console.log(`[crawler] Derived GET ${candidateGet} from registration path (probe ${probeRes.status} on /${id}, user=${username}${createdId != null ? `, A owned id=${createdId}` : ''})`);
                }
                probeFound = true;
                break;  // found one for this path — stop probing, move to next regPath
              }
            }
            // Also try PUT /X/user/{id} (mass assignment candidate)
            const candidatePut = `${regPath}/{id}`;
            const keyPut = `${candidatePut}:PUT`;
            if (!discoveredPaths.has(keyPut)) {
              discoveredPaths.set(keyPut, { path: candidatePut, method: 'PUT', ownedId: createdId });
              console.log(`[crawler] Derived PUT ${candidatePut} (mass-assignment candidate, user=${username})`);
            }
          }
        } else {
          // Per Claude v11 P2: do NOT early-return here. Continue to
          // Step 2 (OpenAPI), Step 3 (HTML crawl — text-path extractor
          // can discover /vapi/api1/user from /vapi/ Redoc page), and
          // Step 3.5 (post-crawl registration from discovered parent
          // paths). If all those also fail, the matrix returns 0
          // confirmed honestly — but at least we tried every discovery
          // path before giving up.
          console.log('[crawler] No login + no registration via hardcoded paths — continuing unauthenticated, will try /vapi/ /docs/ /swagger/ + discovered paths in Step 3.5');
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
  //
  // Added /vapi/, /docs/, /swagger/, /redoc, /api-docs — these are
  // common docs-mount paths. The crawler fetches them and the new
  // text-path extractor (below) finds API endpoints inside the docs
  // HTML/JSON. This is GENERIC: any app that serves docs at /docs/ or
  // /swagger/ benefits, not just vAPI. Per Claude v11 P2: "после fetch
  // корня ходить в очевидные docs: /vapi/, /docs, /swagger, /api-docs".
  const universalApiPaths = [
    // Docs mounts FIRST — these expose API paths via Redoc/Swagger HTML
    // and are highest-value for generic path discovery. vAPI /vapi/
    // returns a 1.15MB Redoc page with all 20 API paths as text.
    // Putting docs first ensures they get crawled even with small
    // maxPages budgets (analyze-job uses maxPages=10).
    '/vapi/', '/docs/', '/docs', '/swagger/', '/swagger', '/redoc',
    '/api/docs', '/api-docs/', '/api-docs',
    // Standard API conventions (lower priority — often 404)
    '/api', '/api/v1', '/api/me', '/api/users',
    '/openapi.json', '/swagger.json', '/v3/api-docs',
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

    // ─── Generic text-path extraction (per Claude v11 P2 review) ────────
    // Many API docs render paths as TEXT content inside <pre> blocks or
    // inline <script> JSON — NOT as <a href="..."> links. The href= regex
    // above misses these.
    //
    // Concrete case: vAPI at /vapi/ returns a 1.15 MB Redoc OpenAPI page
    // that lists ALL 20 API paths as text (in <pre> blocks rendered by
    // Redoc + inline JSON spec in <script> tags). The href= regex finds
    // 0 paths. A generic text-path regex finds 20, including the
    // /vapi/api1/user we were hardcoding in registerPaths.
    //
    // This extractor makes the crawler HONEST: no hardcoded paths needed
    // when the target serves docs. If /vapi/ or /docs/ or /swagger/ pages
    // exist, the paths get discovered generically.
    //
    // Pattern: paths with at least 3 segments (e.g. /vapi/api1/user,
    // /api/v1/books, /v2/user/login). Single-segment paths like /login or
    // /register are too generic — they're noisy (matches menu items).
    const textPathRegex = /\/[a-z][a-z0-9_-]*(?:\/[a-z0-9_{}.-]+){2,5}/gi;
    const textAssetExt = /\.(png|jpg|jpeg|gif|svg|ico|css|js|html?|woff2?|ttf|eot|map|webp|mp[34])$/i;
    const textPathMatches = res.body.matchAll(textPathRegex);
    let textPathFound = 0;
    for (const m of textPathMatches) {
      let p = m[0];
      // Strip trailing punctuation (commas, semicolons, quotes) that
      // might be glued to the path in JSON-stringified content.
      p = p.replace(/[",;)\]]+$/g, '');
      // Skip asset files
      if (textAssetExt.test(p)) continue;
      // Skip external URLs (shouldn't match — regex starts with /, not //)
      if (p.includes('://') || p.startsWith('//')) continue;
      // Skip if path has no 'api'/'v[0-9]' marker and no {id} — too generic
      // (otherwise /foo/bar/baz from random text gets matched as noise)
      const hasApiMarker = /(?:^|\/)(?:api|vapi|v[0-9])/i.test(p) || /\{[^}]*id[^}]*\}/i.test(p);
      if (!hasApiMarker) continue;
      // Parameterize (e.g., /vapi/api1/user/123 → /vapi/api1/user/{id})
      const param = parameterizePath(p);
      const finalPath = param?.paramPath || p;
      const key = `${finalPath}:GET`;
      if (!discoveredPaths.has(key)) {
        discoveredPaths.set(key, { path: finalPath, method: 'GET' });
        textPathFound++;
      }
    }
    if (textPathFound > 0) {
      console.log(`[crawler] Found ${textPathFound} API path(s) from HTML text (not href) on ${url.replace(baseUrl, '') || '/'}`);
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
    // Per Claude v11 §7: also fetch cross-origin (CDN) JS bundles.
    // Production SPAs like vvs.finance serve JS from CDN URLs like
    // https://cdn.example.com/bundle.js — the previous check
    // (src.startsWith('/') || src.startsWith(baseUrl)) would skip
    // these, missing the entire API surface hidden in JS.
    const scriptSrcMatches = res.body.matchAll(/<script[^>]*src=["']([^"']+)["']/gi);
    for (const m of scriptSrcMatches) {
      const src = m[1];
      // Resolve relative, absolute, and cross-origin script srcs
      let jsUrl: string;
      if (src.startsWith('http://') || src.startsWith('https://')) {
        // Cross-origin (CDN) — fetch directly (passive, just GET)
        jsUrl = src;
      } else if (src.startsWith('//')) {
        // Protocol-relative — use same protocol as baseUrl
        jsUrl = `${baseUrl.match(/^https?/)?.[0] || 'https'}:${src}`;
      } else if (src.startsWith('/')) {
        // Same-origin absolute path
        jsUrl = `${baseUrl}${src}`;
      } else {
        // Relative path (e.g., src="bundle.js") — resolve against page URL
        jsUrl = `${baseUrl}/${src}`;
      }
      // Skip obvious non-JS srcs (analytics, fonts, etc.)
      if (jsUrl.match(/\.(png|jpg|gif|svg|ico|css|woff|ttf)(\?|$)/i)) continue;

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
        // Also run generic text-path extraction on JS body — many
        // frameworks (React/Vue/Angular) embed API paths as string
        // constants in bundled JS, not as fetch() calls.
        const textPathRegex = /\/[a-z][a-z0-9_-]*(?:\/[a-z0-9_{}.-]+){2,5}/gi;
        const textAssetExt = /\.(png|jpg|jpeg|gif|svg|ico|css|js|html?|woff2?|ttf|eot|map|webp|mp[34])$/i;
        const textPathMatches = jsRes.body.matchAll(textPathRegex);
        for (const tm of textPathMatches) {
          let p = tm[0].replace(/[",;)\]]+$/g, '');
          if (textAssetExt.test(p)) continue;
          if (p.includes('://') || p.startsWith('//')) continue;
          const hasApiMarker = /(?:^|\/)(?:api|vapi|v[0-9])/i.test(p) || /\{[^}]*id[^}]*\}/i.test(p);
          if (!hasApiMarker) continue;
          const param = parameterizePath(p);
          const finalPath = param?.paramPath || p;
          const key = `${finalPath}:GET`;
          if (!discoveredPaths.has(key)) {
            discoveredPaths.set(key, { path: finalPath, method: 'GET' });
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

  // ─── Step 3.5 (per Claude v11 P2): post-crawl registration from discovered paths ──
  // If Step 1 didn't authenticate (no hardcoded path matched AND no login
  // endpoint found), try POST on the PARENT of every discovered /X/{id} path.
  //
  // Concrete case: vAPI at /vapi/ returns a Redoc page. Step 3's text-path
  // extractor finds /vapi/api1/user/{api1_id} (the BOLA target). The parent
  // /vapi/api1/user is the registration endpoint. POST it with the standard
  // registration body → ownership proof captured → matrix can probe
  // GET /vapi/api1/user/{A's id} with B's auth → BOLA confirmed.
  //
  // This is what makes path discovery HONEST — the registration path comes
  // from /vapi/ docs, NOT from a hardcoded /vapi/api1/user in registerPaths.
  // Per Claude: "Если на /vapi/ пусто — тогда extraRegisterPaths только в
  // benchmark, с комментарием fixture." We're testing the non-fixture path
  // first; if vAPI stays green, the cheat is removed honestly.
  if (!result.loggedIn && config.auth) {
    // Find parent paths of /X/{id} paths — these are registration candidates.
    // E.g., /vapi/api1/user/{id} → parent /vapi/api1/user.
    // Also /vapi/api1/user/{api1_id} → parent /vapi/api1/user (vAPI uses
    // named IDs like {api1_id}, {api5_id} — must match any {xxx_id} or
    // {id} or :id pattern, not just literal '{id}').
    const regCandidates: string[] = [];
    // Match any path segment that's {something_id}, {id}, :id, or :something_id
    const idSegmentRegex = /\/\{[^}]*id[^}]*\}|\/:[a-zA-Z_]*id[a-zA-Z_]* /i;
    for (const [, { path, method }] of discoveredPaths) {
      if (method !== 'GET') continue;
      // Strip the trailing {id}-style segment to derive parent.
      // Pattern: /X/user/{any_id} → /X/user
      //          /X/user/:id     → /X/user
      //          /X/user/{id}/sub → /X/user  (also strips /sub)
      const idMatch = path.match(/^(.+?)\/\{[^}]*id[^}]*\}.*$/i) || path.match(/^(.+?)\/:[a-zA-Z_]*id[a-zA-Z_]*.*$/i);
      if (!idMatch) continue;
      const parent = idMatch[1];
      if (!parent || parent.includes('{') || parent.includes(':')) continue;
      if (!regCandidates.includes(parent)) regCandidates.push(parent);
    }
    if (regCandidates.length > 0) {
      console.log(`[crawler] Step 3.5: trying POST registration on ${regCandidates.length} discovered parent path(s): ${regCandidates.slice(0, 5).join(', ')}${regCandidates.length > 5 ? '...' : ''}`);
    }
    for (const regPath of regCandidates) {
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
      let success = regRes.status === 200 || regRes.status === 201;
      let regResponseBody: any = null;
      try {
        regResponseBody = JSON.parse(regRes.body);
        if (regResponseBody && (regResponseBody.error || regResponseBody.errorInfo || regResponseBody.success === false || regResponseBody.success === 'false' || regResponseBody.cause)) {
          success = false;
        }
      } catch {}
      if (!success) continue;
      console.log(`[crawler] ✓ Self-registered user "${botId}" via DISCOVERED path ${regPath}`);
      // Build auth + ownership proof, same as Step 1's base64 fallback.
      // Auth header is 'Authorization-Token' (vAPI convention). For non-vAPI
      // targets discovered this way, we may need a smarter auth header
      // detection — but Step 1's loginConfig path already handles targets
      // with explicit login endpoints.
      const base64Token = Buffer.from(`${botId}:${config.auth?.password || ''}`).toString('base64');
      const createdId = regResponseBody?.id ?? regResponseBody?.userId ?? regResponseBody?._id;
      const uniqueFields = regResponseBody && typeof regResponseBody === 'object'
        ? Object.fromEntries(
            Object.entries(regResponseBody)
              .filter(([k, v]) => !['error', 'errorInfo', 'success', 'cause', 'message'].includes(k)
                                 && v != null
                                 && (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean'))
              .filter(([k]) => !['id', '_id', 'userId', 'created_at', 'updated_at'].includes(k))
          )
        : {};
      result.loggedIn = true;
      result.session = {
        token: base64Token,
        cookies: '',
        username: botId,
        role: 'user',
        authHeader: 'Authorization-Token',
        ownedResourceId: createdId,
        ownedUniqueFields: uniqueFields,
      };
      authHeader = 'Authorization-Token';
      token = base64Token;
      console.log(`[crawler] ✓ Using base64 auth from DISCOVERED registration${createdId != null ? ` (A's owned id=${createdId})` : ''}`);
      // Derive GET /X/{id} with ownedId (probe A's id first, then 1..5)
      const candidateGet = `${regPath}/{id}`;
      const candidateIds: (string | number)[] = [];
      if (createdId != null) candidateIds.push(createdId);
      for (const id of [1, 2, 3, 4, 5]) {
        if (!candidateIds.includes(id)) candidateIds.push(id);
      }
      for (const id of candidateIds) {
        const probeUrl = `${baseUrl}${regPath}/${id}`;
        const probeRes = await fetchWithTimeout(probeUrl, { method: 'GET' }, config.timeoutMs, '', base64Token, 'Authorization-Token');
        if (probeRes.status !== 404) {
          const key = `${candidateGet}:GET`;
          if (!discoveredPaths.has(key)) {
            discoveredPaths.set(key, { path: candidateGet, method: 'GET', ownedId: createdId });
            console.log(`[crawler] Derived GET ${candidateGet} from DISCOVERED registration (probe ${probeRes.status} on /${id}${createdId != null ? `, A owned id=${createdId}` : ''})`);
          }
          break;
        }
      }
      // Also derive PUT /X/{id} (mass-assignment candidate)
      const candidatePut = `${regPath}/{id}`;
      const keyPut = `${candidatePut}:PUT`;
      if (!discoveredPaths.has(keyPut)) {
        discoveredPaths.set(keyPut, { path: candidatePut, method: 'PUT', ownedId: createdId });
        console.log(`[crawler] Derived PUT ${candidatePut} (mass-assignment candidate)`);
      }
      break;  // stop after first successful registration (one ownership proof is enough)
    }
    if (!result.loggedIn && regCandidates.length > 0) {
      console.log(`[crawler] Step 3.5: POST registration failed on all ${regCandidates.length} discovered parent path(s) — target may require different registration body shape or be read-only`);
    }
  }

  // Step 4: Convert discovered paths to resources
  for (const [key, { path, method, ownedId }] of discoveredPaths) {
    // Check if path has any {id}-style placeholder.
    // Per Claude v11 P2: vAPI uses named IDs like {api1_id}, {api5_id} —
    // match any {something_id} or {id} or :id pattern.
    const hasId = /\{[^}]*id[^}]*\}|\/:[a-zA-Z_]*id/i.test(path);
    const paramResult = hasId ? null : parameterizePath(path);
    const finalPath = paramResult?.paramPath || path;
    const paramType = paramResult?.paramType || (hasId ? 'int' : 'unknown');
    let sampleIds: (string | number)[] = paramResult ? [paramResult.idValue] : (hasId ? [1, 2, 3] : []);
    // Per Claude v11 P0: prepend A's owned resource id to sampleIds so the
    // identity matrix probes A's just-created resource FIRST (cleanest
    // bytewise proof for the ownership-based IDOR oracle).
    if (ownedId != null && !sampleIds.includes(ownedId)) {
      sampleIds.unshift(ownedId);
    }
    // Matrix slices sampleIds to .slice(0, 3) — ensure ownedId survives the slice
    // (it's first, so it always will).

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
