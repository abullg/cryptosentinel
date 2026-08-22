/**
 * Auto-Registrar — automatically registers an account on the TARGET being
 * scanned, so the identity matrix can probe authenticated endpoints without
 * the user manually entering Token A / Token B.
 *
 * Strategy:
 *   1. Take discovered endpoints + forms from deep-crawler
 *   2. Find candidate registration endpoints (POST /register, /signup,
 *      /api/users, /api/v1/users, /api/auth/signup, etc.)
 *   3. For each candidate, POST a JSON body with a unique username + password
 *      (also try form-encoded if JSON returns 415)
 *   4. On 200/201 with no error field → success
 *   5. Parse response for: createdId, token, cookies (Set-Cookie), unique fields
 *   6. Optionally: try to login with the new creds to get a session token
 *
 * Returns RegisteredAccount | null. Never throws — failures are logged and
 * returned as null (the scanner continues without auto-reg).
 */

export interface RegisteredAccount {
  username: string;
  password: string;
  email: string;
  regPath: string;            // e.g. POST /api/users
  method: 'json' | 'form';    // which body type worked
  createdId?: string | number; // id returned by the server (e.g. user.id)
  sessionToken?: string;       // JWT/session token from login
  sessionCookie?: string;      // raw Set-Cookie value
  uniqueFields?: Record<string, any>;  // echoed fields (username, email, etc.)
  responseStatus: number;
}

interface RegistrarInput {
  baseUrl: string;
  discoveredEndpoints: string[];  // from deep-crawler
  discoveredForms: { method: string; action: string; fields: string[] }[];
  timeoutMs?: number;
  // Optional: extra paths to try (e.g. if user knows the registration endpoint)
  extraPaths?: string[];
}

// Path candidates that look like registration endpoints
const REG_PATH_PATTERNS = [
  '/api/register', '/api/signup', '/api/auth/register', '/api/auth/signup',
  '/api/user/register', '/api/users/register', '/api/v1/register',
  '/api/v1/signup', '/api/v1/auth/register', '/api/v1/auth/signup',
  '/api/v1/users', '/api/users', '/api/user', '/api/v1/user',
  '/api/v2/users', '/api/v2/user',
  '/register', '/signup', '/auth/register', '/auth/signup',
  '/users/register', '/users/signup',
  '/account/register', '/account/signup',
  '/member/register', '/member/signup',
];

// Paths that look like login (for post-registration session establishment)
const LOGIN_PATH_PATTERNS = [
  '/api/login', '/api/auth/login', '/api/auth/signin',
  '/api/v1/login', '/api/v1/auth/login', '/api/v1/auth/signin',
  '/api/user/login', '/api/users/login',
  '/login', '/auth/login', '/auth/signin',
];

function isLikelyRegisterPath(path: string): boolean {
  if (!path) return false;
  const p = path.toLowerCase();
  // Must NOT contain {id} or :id (those are GET endpoints, not register)
  if (p.includes('{') || p.includes(':id')) return false;
  // Must look register-ish
  return REG_PATH_PATTERNS.some(cand => p === cand || p.endsWith(cand))
      || /(register|signup|sign-up)/.test(p)
      || /\/api\/[^/]*user[s]?$/.test(p);  // /api/user or /api/users (POST often = register)
}

function isLikelyLoginPath(path: string): boolean {
  if (!path) return false;
  const p = path.toLowerCase();
  if (p.includes('{') || p.includes(':id')) return false;
  return LOGIN_PATH_PATTERNS.some(cand => p === cand || p.endsWith(cand))
      || /(login|signin|sign-in)/.test(p);
}

function buildBaseUrl(url: string): string {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}`;
  } catch {
    return url.replace(/\/.*$/, '');
  }
}

async function tryRegister(
  fullUrl: string,
  botId: string,
  password: string,
  timeoutMs: number,
): Promise<RegisteredAccount | null> => {
  const email = `${botId}@test.local`;
  const jsonBody = JSON.stringify({
    username: botId,
    email,
    password,
    name: 'CryptoSentinel Bot',
    confirmPassword: password,
  });
  const formBody = new URLSearchParams({
    username: botId,
    email,
    password,
    name: 'CryptoSentinel Bot',
    confirmPassword: password,
  }).toString();

  // Try JSON first, then form-encoded
  const attempts: Array<{ method: 'json' | 'form'; body: string; contentType: string }> = [
    { method: 'json', body: jsonBody, contentType: 'application/json' },
    { method: 'form', body: formBody, contentType: 'application/x-www-form-urlencoded' },
  ];

  for (const attempt of attempts) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(fullUrl, {
        method: 'POST',
        headers: {
          'Content-Type': attempt.contentType,
          'User-Agent': 'CryptoSentinelBot/1.0 (security audit; contact admin)',
          'Accept': 'application/json, text/plain, */*',
        },
        body: attempt.body,
        signal: controller.signal,
        redirect: 'manual',  // don't follow redirects — we want the raw response
      });
      clearTimeout(timer);

      // 200/201 = success candidate
      const success = res.status === 200 || res.status === 201;
      // 415 = wrong content-type — try next attempt
      if (res.status === 415) continue;
      // 401/403 = endpoint exists but auth required (not a register endpoint)
      if (res.status === 401 || res.status === 403) return null;
      // 404/405 = endpoint doesn't exist or doesn't accept POST
      if (res.status === 404 || res.status === 405) return null;

      // Extract Set-Cookie if present (sessionCookie)
      const setCookie = res.headers.get('set-cookie') || undefined;

      // Parse response body (try JSON; fall back to text)
      let body: any = null;
      let bodyText = '';
      try {
        bodyText = await res.text();
        try {
          body = JSON.parse(bodyText);
        } catch {
          // Not JSON — keep bodyText
        }
      } catch {}

      if (!success) {
        // 4xx (except above) = registration failed (e.g. user already exists, validation)
        // Don't retry — endpoint exists but rejected our payload
        return null;
      }

      // Check for error fields in body (some APIs return 200 with errorInfo)
      if (body && typeof body === 'object') {
        if (body.error || body.errorInfo || body.success === false || body.success === "false" || body.cause) {
          return null;
        }
      }

      // Success! Extract ownership proof + session info
      const createdId = body?.id ?? body?.userId ?? body?._id ?? body?.user?.id ?? body?.user?._id;
      const sessionToken = body?.token ?? body?.accessToken ?? body?.access_token ?? body?.sessionToken ?? body?.authToken;
      // Collect A-specific unique fields (everything except ids + timestamps)
      const uniqueFields = body && typeof body === 'object'
        ? Object.fromEntries(
            Object.entries(body)
              .filter(([k, v]) => !['error', 'errorInfo', 'success', 'cause', 'message', 'token', 'accessToken', 'access_token', 'sessionToken', 'authToken'].includes(k)
                               && v != null
                               && (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean'))
              .filter(([k]) => !['id', '_id', 'userId', 'created_at', 'updated_at', 'createdAt', 'updatedAt'].includes(k))
          )
        : {};

      // Compute regPath from full URL
      let regPath = '/';
      try {
        const u = new URL(fullUrl);
        regPath = u.pathname;
      } catch {}

      return {
        username: botId,
        password,
        email,
        regPath,
        method: attempt.method,
        createdId,
        sessionToken,
        sessionCookie: setCookie,
        uniqueFields,
        responseStatus: res.status,
      };
    } catch (e: any) {
      clearTimeout(timer);
      const msg = String(e?.message || e);
      if (msg.includes('aborted') || msg.includes('timeout')) {
        return null;  // don't retry on timeout — endpoint too slow
      }
      // Network error — try next attempt
      continue;
    }
  }
  return null;
}

async function tryLogin(
  fullUrl: string,
  username: string,
  password: string,
  timeoutMs: number,
): Promise<{ token?: string; cookie?: string } | null> {
  const jsonBody = JSON.stringify({ username, email: `${username}@test.local`, password });
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(fullUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'CryptoSentinelBot/1.0',
        'Accept': 'application/json',
      },
      body: jsonBody,
      signal: controller.signal,
      redirect: 'manual',
    });
    clearTimeout(timer);
    if (res.status < 200 || res.status >= 300) return null;

    const setCookie = res.headers.get('set-cookie') || undefined;
    let body: any = null;
    try {
      body = await res.json();
    } catch {
      try { await res.text(); } catch {}
    }
    const token = body?.token ?? body?.accessToken ?? body?.access_token ?? body?.sessionToken ?? body?.authToken;
    return { token, cookie: setCookie };
  } catch {
    clearTimeout(timer);
    return null;
  }
}

/**
 * Main entry point. Tries to register an account on the target.
 *
 * @returns RegisteredAccount | null
 */
export async function autoRegister(
  input: RegistrarInput,
): Promise<RegisteredAccount | null> {
  const baseUrl = buildBaseUrl(input.baseUrl);
  const timeoutMs = input.timeoutMs ?? 8000;
  const botId = `csbot${Date.now().toString(36).slice(-6)}${Math.random().toString(36).slice(-2)}`;
  const password = `Cs!${Date.now().toString(36).slice(-6)}${Math.random().toString(36).slice(-2)}`;

  // Collect candidate paths from:
  //   1. Hardcoded REG_PATH_PATTERNS (always try)
  //   2. Discovered endpoints (filter for likely register paths)
  //   3. Discovered forms (POST forms with username+password fields)
  //   4. Extra paths from input (if user provided)
  const candidates: string[] = [];
  for (const p of REG_PATH_PATTERNS) candidates.push(p);
  for (const ep of (input.discoveredEndpoints || [])) {
    if (isLikelyRegisterPath(ep) && !candidates.includes(ep)) candidates.push(ep);
  }
  for (const f of (input.discoveredForms || [])) {
    if (f.method.toUpperCase() === 'POST' && f.action && isLikelyRegisterPath(f.action)) {
      if (!candidates.includes(f.action)) candidates.push(f.action);
    }
  }
  for (const p of (input.extraPaths || [])) {
    if (!candidates.includes(p)) candidates.push(p);
  }

  console.log(`[auto-registrar] Trying ${candidates.length} candidate register paths on ${baseUrl}`);

  // Try each candidate path
  for (const path of candidates) {
    const fullUrl = path.startsWith('http') ? path : `${baseUrl}${path}`;
    console.log(`[auto-registrar]   Trying POST ${fullUrl}...`);
    const result = await tryRegister(fullUrl, botId, password, timeoutMs);
    if (result) {
      console.log(`[auto-registrar] ✓ Registered as ${result.username} via ${result.method} ${path} (status ${result.responseStatus})`);
      // If we don't have a session token, try to login explicitly
      if (!result.sessionToken) {
        const loginCandidates = LOGIN_PATH_PATTERNS
          .filter(p => !candidates.includes(p))
          .slice(0, 3);
        for (const loginPath of loginCandidates) {
          const loginUrl = `${baseUrl}${loginPath}`;
          console.log(`[auto-registrar]   Trying login at ${loginUrl}...`);
          const loginResult = await tryLogin(loginUrl, botId, password, timeoutMs);
          if (loginResult?.token || loginResult?.cookie) {
            if (loginResult.token) result.sessionToken = loginResult.token;
            if (loginResult.cookie) result.sessionCookie = loginResult.cookie;
            console.log(`[auto-registrar] ✓ Got session via login at ${loginPath}`);
            break;
          }
        }
      }
      return result;
    }
  }

  console.log(`[auto-registrar] No registration endpoint found among ${candidates.length} candidates`);
  return null;
}

/**
 * Register TWO accounts for the identity matrix (user A + peer user B).
 * Both accounts have the same role (peer) — required for horizontal IDOR.
 */
export async function autoRegisterPair(
  input: RegistrarInput,
): Promise<{ userA: RegisteredAccount | null; userB: RegisteredAccount | null }> {
  const userA = await autoRegister(input);
  // Small delay so the second account has a different timestamp
  await new Promise(r => setTimeout(r, 200));
  const userB = await autoRegister(input);
  return { userA, userB };
}
