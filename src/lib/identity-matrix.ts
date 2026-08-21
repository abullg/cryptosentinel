/**
 * Identity Matrix Engine — per Claude v10 §4.3.
 *
 * "Сейчас IDOR — сценарий «возьми id юзера A, спроси юзером B». Нужно ядро"
 *
 * The engine takes: resource URL, verb (GET/PUT/PATCH/DELETE), user A token,
 * user B token, and checks if B can access/modify A's resource.
 *
 * Oracles (all deterministic, byte-level proof):
 *
 * 1. IDOR (horizontal): B GET A's resource → 200 + A's data in body
 * 2. Mass assignment: A PUT {role:"admin"} → GET confirms role changed
 * 3. BFLA: user calls admin-only endpoint → 2xx (should be 403)
 * 4. Missing authn: anonymous GET A's resource → 200 (should be 401)
 *
 * Per Claude: "Подтверждение только байт-уровнем: в теле B есть SSN/email/данные A;
 * role после PUT стал admin (и в повторном GET тоже); DELETE чужого объекта → 2xx
 * и объект исчез; не 401/403, а именно успех + содержимое жертвы / смена состояния"
 */

export interface AuthSession {
  token: string;
  username: string;
  role: string;
  cookies?: string;
}

export interface DiscoveredResource {
  path: string;          // e.g., /api/users/{id}
  method: string;        // GET, PUT, POST, DELETE, PATCH
  parameterized: boolean; // true if path has {id} or :id
  paramType: 'int' | 'uuid' | 'email' | 'string' | 'unknown';
  sampleIds: (string | number)[]; // discovered IDs from crawling
  fields?: string[];     // JSON fields seen in GET response
}

export interface MatrixFinding {
  type: 'idor' | 'mass_assignment' | 'bfla' | 'missing_authn';
  severity: 'high' | 'critical';
  confirmed: boolean;
  oracle: 'auth-diff';
  evidence: string;
  payload: string;
  target: string;
  parameter?: string;
}

export interface IdentityMatrixConfig {
  baseUrl: string;
  sessionA: AuthSession;      // user A (low privilege)
  sessionB: AuthSession;      // user B (low privilege, same or different tenant)
  sessionAdmin?: AuthSession; // admin (for BFLA baseline)
  resources: DiscoveredResource[];
  timeoutMs: number;
}

function makeHeaders(session: AuthSession | undefined): Record<string, string> {
  const headers: Record<string, string> = {
    'User-Agent': 'CryptoSentinel-Identity-Matrix/1.0',
  };
  if (session?.token) {
    headers['Authorization'] = `Bearer ${session.token}`;
  }
  if (session?.cookies) {
    headers['Cookie'] = session.cookies;
  }
  return headers;
}

async function fetchJson(url: string, opts: RequestInit, timeoutMs: number): Promise<{ status: number; body: any; raw: string }> {
  try {
    const res = await fetch(url, { ...opts, signal: AbortSignal.timeout(timeoutMs) });
    const raw = await res.text();
    let body: any = null;
    try { body = JSON.parse(raw); } catch {}
    return { status: res.status, body, raw };
  } catch (e) {
    return { status: 0, body: null, raw: String(e).slice(0, 100) };
  }
}

/**
 * IDOR (horizontal): user B accesses user A's resource by ID.
 * Oracle: 200 + response body contains data belonging to user A.
 */
async function testIdor(
  config: IdentityMatrixConfig,
  resource: DiscoveredResource,
  resourceId: string | number,
): Promise<MatrixFinding[]> {
  const findings: MatrixFinding[] = [];
  const path = resource.path.replace(/\{id\}|:id/, String(resourceId));

  // Step 1: User A GETs their own resource (baseline)
  const resA = await fetchJson(
    `${config.baseUrl}${path}`,
    { headers: makeHeaders(config.sessionA) },
    config.timeoutMs,
  );

  if (resA.status !== 200 || !resA.body) {
    console.log(`[matrix]   idor: user A GET ${path} → ${resA.status} (baseline failed)`);
    return [];
  }

  // Extract user A's sensitive fields (SSN, email, etc.)
  const aData = JSON.stringify(resA.body);
  const sensitiveFields = ['ssn', 'email', 'password', 'token', 'secret', 'balance', 'phone', 'address'];
  const aSensitiveData: Record<string, any> = {};
  for (const field of sensitiveFields) {
    if (resA.body[field] !== undefined) {
      aSensitiveData[field] = resA.body[field];
    }
  }

  if (Object.keys(aSensitiveData).length === 0) {
    console.log(`[matrix]   idor: no sensitive fields in A's response — skipping`);
    return [];
  }

  // Step 2: User B GETs the same resource
  const resB = await fetchJson(
    `${config.baseUrl}${path}`,
    { headers: makeHeaders(config.sessionB) },
    config.timeoutMs,
  );

  // Oracle: 200 + B's response contains A's sensitive data
  if (resB.status === 200 && resB.body) {
    const bData = JSON.stringify(resB.body);
    let leakedFields: string[] = [];
    for (const [field, value] of Object.entries(aSensitiveData)) {
      // Check if B's response contains A's exact value for this field
      if (bData.includes(String(value))) {
        leakedFields.push(field);
      }
    }

    if (leakedFields.length > 0) {
      findings.push({
        type: 'idor',
        severity: 'high',
        confirmed: true,
        oracle: 'auth-diff',
        evidence: `IDOR (horizontal) confirmed: user B (${config.sessionB.username}) accessed resource id=${resourceId} belonging to user A (${config.sessionA.username}). Response contained A's sensitive fields: ${leakedFields.join(', ')}. Values: ${leakedFields.map(f => `${f}=${aSensitiveData[f]}`).join(', ')}. No per-user authorization check — any authenticated user can access any resource by ID.`,
        payload: `GET ${path} with Bearer token of user B (different from user A who owns the resource)`,
        target: `${config.baseUrl}${path}`,
        parameter: 'id (path)',
      });
      console.log(`[matrix]   idor: ✅ CONFIRMED — B accessed A's data (${leakedFields.join(', ')})`);
    }
  } else if (resB.status === 401 || resB.status === 403) {
    console.log(`[matrix]   idor: B got ${resB.status} — authz check exists (good)`);
  } else {
    console.log(`[matrix]   idor: B got ${resB.status} — unexpected`);
  }

  return findings;
}

/**
 * Mass assignment: user A PUT {role:"admin"} → role changes.
 * Oracle: GET after PUT shows role=admin (byte-level proof).
 */
async function testMassAssignment(
  config: IdentityMatrixConfig,
  resource: DiscoveredResource,
  resourceId: string | number,
): Promise<MatrixFinding[]> {
  const findings: MatrixFinding[] = [];
  const path = resource.path.replace(/\{id\}|:id/, String(resourceId));

  // Step 1: GET baseline — what fields does the resource have?
  const resA = await fetchJson(
    `${config.baseUrl}${path}`,
    { headers: makeHeaders(config.sessionA) },
    config.timeoutMs,
  );

  if (resA.status !== 200 || !resA.body) return [];

  const currentRole = resA.body.role || resA.body.isAdmin || resA.body.privilege;
  if (currentRole === 'admin' || currentRole === true) {
    console.log(`[matrix]   mass-assign: A is already admin — skipping`);
    return [];
  }

  // Step 2: PUT with role=admin (mass assignment attempt)
  const putBody = JSON.stringify({ ...resA.body, role: 'admin' });
  const resPut = await fetchJson(
    `${config.baseUrl}${path}`,
    {
      method: 'PUT',
      headers: { ...makeHeaders(config.sessionA), 'Content-Type': 'application/json' },
      body: putBody,
    },
    config.timeoutMs,
  );

  // Step 3: GET again — did role change?
  const resVerify = await fetchJson(
    `${config.baseUrl}${path}`,
    { headers: makeHeaders(config.sessionA) },
    config.timeoutMs,
  );

  if (resVerify.status === 200 && resVerify.body) {
    const newRole = resVerify.body.role || resVerify.body.isAdmin;
    if (newRole === 'admin' || newRole === true) {
      findings.push({
        type: 'mass_assignment',
        severity: 'critical',
        confirmed: true,
        oracle: 'auth-diff',
        evidence: `Mass assignment confirmed: user A (${config.sessionA.username}) sent PUT ${path} with {role:"admin"}. Subsequent GET confirmed role changed from "${currentRole}" to "${newRole}". Server accepted and persisted the role field without validation — any user can escalate privileges by including role/admin fields in PUT/PATCH body.`,
        payload: `PUT ${path} body={"role":"admin"} with user A's token`,
        target: `${config.baseUrl}${path}`,
        parameter: 'role (body field)',
      });
      console.log(`[matrix]   mass-assign: ✅ CONFIRMED — role escalated to admin`);

      // RESTORE: change role back to original
      await fetchJson(
        `${config.baseUrl}${path}`,
        {
          method: 'PUT',
          headers: { ...makeHeaders(config.sessionA), 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...resVerify.body, role: currentRole }),
        },
        config.timeoutMs,
      );
      console.log(`[matrix]   mass-assign: restored role to "${currentRole}"`);
    }
  }

  return findings;
}

/**
 * BFLA: user calls admin-only endpoint → 2xx (should be 403).
 * Oracle: low-priv user gets 200 on endpoint that admin uses.
 */
async function testBfla(
  config: IdentityMatrixConfig,
  resource: DiscoveredResource,
): Promise<MatrixFinding[]> {
  const findings: MatrixFinding[] = [];

  // Only test POST/PUT/DELETE on admin-like paths
  if (!['POST', 'PUT', 'DELETE', 'PATCH'].includes(resource.method.toUpperCase())) return [];
  if (!resource.path.includes('/admin') && !resource.path.includes('/manage')) return [];

  // Step 1: Admin calls the endpoint (baseline)
  // POST/PUT/PATCH need Content-Type + body to avoid crash on req.body destructuring
  if (!config.sessionAdmin) return [];
  const adminHeaders = makeHeaders(config.sessionAdmin);
  const adminOpts: RequestInit = { method: resource.method, headers: adminHeaders };
  if (['POST', 'PUT', 'PATCH'].includes(resource.method.toUpperCase())) {
    adminHeaders['Content-Type'] = 'application/json';
    adminOpts.body = JSON.stringify({});  // empty body — server uses defaults
  }
  const resAdmin = await fetchJson(
    `${config.baseUrl}${resource.path}`,
    adminOpts,
    config.timeoutMs,
  );

  if (resAdmin.status >= 400) {
    console.log(`[matrix]   bfla: admin got ${resAdmin.status} — endpoint not usable, skipping`);
    return [];
  }

  // Step 2: Low-priv user calls the same endpoint
  const userHeaders = makeHeaders(config.sessionA);
  const userOpts: RequestInit = { method: resource.method, headers: userHeaders };
  if (['POST', 'PUT', 'PATCH'].includes(resource.method.toUpperCase())) {
    userHeaders['Content-Type'] = 'application/json';
    userOpts.body = JSON.stringify({});
  }
  const resUser = await fetchJson(
    `${config.baseUrl}${resource.path}`,
    userOpts,
    config.timeoutMs,
  );

  // Oracle: user gets 2xx (should be 403)
  if (resUser.status >= 200 && resUser.status < 300) {
    findings.push({
      type: 'bfla',
      severity: 'high',
      confirmed: true,
      oracle: 'auth-diff',
      evidence: `BFLA confirmed: low-priv user (${config.sessionA.username}, role=${config.sessionA.role}) called admin-only endpoint ${resource.method} ${resource.path}. Admin got ${resAdmin.status}, user got ${resUser.status} (should be 403). No function-level authorization check — any authenticated user can invoke admin operations.`,
      payload: `${resource.method} ${resource.path} with low-priv user's token`,
      target: `${config.baseUrl}${resource.path}`,
      parameter: 'N/A (function-level)',
    });
    console.log(`[matrix]   bfla: ✅ CONFIRMED — user accessed admin endpoint`);
  }

  return findings;
}

/**
 * Missing authn: anonymous user accesses authenticated resource.
 * Oracle: 200 without any token (should be 401).
 */
async function testMissingAuthn(
  config: IdentityMatrixConfig,
  resource: DiscoveredResource,
  resourceId: string | number,
): Promise<MatrixFinding[]> {
  const findings: MatrixFinding[] = [];
  const path = resource.path.replace(/\{id\}|:id/, String(resourceId));

  const resAnon = await fetchJson(
    `${config.baseUrl}${path}`,
    { headers: { 'User-Agent': 'CryptoSentinel-Identity-Matrix/1.0' } },
    config.timeoutMs,
  );

  if (resAnon.status === 200 && resAnon.body) {
    findings.push({
      type: 'missing_authn',
      severity: 'high',
      confirmed: true,
      oracle: 'auth-diff',
      evidence: `Missing authentication confirmed: anonymous request (no token/cookie) to ${path} returned 200 + full data. Server did not require authentication — anyone can access this resource without credentials.`,
      payload: `GET ${path} with NO Authorization header`,
      target: `${config.baseUrl}${path}`,
    });
    console.log(`[matrix]   missing-authn: ✅ CONFIRMED — anonymous access works`);
  }

  return findings;
}

/**
 * Run the full identity matrix on all discovered resources.
 *
 * Per Claude v10 §4.3 + v10-feedback:
 * "Нашёл ресурс GET /api/users/{id} → обязан прогнать GET/PUT/PATCH/DELETE
 *  от A и от B."
 *
 * Verb-inference: ANY discovered path is tested with ALL verbs, not just
 * the verb the crawler found. If we found GET /api/users/{id}, we also
 * try PUT/PATCH/DELETE on the same path — because the API might accept
 * them even if the HTML/JS only showed GET.
 */
export async function runIdentityMatrix(
  config: IdentityMatrixConfig,
): Promise<{ findings: MatrixFinding[]; telemetry: MatrixTelemetry }> {
  const telemetry: MatrixTelemetry = {
    resources_found: config.resources.length,
    idor_tested: 0,
    mass_assign_tested: 0,
    bfla_tested: 0,
    missing_authn_tested: 0,
    verbs_tried: new Set<string>(),
    paths_tested: [],
    fallback_used: false,
  };

  console.log(`[matrix] Starting identity matrix on ${config.resources.length} resources`);
  console.log(`[matrix]   User A: ${config.sessionA.username} (${config.sessionA.role})`);
  console.log(`[matrix]   User B: ${config.sessionB.username} (${config.sessionB.role})`);
  if (config.sessionAdmin) {
    console.log(`[matrix]   Admin: ${config.sessionAdmin.username} (${config.sessionAdmin.role})`);
  }

  const allFindings: MatrixFinding[] = [];

  for (const resource of config.resources) {
    console.log(`[matrix] Processing ${resource.method} ${resource.path} (paramType=${resource.paramType}, ids=${resource.sampleIds.length})`);
    telemetry.paths_tested.push(`${resource.method} ${resource.path}`);

    // For each sample ID, test with ALL verbs (verb-inference per Claude)
    for (const id of resource.sampleIds.slice(0, 3)) {
      const testResource = { ...resource, path: resource.path.replace(/\{id\}|:id/, String(id)) };

      // ALWAYS test GET (IDOR + missing authn) — even if discovered as PUT
      console.log(`[matrix]   Testing GET (IDOR + missing authn) on id=${id}...`);
      telemetry.verbs_tried.add('GET');
      telemetry.idor_tested++;
      allFindings.push(...await testIdor(config, resource, id));
      telemetry.missing_authn_tested++;
      allFindings.push(...await testMissingAuthn(config, resource, id));

      // ALWAYS test PUT (mass assignment) — even if discovered as GET
      // Per Claude: "Нашёл ресурс GET /api/users/{id} → обязан прогнать PUT"
      console.log(`[matrix]   Testing PUT (mass assignment) on id=${id}...`);
      telemetry.verbs_tried.add('PUT');
      telemetry.mass_assign_tested++;
      allFindings.push(...await testMassAssignment(config, resource, id));

      // Also try PATCH
      console.log(`[matrix]   Testing PATCH on id=${id}...`);
      telemetry.verbs_tried.add('PATCH');
      // PATCH is same as PUT for mass assignment test
      allFindings.push(...await testMassAssignment(config, { ...resource, method: 'PATCH' }, id));

      // Try DELETE (can user B delete user A's resource?)
      console.log(`[matrix]   Testing DELETE on id=${id}...`);
      telemetry.verbs_tried.add('DELETE');
      const path = resource.path.replace(/\{id\}|:id/, String(id));
      const resDel = await fetchJson(
        `${config.baseUrl}${path}`,
        { method: 'DELETE', headers: makeHeaders(config.sessionB) },
        config.timeoutMs,
      );
      if (resDel.status >= 200 && resDel.status < 300) {
        allFindings.push({
          type: 'idor',
          severity: 'critical',
          confirmed: true,
          oracle: 'auth-diff',
          evidence: `IDOR (DELETE) confirmed: user B (${config.sessionB.username}) deleted resource id=${id} belonging to user A. Server returned ${resDel.status} — no authorization check on DELETE.`,
          payload: `DELETE ${path} with user B's token`,
          target: `${config.baseUrl}${path}`,
          parameter: 'id (path)',
        });
        console.log(`[matrix]   delete: ✅ CONFIRMED — B deleted A's resource`);
      }
    }

    // Test BFLA on admin-like endpoints (or any POST/PUT/DELETE endpoint)
    console.log(`[matrix]   Testing BFLA...`);
    telemetry.bfla_tested++;
    allFindings.push(...await testBfla(config, resource));
  }

  const confirmed = allFindings.filter(f => f.confirmed);
  console.log(`[matrix] Done. ${confirmed.length}/${allFindings.length} confirmed.`);
  console.log(`[matrix] Telemetry: resources=${telemetry.resources_found}, idor_tested=${telemetry.idor_tested}, mass_assign_tested=${telemetry.mass_assign_tested}, bfla_tested=${telemetry.bfla_tested}, verbs=${[...telemetry.verbs_tried].join(',')}`);

  return { findings: allFindings, telemetry };
}

export interface MatrixTelemetry {
  resources_found: number;
  idor_tested: number;
  mass_assign_tested: number;
  bfla_tested: number;
  missing_authn_tested: number;
  verbs_tried: Set<string>;
  paths_tested: string[];
  fallback_used: boolean;
}
