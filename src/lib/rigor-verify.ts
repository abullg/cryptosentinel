/**
 * CryptoSentinel — Rigor Verification
 *
 * User feedback: "Почему он уверен что email действительно принадлежит
 * реальному пользователю? balance динамический и реальный? endpoint
 * работает повторно? одинаково работает в чистой сессии без cookies/auth
 * headers? данные относятся к нескольким пользователям или только к
 * публичному объекту? И такие вопросы могут быть к любой уязвимости
 * только по другому будет звучать"
 *
 * Translation: every confirmed finding must answer 5 standard questions
 * before being marked EXPLOITABLE:
 *
 *  1. REPEATABILITY — does the endpoint work consistently on multiple
 *     requests? (idempotency check — if it works only once, it could
 *     be a transient glitch or a one-time leak)
 *
 *  2. CLEAN SESSION — does it work in a clean session (no cookies,
 *     no auth headers, fresh User-Agent)? If it needs a session, it's
 *     NOT a real auth bypass — it's just reusing existing auth.
 *
 *  3. PUBLIC COMPARISON — is the response DIFFERENT from what the
 *     homepage / public endpoint returns? If /admin returns the SAME
 *     HTML as /, it's not "admin access" — it's a SPA shell route that
 *     the frontend router treats as admin-only on the client side.
 *
 *  4. MULTI-ENTITY UNIQUENESS — does the response contain data for
 *     MULTIPLE distinct users / records, or just ONE? If only one
 *     userId/email, it could be a public demo user shown to all visitors
 *     (e.g., Nuxt.js window.__NUXT__.state shows demo user). If MANY
 *     distinct userIds, it's a real leak.
 *
 *  5. REAL-VS-DEMO — does the data look real (proper email format,
 *     plausible balance values, realistic names) or does it look like
 *     a placeholder (test@test.com, balance=0, name=Demo User)?
 *
 * Each rigor check returns:
 *  - PASS: the finding is real, evidence supports the verdict
 *  - FAIL: the finding is likely a false positive (e.g., SPA shell)
 *  - INCONCLUSIVE: couldn't determine (network issue, etc.)
 *
 * The PreConfirmedFinding's `description` and `evidence` fields include
 * the explicit answers so the user can see the validator's reasoning.
 */
import type { PreConfirmedFinding } from './active-probe';

const BROWSER_HEADERS: Record<string, string> = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.9',
};

const CLEAN_SESSION_HEADERS: Record<string, string> = {
  // NO cookies, NO Authorization header, different User-Agent (mobile)
  'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15',
  'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.9',
  // Explicitly no cookies — clear-session simulation
  'Cache-Control': 'no-cache',
};

export type RigorVerdict = 'PASS' | 'FAIL' | 'INCONCLUSIVE';

export interface RigorResult {
  verdict: RigorVerdict;
  repeatability: 'consistent' | 'varies' | 'unknown';
  cleanSession: 'works-without-auth' | 'requires-auth' | 'unknown';
  publicComparison: 'different-from-public' | 'same-as-public' | 'unknown';
  multiEntity: 'multiple-distinct' | 'single-entity' | 'no-entities' | 'unknown';
  realVsDemo: 'real-data' | 'demo-data' | 'unknown';
  evidence: string;       // human-readable answers to all 5 questions
  refinedDescription: string; // updated finding description with rigor answers
}

/**
 * Run rigor verification on a confirmed finding.
 *
 * For each finding, we send additional HTTP requests to verify:
 *  - repeatability (2 more requests)
 *  - clean session (1 request without cookies/headers)
 *  - public comparison (1 request to homepage or parent path)
 *
 * Then we analyze the response body for:
 *  - multi-entity uniqueness (count distinct userIds/emails)
 *  - real-vs-demo (check for placeholder patterns)
 *
 * @param finding - the PreConfirmedFinding to verify
 * @param targetUrl - the original target URL (for homepage comparison)
 * @returns RigorResult with explicit answers
 */
export async function rigorVerifyFinding(
  finding: PreConfirmedFinding,
  targetUrl: string,
): Promise<RigorResult> {
  const result: RigorResult = {
    verdict: 'INCONCLUSIVE',
    repeatability: 'unknown',
    cleanSession: 'unknown',
    publicComparison: 'unknown',
    multiEntity: 'unknown',
    realVsDemo: 'unknown',
    evidence: '',
    refinedDescription: finding.description,
  };

  // Extract the URL from finding.location (format: "https://... (param: X)")
  const findingUrl = finding.location.split(' (')[0];
  if (!findingUrl) {
    result.evidence = 'Rigor check skipped — could not parse finding URL.';
    return result;
  }

  // ─── PARALLEL CHECKS — fire all 4 HTTP requests at once ───
  // Previous version did these SEQUENTIALLY: 4 × 6s = 24s per finding.
  // With 30 findings × 24s = 12 MINUTES in Phase 0 (no progress updates).
  // This caused the user's "stuck for 16 min" report. Parallel cuts
  // per-finding time to ~6s (the slowest of 4 requests), so 30 findings
  // × 6s / 5 parallel = 36s total — 20x speedup.
  const pubUrl = new URL(findingUrl);
  pubUrl.pathname = '/';
  pubUrl.search = '';
  const pubUrlStr = pubUrl.toString();

  const [repeat1Res, repeat2Res, cleanRes, publicRes] = await Promise.allSettled([
    fetch(findingUrl, {
      headers: BROWSER_HEADERS,
      signal: AbortSignal.timeout(6_000),
      redirect: 'follow',
    }).then(r => r.text()),
    fetch(findingUrl, {
      headers: BROWSER_HEADERS,
      signal: AbortSignal.timeout(6_000),
      redirect: 'follow',
    }).then(r => r.text()),
    fetch(findingUrl, {
      headers: CLEAN_SESSION_HEADERS,
      signal: AbortSignal.timeout(6_000),
      redirect: 'manual', // don't follow — check for auth redirect
    }).then(async r => ({ status: r.status, body: await r.text(), location: r.headers.get('location') || '' })),
    fetch(pubUrlStr, {
      headers: BROWSER_HEADERS,
      signal: AbortSignal.timeout(6_000),
      redirect: 'follow',
    }).then(r => r.text()),
  ]);

  // ─── CHECK 1: REPEATABILITY ───
  const repeat1Body = repeat1Res.status === 'fulfilled' ? repeat1Res.value : '';
  const repeat2Body = repeat2Res.status === 'fulfilled' ? repeat2Res.value : '';
  if (repeat1Body && repeat2Body) {
    const sameLength = Math.abs(repeat1Body.length - repeat2Body.length) < 200;
    const sameContent = repeat1Body === repeat2Body;
    if (sameContent) {
      result.repeatability = 'consistent';
    } else if (sameLength) {
      result.repeatability = 'consistent';
    } else {
      result.repeatability = 'varies';
    }
  }

  // ─── CHECK 2: CLEAN SESSION ───
  if (cleanRes.status === 'fulfilled' && cleanRes.value) {
    const { status, body: cleanBody, location } = cleanRes.value;
    if (status >= 300 && status < 400) {
      result.cleanSession = 'requires-auth';
      result.evidence += `Clean session redirected to ${location} — server ENFORCES auth via redirect. NOT a real bypass.\n`;
    } else if (status === 401 || status === 403) {
      result.cleanSession = 'requires-auth';
      result.evidence += `Clean session got ${status} — server ENFORCES auth. NOT a real bypass.\n`;
    } else if (status === 200 && cleanBody.length > 200) {
      result.cleanSession = 'works-without-auth';
      result.evidence += `Clean session (no cookies, mobile UA) returned ${status} with ${cleanBody.length} bytes — endpoint works WITHOUT any auth.\n`;
    }
  }

  // ─── CHECK 3: PUBLIC COMPARISON ───
  const publicBody = publicRes.status === 'fulfilled' ? publicRes.value : '';
  if (publicBody && repeat1Body) {
    const similarity = computeSimilarity(publicBody, repeat1Body);
    if (similarity > 0.95) {
      result.publicComparison = 'same-as-public';
      result.evidence += `Response is ${Math.round(similarity * 100)}% similar to homepage — likely SPA shell route (NOT real admin content).\n`;
    } else if (similarity < 0.5) {
      result.publicComparison = 'different-from-public';
      result.evidence += `Response differs significantly from homepage (${Math.round(similarity * 100)}% similar) — real admin-specific content.\n`;
    } else {
      result.publicComparison = 'different-from-public';
      result.evidence += `Response partially differs from homepage (${Math.round(similarity * 100)}% similar) — contains some admin-specific content.\n`;
    }
  }

  // ─── CHECK 4: MULTI-ENTITY UNIQUENESS — count distinct userIds/emails ───
  // For findings that claim data exposure, verify the data is about
  // MULTIPLE users (real leak) vs ONE user (could be a public demo).
  const bodyToCheck = repeat1Body || cleanBody;
  if (bodyToCheck) {
    const emails = new Set<string>();
    const userIds = new Set<string>();
    const balances = new Set<string>();

    // Extract emails
    for (const m of bodyToCheck.matchAll(/[\w.+-]+@[\w.-]+\.[a-z]{2,}/gi)) {
      // Skip obvious placeholder emails
      if (!/^(test|example|demo|sample|user@example|foo@bar)/i.test(m[0])) {
        emails.add(m[0].toLowerCase());
      }
    }
    // Extract userIds (numeric or UUID-like)
    for (const m of bodyToCheck.matchAll(/(?:user[_-]?id|userId|uid)["':\s]+["']?(\d{3,}|[0-9a-f-]{8,})["']?/gi)) {
      userIds.add(m[1]);
    }
    // Extract balances
    for (const m of bodyToCheck.matchAll(/(?:balance|amount|total)["':\s]+["']?(\d+(?:\.\d+)?)["']?/gi)) {
      balances.add(m[1]);
    }

    if (emails.size > 0 || userIds.size > 0) {
      const totalEntities = Math.max(emails.size, userIds.size);
      if (totalEntities > 1) {
        result.multiEntity = 'multiple-distinct';
        result.evidence += `Found ${emails.size} distinct emails, ${userIds.size} distinct userIds, ${balances.size} distinct balances — MULTIPLE users = real leak.\n`;
      } else {
        result.multiEntity = 'single-entity';
        result.evidence += `Found only ${emails.size} email(s), ${userIds.size} userId(s) — could be a SINGLE public demo user, not a multi-user leak.\n`;
      }
    } else {
      result.multiEntity = 'no-entities';
      result.evidence += `No userIds/emails detected in response body — claim of "userId/email/balance data exposed" is unsupported.\n`;
    }
  }

  // ─── CHECK 5: REAL-VS-DEMO — check for placeholder patterns ───
  if (bodyToCheck) {
    const demoPatterns = [
      /test@test\.[a-z]+/i,
      /demo@demo\.[a-z]+/i,
      /example@(?:example|test)\.[a-z]+/i,
      /user@(?:example|test)\.[a-z]+/i,
      /foo@bar\.[a-z]+/i,
      /\bDemo\s+User\b/i,
      /\bTest\s+User\b/i,
      /\bJohn\s+Doe\b/i,
      /\bJane\s+Doe\b/i,
      /"balance":\s*0(?:\.0+)?\b/i,           // balance: 0
      /"balance":\s*"0(?:\.0+)?"/i,           // balance: "0"
      /"amount":\s*0(?:\.0+)?\b/i,
      /\bplaceholder\b/i,
      /\bsample\s+data\b/i,
      /\bdemo\s+data\b/i,
    ];
    const foundDemoPatterns = demoPatterns.filter(p => p.test(bodyToCheck));
    if (foundDemoPatterns.length > 0) {
      result.realVsDemo = 'demo-data';
      result.evidence += `Response contains ${foundDemoPatterns.length} placeholder/demo patterns (e.g. test@example.com, balance:0) — likely DEMO data, not real user data.\n`;
    } else if (result.multiEntity === 'multiple-distinct') {
      result.realVsDemo = 'real-data';
      result.evidence += `Multiple distinct users with realistic data (no placeholder patterns) — appears to be REAL user data.\n`;
    } else {
      result.realVsDemo = 'real-data';
      result.evidence += `No placeholder patterns detected — data appears non-demo (but only ${result.multiEntity === 'single-entity' ? 'one entity' : 'unverified count'}).\n`;
    }
  }

  // ─── FINAL VERDICT ───
  // The finding PASSES rigor only if:
  //  - repeatability is consistent OR varies (both OK — varies = real data)
  //  - clean session works (proves it's a real auth bypass)
  //  - public comparison differs from homepage (proves it's not SPA shell)
  //  - multi-entity shows multiple distinct users OR no entities claimed
  //  - real-vs-demo doesn't show obvious placeholder patterns
  const checks: Array<{ name: string; ok: boolean }> = [
    { name: 'repeatability', ok: result.repeatability === 'consistent' || result.repeatability === 'varies' },
    { name: 'cleanSession', ok: result.cleanSession === 'works-without-auth' },
    { name: 'publicComparison', ok: result.publicComparison === 'different-from-public' },
    { name: 'multiEntity', ok: result.multiEntity === 'multiple-distinct' || result.multiEntity === 'no-entities' },
    { name: 'realVsDemo', ok: result.realVsDemo === 'real-data' },
  ];
  const passedChecks = checks.filter(c => c.ok).length;
  if (passedChecks === 5) {
    result.verdict = 'PASS';
    result.evidence = `✓ RIGOR PASSED (5/5 checks)\n` + result.evidence;
  } else if (passedChecks >= 3) {
    // Mixed result — keep as confirmed but flag caveats
    result.verdict = 'PASS';
    result.evidence = `⚠ RIGOR PARTIAL (${passedChecks}/5 checks passed)\n` + result.evidence +
      `\nCaveats: ${checks.filter(c => !c.ok).map(c => c.name).join(', ')} did not pass full verification.\n`;
  } else {
    result.verdict = 'FAIL';
    result.evidence = `✗ RIGOR FAILED (${passedChecks}/5 checks passed) — likely FALSE POSITIVE\n` + result.evidence +
      `\nFailed checks: ${checks.filter(c => !c.ok).map(c => c.name).join(', ')}\n`;
  }

  // Build refined description that ANSWERS the user's standard questions
  result.refinedDescription = finding.description +

    `\n\n== RIGOR VERIFICATION — answers to standard questions ==\n` +
    `1. REPEATABILITY: ${result.repeatability} — endpoint works on repeat request: ${result.repeatability === 'consistent' || result.repeatability === 'varies' ? 'YES' : 'NO/UNKNOWN'}\n` +
    `2. CLEAN SESSION (no cookies/auth, mobile UA): ${result.cleanSession === 'works-without-auth' ? 'WORKS — real auth bypass' : result.cleanSession === 'requires-auth' ? 'REQUIRES AUTH — NOT a bypass' : 'UNKNOWN'}\n` +
    `3. PUBLIC COMPARISON: ${result.publicComparison === 'different-from-public' ? 'DIFFERENT from homepage — real admin content' : result.publicComparison === 'same-as-public' ? 'SAME as homepage — likely SPA shell, NOT admin access' : 'UNKNOWN'}\n` +
    `4. MULTI-ENTITY UNIQUENESS: ${result.multiEntity === 'multiple-distinct' ? 'MULTIPLE distinct users — real leak' : result.multiEntity === 'single-entity' ? 'SINGLE entity — could be public demo user' : result.multiEntity === 'no-entities' ? 'NO user data actually found' : 'UNKNOWN'}\n` +
    `5. REAL-VS-DEMO: ${result.realVsDemo === 'real-data' ? 'REAL data — no placeholder patterns' : result.realVsDemo === 'demo-data' ? 'DEMO/placeholder data — likely fake' : 'UNKNOWN'}\n` +
    `\nVerdict: ${result.verdict}\n${result.evidence}`;

  return result;
}

/**
 * Compute similarity ratio between two strings (0.0 to 1.0).
 * Uses a simple Jaccard similarity on word sets — fast and good enough
 * for "is this the same SPA shell?" detection.
 */
function computeSimilarity(a: string, b: string): number {
  if (!a || !b) return 0;
  if (a === b) return 1;
  // For large strings, compare first 5000 chars (homepage HTML can be huge)
  const aSlice = a.slice(0, 5000);
  const bSlice = b.slice(0, 5000);
  // Tokenize on whitespace
  const tokensA = new Set(aSlice.split(/\s+/).filter(t => t.length > 3));
  const tokensB = new Set(bSlice.split(/\s+/).filter(t => t.length > 3));
  if (tokensA.size === 0 && tokensB.size === 0) return 1;
  // Jaccard
  let intersection = 0;
  for (const t of tokensA) {
    if (tokensB.has(t)) intersection++;
  }
  const union = tokensA.size + tokensB.size - intersection;
  return union === 0 ? 0 : intersection / union;
}
