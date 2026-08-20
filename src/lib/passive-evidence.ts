/**
 * CryptoSentinel — Passive Evidence Checker
 *
 * User feedback was critical: "Passive type ≠ automatically valid.
 * Passive type + SUFFICIENT passive evidence → auto-confirm."
 *
 * Presence of a pattern in recon ≠ proof of security impact.
 * Example: 'Access-Control-Allow-Origin: *' alone is FINE for public
 * APIs. Only exploitable if combined with credentials flag.
 * Example: '/api/openapi.json exists' ≠ API leak — only leak if it
 * actually contains internal API structure or secrets.
 *
 * This module defines, for each passive finding type, WHAT
 * constitutes SUFFICIENT evidence to auto-confirm. If sufficient
 * evidence is found in the recon data, skip active HTTP validation
 * (it's redundant — we already have proof). If NOT sufficient, fall
 * back to active HTTP validation.
 *
 * This is the next architectural step: the system now understands
 * not just WHAT to check, but WHAT TYPE OF PROOF each finding
 * requires. Passive findings with sufficient evidence skip active
 * validation — saves HTTP requests, faster pipeline, more
 * concurrency available for findings that genuinely need runtime
 * proof.
 */

export interface EvidenceResult {
  sufficient: boolean;
  evidence: string;      // human-readable explanation of why this is/isn't sufficient
  confidence: number;    // 0.0 - 1.0
  severity?: string;     // override severity based on evidence strength
}

export type EvidenceChecker = (sourceCode: string, finding: any) => EvidenceResult;

// ─── Per-type evidence checkers ────────────────────────────────────

const checkCspMissing: EvidenceChecker = (sc) => {
  // CSP missing IS sufficient evidence on its own — XSS protection
  // is absent in the browser. This is a real config weakness.
  if (sc.includes('CSP: MISSING')) {
    return {
      sufficient: true,
      evidence: 'CSP header is ABSENT in HTTP response. Browser has no XSS mitigation. Real config weakness — any reflected XSS on this domain would execute without browser-side defense.',
      confidence: 0.9,
      severity: 'medium',  // config weakness, not exploitable bug
    };
  }
  return { sufficient: false, evidence: 'CSP not flagged as missing in recon data', confidence: 0 };
};

const checkCorsMisconfig: EvidenceChecker = (sc) => {
  // CORS * ALONE is fine for public APIs (e.g., weather API, public price feeds).
  // Exploitable CORS requires BOTH:
  //   (a) Reflect arbitrary origin OR wildcard origin
  //   (b) Allow credentials (Access-Control-Allow-Credentials: true)
  // Without credentials, attacker website can read PUBLIC data — no impact.
  // With credentials, attacker website can read AUTHENTICATED data — real leak.
  const hasWildcardOrigin = sc.includes('CORS: Allow-Origin: *') ||
                            sc.toLowerCase().includes('access-control-allow-origin: *');
  const hasCredentials = sc.toLowerCase().includes('access-control-allow-credentials: true') ||
                         sc.toLowerCase().includes('allow-credentials: true');
  const hasReflectedOrigin = sc.toLowerCase().includes('reflected origin') ||
                              sc.toLowerCase().includes('origin reflected') ||
                              sc.toLowerCase().includes('access-control-allow-origin: https://');

  if (hasWildcardOrigin && hasCredentials) {
    return {
      sufficient: true,
      evidence: 'CORS allows ANY origin (Access-Control-Allow-Origin: *) AND sends credentials (Access-Control-Allow-Credentials: true). ANY website can read authenticated responses — full credential theft possible. Note: per spec, browsers should reject this combination, but misconfigured servers/CDNs sometimes accept it.',
      confidence: 0.92,
      severity: 'high',
    };
  }
  if (hasReflectedOrigin && hasCredentials) {
    return {
      sufficient: true,
      evidence: 'CORS reflects arbitrary Origin header AND sends credentials. Attacker website can read authenticated responses from any origin. Same impact as wildcard + credentials.',
      confidence: 0.95,
      severity: 'high',
    };
  }
  if (hasWildcardOrigin && !hasCredentials) {
    // NOT sufficient — public API, anyone can read public data anyway
    return {
      sufficient: false,
      evidence: 'CORS allows wildcard origin but does NOT send credentials. This is NORMAL for public APIs (price feeds, public data). No security impact — attacker website can only read public data that anyone can fetch directly.',
      confidence: 0,
    };
  }
  return { sufficient: false, evidence: 'No CORS misconfiguration evidence found in recon data', confidence: 0 };
};

const checkApiLeak: EvidenceChecker = (sc, finding) => {
  // For api_leak: sufficient evidence = REAL secret pattern in JS bundle.
  // NOT placeholders like 'your_api_key_here' or 'sk-test'.
  const realSecretPatterns: Array<{ regex: RegExp; type: string }> = [
    { regex: /\bsk-[\w-]{20,}\b/g, type: 'OpenAI/Stripe-style key' },
    { regex: /\beyJ[\w-]+\.[\w-]+\.[\w-]+\b/g, type: 'JWT token' },
    { regex: /\bAKIA[\w]{16}\b/g, type: 'AWS access key ID' },
    { regex: /\bghp_[\w]{36,}\b/g, type: 'GitHub personal access token' },
    { regex: /\bgho_[\w]{36,}\b/g, type: 'GitHub OAuth token' },
    { regex: /\bAIza[\w]{35}\b/g, type: 'Google API key' },
    { regex: /\bxox[baprs]-[\w-]{10,}\b/g, type: 'Slack token' },
  ];

  const placeholderPatterns = /^(sk-test|sk-leaked|sk-fake|sk-placeholder|test|example|demo|sample|xxx|yyy|aaa|your[_-]?api[_-]?key|placeholder|changeme|default|foo|bar|baz|password|secret|token|abc123|123456789|00000000|example\.com)/i;

  for (const { regex, type } of realSecretPatterns) {
    const matches = [...sc.matchAll(regex)];
    for (const m of matches) {
      const val = m[0];
      if (!placeholderPatterns.test(val)) {
        return {
          sufficient: true,
          evidence: `Real ${type} detected in recon data: "${val.slice(0, 20)}${val.length > 20 ? '...' : ''}". This is NOT a placeholder (rejected pattern check). Direct credential exposure — attacker can use this key immediately.`,
          confidence: 0.97,
          severity: 'critical',
        };
      }
    }
  }

  // Check if finding description mentions specific secret
  const findingDesc = (finding?.description || '').toLowerCase();
  if (findingDesc.includes('hardcoded') && (findingDesc.includes('sk-') || findingDesc.includes('akia') || findingDesc.includes('ghp_'))) {
    return {
      sufficient: true,
      evidence: 'AI finding explicitly mentions a hardcoded secret pattern (sk-/AKIA/ghp_) in description. Treat as confirmed credential exposure.',
      confidence: 0.85,
      severity: 'critical',
    };
  }

  return {
    sufficient: false,
    evidence: 'No REAL secret pattern found in recon data (only generic mentions or placeholders detected). Active validation needed to confirm if any "secret" is actually exploitable.',
    confidence: 0,
  };
};

const checkInfoExposure: EvidenceChecker = (sc, finding) => {
  // info_exposure is VERY context-dependent. Insufficient to auto-confirm
  // just because the type matches. Need SPECIFIC evidence.
  const findingDesc = (finding?.description || '').toLowerCase();
  const findingTitle = (finding?.title || '').toLowerCase();

  // Case 1: window.__net_track__ or similar client-side state leak
  if (findingDesc.includes('__net_track__') || sc.includes('__net_track__')) {
    if (sc.includes('clientIp') || sc.includes('client_ip') || sc.toLowerCase().includes('ip address')) {
      return {
        sufficient: true,
        evidence: 'window.__net_track__ (or similar) found in HTML, contains clientIp field. Server is leaking client IP, city, country, requestId to client-side JS. Real info exposure — could be used for fingerprinting/tracking.',
        confidence: 0.85,
        severity: 'low',  // info exposure, not exploitable
      };
    }
  }

  // Case 2: Stack traces / error messages with internal paths
  if (findingDesc.includes('stack trace') || findingDesc.includes('error message')) {
    if (sc.includes('/usr/') || sc.includes('/var/') || sc.includes('/home/') || sc.includes('c:\\')) {
      return {
        sufficient: true,
        evidence: 'Stack trace or error message in HTML reveals internal file system paths. Info exposure — could enable targeted path traversal attacks.',
        confidence: 0.85,
        severity: 'low',
      };
    }
  }

  // Case 3: User PII (emails, phones) in HTML
  const emailMatches = [...sc.matchAll(/[\w.+-]+@(?:[\w-]+\.)+[\w]{2,}/g)];
  const realEmails = emailMatches.filter(m => !/test@|example@|demo@|admin@example|user@example/i.test(m[0]));
  if (findingDesc.includes('email') || findingDesc.includes('pii')) {
    if (realEmails.length >= 5) {
      return {
        sufficient: true,
        evidence: `${realEmails.length} real-looking email addresses found in HTML. Potential PII exposure — could be spam list or user enumeration.`,
        confidence: 0.8,
        severity: 'medium',
      };
    }
  }

  // Case 4: Internal API structure leaked in JS
  if (findingDesc.includes('internal') && (findingDesc.includes('api') || findingDesc.includes('endpoint'))) {
    if (sc.includes('/api/internal/') || sc.includes('/api/admin/') || sc.includes('/_next/data/')) {
      return {
        sufficient: true,
        evidence: 'Internal API endpoints (e.g., /api/internal/, /api/admin/) found in HTML/JS. Real info exposure — attacker can use these endpoints as attack surface.',
        confidence: 0.85,
        severity: 'medium',
      };
    }
  }

  // Case 5: Public API docs (swagger/openapi) — INSUFFICIENT alone
  // /api/swagger existing doesn't mean it's a leak — many APIs are
  // intentionally public. Need to check if it contains internal
  // endpoints or sensitive schemas.
  if (findingDesc.includes('swagger') || findingDesc.includes('openapi')) {
    return {
      sufficient: false,
      evidence: 'Swagger/OpenAPI endpoint exists, but existence ≠ leak. Many APIs are intentionally documented publicly. Active validation needed: fetch /api/swagger and check if it exposes internal endpoints, admin routes, or sensitive schemas.',
      confidence: 0,
    };
  }

  return {
    sufficient: false,
    evidence: 'info_exposure type matched but no SPECIFIC sufficient evidence found in recon data. Active validation needed to confirm actual exposure.',
    confidence: 0,
  };
};

const checkClickjacking: EvidenceChecker = (sc) => {
  // X-Frame-Options MISSING is sufficient evidence — page can be iframed
  // by any site, including attacker-controlled. Combined with sensitive
  // actions (click-to-confirm, withdraw), this is exploitable.
  if (sc.includes('X-Frame-Options: MISSING')) {
    // Check if page has wallet/financial interactions
    if (sc.toLowerCase().includes('wallet') || sc.toLowerCase().includes('withdraw') ||
        sc.toLowerCase().includes('deposit') || sc.toLowerCase().includes('approve') ||
        sc.toLowerCase().includes('metamask') || sc.toLowerCase().includes('signmessage')) {
      return {
        sufficient: true,
        evidence: 'X-Frame-Options is MISSING AND page contains wallet/financial interactions. Real clickjacking risk — attacker can iframe this page and trick user into clicking withdraw/approve.',
        confidence: 0.9,
        severity: 'medium',
      };
    }
    // Page without sensitive interactions — clickjacking has lower impact
    return {
      sufficient: true,
      evidence: 'X-Frame-Options is MISSING. Page can be iframed by any site. Clickjacking possible but limited impact — no sensitive wallet/financial interactions detected in HTML.',
      confidence: 0.7,
      severity: 'low',
    };
  }
  return { sufficient: false, evidence: 'X-Frame-Options is present in recon data', confidence: 0 };
};

const checkHstsMissing: EvidenceChecker = (sc) => {
  if (sc.includes('HSTS: MISSING')) {
    return {
      sufficient: true,
      evidence: 'Strict-Transport-Security header is ABSENT. HTTPS downgrade attack (MITM) is possible — attacker on hostile network can strip HTTPS and intercept traffic.',
      confidence: 0.85,
      severity: 'low',  // config weakness, requires MITM conditions
    };
  }
  return { sufficient: false, evidence: 'HSTS is present in recon data', confidence: 0 };
};

const checkCookieSecurity: EvidenceChecker = (sc) => {
  if (sc.includes('Cookie issues:')) {
    // Extract the specific issues
    const cookieIssuesMatch = sc.match(/Cookie issues:\s*([^\n]+)/);
    const issues = cookieIssuesMatch?.[1] || '';
    return {
      sufficient: true,
      evidence: `Cookie security issues confirmed in recon data: ${issues}. These are real config weaknesses — session cookies are vulnerable to XSS/CSRF/MITM depending on missing flags.`,
      confidence: 0.88,
      severity: 'medium',
    };
  }
  return { sufficient: false, evidence: 'No cookie issues found in recon data', confidence: 0 };
};

const checkHeaderMisconfig: EvidenceChecker = (sc, finding) => {
  // Generic header misconfig — check description for specific header
  const findingDesc = (finding?.description || '').toLowerCase();
  if (findingDesc.includes('x-powered-by') && sc.toLowerCase().includes('x-powered-by:')) {
    return {
      sufficient: true,
      evidence: 'X-Powered-By header is exposed — leaks tech stack (e.g., Express, PHP, ASP.NET). Helps attacker target framework-specific CVEs.',
      confidence: 0.8,
      severity: 'low',
    };
  }
  if (findingDesc.includes('server:') && sc.toLowerCase().includes('server:')) {
    return {
      sufficient: true,
      evidence: 'Server header exposed — leaks web server version. Helps attacker target server-specific CVEs.',
      confidence: 0.8,
      severity: 'low',
    };
  }
  return { sufficient: false, evidence: 'Specific header misconfig evidence not found', confidence: 0 };
};

// ─── Registry of passive evidence checkers ─────────────────────────

export const PASSIVE_EVIDENCE_CHECKERS: Record<string, EvidenceChecker> = {
  csp_missing: checkCspMissing,
  cors_misconfig: checkCorsMisconfig,
  api_leak: checkApiLeak,
  info_exposure: checkInfoExposure,
  information_disclosure: checkInfoExposure, // AI synonym — same handler
  clickjacking: checkClickjacking,
  hsts_missing: checkHstsMissing,
  cookie_security: checkCookieSecurity,
  header_misconfig: checkHeaderMisconfig,
};

/**
 * Check if a finding has sufficient passive evidence to auto-confirm.
 * Returns sufficient=true if recon data ALONE is enough proof — skip
 * active HTTP validation. Returns sufficient=false if active validation
 * is still needed.
 */
export function checkPassiveEvidence(
  findingType: string,
  sourceCode: string,
  finding: any,
): EvidenceResult {
  const checker = PASSIVE_EVIDENCE_CHECKERS[findingType.toLowerCase()];
  if (!checker) {
    return {
      sufficient: false,
      evidence: `No passive evidence checker for type "${findingType}" — treat as active validation required`,
      confidence: 0,
    };
  }
  return checker(sourceCode, finding);
}
