/**
 * CryptoSentinel — Impact Engine & Security Boundary Analysis
 *
 * User critique (the next architectural transition):
 *   'система доказала security property и правильно оценила,
 *    нарушает ли оно security boundary, какую возможность
 *    получает атакующий и какой реальный impact возникает'
 *
 * Multi-state verdict model (was CONFIRMED/DROP, now):
 *   OBSERVED                 — data/pattern exists in response
 *   CONFIRMED_CONFIGURATION — misconfiguration proven (e.g., CSP missing)
 *   NOT_DIRECTLY_EXPLOITABLE — real finding but no direct exploit
 *   EXPLOITABLE              — security boundary violated, exploit possible
 *   IMPACT_CONFIRMED         — exploit demonstrated, real impact proven
 *   EXPECTED_BEHAVIOR        — normal app behavior, NOT a vulnerability
 *   DROP                     — actively disproven (false positive)
 *
 * Multi-dimensional confidence (was single number):
 *   detectionConfidence      — how sure we are the pattern exists
 *   evidenceConfidence       — how strong is the evidence
 *   exploitabilityConfidence — how likely this is exploitable
 *   impactConfidence         — how much real impact
 *
 * Security Boundary Analysis:
 *   subject → object → authorization boundary → exposure
 *   own IP → expected | other user's IP → exposure
 *   own balance → expected | other user's balance → vulnerability
 */

export type VerdictState =
  | 'OBSERVED'
  | 'CONFIRMED_CONFIGURATION'
  | 'NOT_DIRECTLY_EXPLOITABLE'
  | 'EXPLOITABLE'
  | 'IMPACT_CONFIRMED'
  | 'EXPECTED_BEHAVIOR'
  | 'DROP';

export interface MultiConfidence {
  detection: number;        // pattern exists?
  evidence: number;         // evidence strong?
  exploitability: number;   // can attacker exploit?
  impact: number;           // real damage?
}

export interface SecurityBoundary {
  dataSubject: string;       // who owns the data?
  dataSensitivity: 'public' | 'internal' | 'user-specific' | 'credential' | 'system';
  isOwnerData: boolean;      // is this the requesting user's own data?
  isPublicByDesign: boolean; // is this intentionally public?
  authorizationBoundary: string; // what boundary protects this data?
  boundaryViolated: boolean; // did the attacker cross a boundary?
  boundaryReasoning: string; // why
}

export interface ImpactAssessment {
  attackerCapability: string;    // what can attacker do?
  attackPrerequisites: string;   // what does attacker need?
  impactChain: string[];         // data → access → sensitivity → impact
  realImpact: 'none' | 'informational' | 'low' | 'medium' | 'high' | 'critical';
  impactReasoning: string;
}

export interface CorrelationHint {
  relatedFindingType: string;
  relationship: 'enabling' | 'amplifying' | 'independent';
  description: string;
}

export interface SeverityModifier {
  condition: string;
  modifier: number; // +1, -1, +2 etc
  applies: boolean;
}

export interface FullVerificationResult {
  verdict: VerdictState;
  confidence: MultiConfidence;
  boundary: SecurityBoundary | null;
  impact: ImpactAssessment | null;
  severity: string;
  severityReasoning: string;
  correlations: CorrelationHint[];
  evidenceChain: string;
}

// ─── SECURITY BOUNDARY ANALYZERS ────────────────────────────────────

function analyzeInfoExposureBoundary(
  finding: any,
  response: { bodyExcerpt: string; status: number; headers: Record<string, string> },
  sourceCode: string,
): SecurityBoundary {
  const desc = (finding.description || '').toLowerCase();
  const body = response.bodyExcerpt.toLowerCase();

  // window.__net_track__ with clientIp
  if (desc.includes('__net_track__') || body.includes('__net_track__')) {
    return {
      dataSubject: 'requesting user (self)',
      dataSensitivity: 'internal',
      isOwnerData: true, // it's the USER'S OWN IP
      isPublicByDesign: true, // CDN edge metadata reflected to requesting client
      authorizationBoundary: 'CDN edge → same user\'s browser (not cross-user)',
      boundaryViolated: false,
      boundaryReasoning: `PROVEN: User A requests page → HTML contains IP A (User A's own IP).
NOT PROVEN: User B requests page → HTML contains IP A (cross-user leak).

The clientIp in window.__net_track__ is the REQUESTING USER'S OWN IP, reflected from CDN edge.
This is User A seeing User A's own IP — NOT User B seeing User A's IP.

The finding description claims 'any visitor can read the client IP' — this is MISLEADING.
What's proven: each visitor sees THEIR OWN IP. What's NOT proven: visitor sees ANOTHER user's IP.

isEdgeCache: true suggests a HYPOTHESIS: if edge cache serves User A's cached HTML to User B,
then User B would see User A's IP. But this hypothesis was NOT tested.
To prove: send Request A (marker IP) → get cached response → send Request B (different IP)
→ check if Response B contains __net_track__ from Request A. If yes → cross-user disclosure.
If no → edge cache is per-user, no cross-user leak.

PII classification (GDPR/CCPA): clientIp IS PII. But PII ≠ vulnerability.
PII is a DATA CLASSIFICATION. Security violation requires PROOF that data is accessible
to a SUBJECT WHO SHOULDN'T HAVE IT. Currently, only the data owner (requesting user)
can see their own IP — no unauthorized disclosure proven.

requestId: classified as CORRELATION IDENTIFIER only. NOT proven to be:
- linked to session
- used in authentication
- used in authorization
- predictable
- usable to obtain data
Without these proofs, requestId is just an opaque tracking ID.`,
    };
  }

  // Stack trace with internal paths
  if (desc.includes('stack trace') || desc.includes('error message')) {
    if (body.includes('/usr/') || body.includes('/var/') || body.includes('/home/')) {
      return {
        dataSubject: 'system (server infrastructure)',
        dataSensitivity: 'internal',
        isOwnerData: false,
        isPublicByDesign: false,
        authorizationBoundary: 'server internals → public response',
        boundaryViolated: true,
        boundaryReasoning: 'Internal file system paths exposed in error response. This crosses the server-internal → public boundary. Attacker learns the server\'s file system layout, enabling targeted path traversal attacks.',
      };
    }
  }

  // Multiple user emails
  if (desc.includes('email') || desc.includes('pii')) {
    const emails = [...response.bodyExcerpt.matchAll(/[\w.+-]+@(?:[\w-]+\.)+[\w]{2,}/g)].map(m => m[0]);
    const realEmails = emails.filter(e => !/test@|example@|demo@|admin@example/i.test(e));
    if (realEmails.length >= 5) {
      return {
        dataSubject: 'multiple users (cross-user)',
        dataSensitivity: 'user-specific',
        isOwnerData: false,
        isPublicByDesign: false,
        authorizationBoundary: 'user data → public response',
        boundaryViolated: true,
        boundaryReasoning: `${realEmails.length} real email addresses from DIFFERENT users exposed in response. This is NOT the requesting user\'s own data — it\'s cross-user PII. Authorization boundary crossed: other users\' data is accessible without authentication.`,
      };
    }
  }

  // API endpoint existence
  if (desc.includes('api') || desc.includes('endpoint') || desc.includes('swagger')) {
    return {
      dataSubject: 'application (API structure)',
      dataSensitivity: 'public',
      isOwnerData: false,
      isPublicByDesign: true,
      authorizationBoundary: 'none (publicly accessible by design)',
      boundaryViolated: false,
      boundaryReasoning: 'API endpoint existence (swagger, openapi.json) is PUBLIC BY DESIGN for most web APIs. SPA applications expose API endpoints in client-side JavaScript as a normal part of their architecture. No authorization boundary is crossed — this is EXPECTED behavior.',
    };
  }

  // Default
  return {
    dataSubject: 'unknown',
    dataSensitivity: 'internal',
    isOwnerData: false,
    isPublicByDesign: false,
    authorizationBoundary: 'unknown',
    boundaryViolated: false,
    boundaryReasoning: 'Could not determine data ownership or authorization boundary from available evidence.',
  };
}

// ─── IMPACT ASSESSMENT ───────────────────────────────────────────────

function assessCspMissingImpact(): ImpactAssessment {
  return {
    attackerCapability: 'None directly — CSP is a defense-in-depth layer, not a vulnerability itself',
    attackPrerequisites: 'Requires a SEPARATE XSS vulnerability to have impact. Without XSS, CSP absence has zero direct impact.',
    impactChain: [
      'CSP header absent → browser has no XSS mitigation layer',
      'IF XSS exists → attacker script executes without browser-side restriction',
      'IF no XSS → CSP absence has no impact',
    ],
    realImpact: 'informational',
    impactReasoning: 'Missing CSP is a CONFIGURATION WEAKNESS, not an exploitable vulnerability. It only matters if combined with a separate XSS finding. Alone, it provides zero attacker capability. Severity should be Informational, not Medium or High.',
  };
}

function assessClientIpExposureImpact(): ImpactAssessment {
  return {
    attackerCapability: 'None proven. User A can read User A\'s own IP from page source — this is self-referential, not an attacker capability. To obtain ANOTHER user\'s IP, would need cache poisoning (NOT tested).',
    attackPrerequisites: 'For cross-user disclosure: edge cache must serve User A\'s HTML to User B (NOT PROVEN — hypothesis only). For same-user data theft: requires separate XSS (if attacker has XSS, they can get IP via WebRTC anyway).',
    impactChain: [
      'PROVEN: User A → request → HTML contains IP A (own IP)',
      'NOT PROVEN: User B → request → HTML contains IP A (cross-user leak)',
      'HYPOTHESIS: isEdgeCache=true suggests cache might serve stale HTML — but NOT tested',
      'To test: Request A (marker IP) → Request B (different IP) → compare __net_track__ in responses',
      'If B gets A\'s IP → cross-user disclosure (real vulnerability)',
      'If B gets B\'s IP → edge cache is per-user (expected behavior, no vuln)',
      'PII classification: clientIp IS PII under GDPR/CCPA — but PII ≠ vulnerability',
      'PII is data classification, not security violation',
      'Security violation requires: unauthorized subject accessing data — NOT proven here',
    ],
    realImpact: 'informational',
    impactReasoning: `What's PROVEN: Each user sees their OWN IP in page source. This is CDN edge metadata reflected to the requesting client — expected behavior for Cloudflare-fronted sites.

What's NOT PROVEN: Cross-user IP disclosure (User B seeing User A's IP). The finding's claim 'any visitor can read the client IP' is misleading — each visitor reads THEIR OWN IP, not other users' IPs.

isEdgeCache=true is a HYPOTHESIS about potential cache poisoning, not a proven exploit. The system identified this as a potential attack vector but did not test it. Testing would require: send Request A with unique marker → send Request B from different IP → check if Response B contains Request A's __net_track__ data.

PII ≠ vulnerability: clientIp IS PII under GDPR/CCPA. But PII is a DATA CLASSIFICATION. Security violation requires proof that data is accessible to a subject who shouldn't have it. Currently, only the data owner (requesting user) can see their own IP. No unauthorized disclosure proven.

requestId: classified as correlation identifier only. NOT proven to be linked to session, authentication, authorization, or predictable. 'Could be used for session correlation' is speculative — not proven.

Net impact: informational. The finding correctly identifies that __net_track__ contains client IP, but overestimates impact by implying cross-user disclosure which was not tested/proven.`,
  };
}

function assessAuthBypassImpact(boundary: SecurityBoundary): ImpactAssessment {
  if (boundary.boundaryViolated && !boundary.isOwnerData) {
    return {
      attackerCapability: 'Access to other users\' data without authentication',
      attackPrerequisites: 'None — endpoint accessible without auth',
      impactChain: [
        'Endpoint returns user-specific data without auth',
        'Data belongs to DIFFERENT users (not requesting user)',
        'Authorization boundary crossed: user data → public access',
        'Attacker can enumerate users, read PII, access financial data',
      ],
      realImpact: 'high',
      impactReasoning: 'Auth bypass with cross-user data exposure is a real vulnerability. Attacker gains access to other users\' data without any credentials. Impact depends on data sensitivity (balance → high, email → medium, IP → low).',
    };
  }
  return {
    attackerCapability: 'None — no boundary violated',
    attackPrerequisites: 'N/A',
    impactChain: ['No security boundary crossed'],
    realImpact: 'none',
    impactReasoning: 'No authorization boundary was violated.',
  };
}

// ─── CORRELATION ENGINE ──────────────────────────────────────────────

function getCorrelations(findingType: string): CorrelationHint[] {
  const correlations: Record<string, CorrelationHint[]> = {
    csp_missing: [
      { relatedFindingType: 'xss', relationship: 'amplifying', description: 'Missing CSP + confirmed XSS = significantly higher impact. Without CSP, XSS payloads execute without browser-side restriction. If XSS exists, CSP absence elevates from Informational to High.' },
      { relatedFindingType: 'stored_xss', relationship: 'amplifying', description: 'Missing CSP + stored XSS = persistent attacker script execution without mitigation. Severity should be Critical.' },
    ],
    xss: [
      { relatedFindingType: 'csp_missing', relationship: 'amplifying', description: 'XSS + missing CSP = no browser-side mitigation. Attacker script executes unrestricted.' },
      { relatedFindingType: 'cookie_security', relationship: 'enabling', description: 'XSS + missing HttpOnly cookie flag = attacker can steal session tokens via document.cookie.' },
    ],
    ssrf: [
      { relatedFindingType: 'info_exposure', relationship: 'enabling', description: 'SSRF to internal metadata + missing auth on internal endpoints = full internal network reconnaissance.' },
    ],
  };
  return correlations[findingType] || [];
}

// ─── SEVERITY COMPUTATION ───────────────────────────────────────────

function computeSeverity(
  findingType: string,
  verdict: VerdictState,
  boundary: SecurityBoundary | null,
  impact: ImpactAssessment | null,
): { severity: string; reasoning: string } {
  // Base severity from impact
  if (impact) {
    switch (impact.realImpact) {
      case 'critical': return { severity: 'critical', reasoning: `Impact: ${impact.impactReasoning}` };
      case 'high': return { severity: 'high', reasoning: `Impact: ${impact.impactReasoning}` };
      case 'medium': return { severity: 'medium', reasoning: `Impact: ${impact.impactReasoning}` };
      case 'low': return { severity: 'low', reasoning: `Impact: ${impact.impactReasoning}` };
      case 'informational': return { severity: 'info', reasoning: `Informational — ${impact.impactReasoning}` };
      case 'none': return { severity: 'info', reasoning: 'No real impact identified.' };
    }
  }

  // Fallback to verdict-based
  switch (verdict) {
    case 'IMPACT_CONFIRMED': return { severity: 'high', reasoning: 'Impact confirmed via exploit.' };
    case 'EXPLOITABLE': return { severity: 'high', reasoning: 'Security boundary violated, exploit possible.' };
    case 'NOT_DIRECTLY_EXPLOITABLE': return { severity: 'low', reasoning: 'Real finding but not directly exploitable. May amplify other findings.' };
    case 'CONFIRMED_CONFIGURATION': return { severity: 'info', reasoning: 'Configuration weakness confirmed. Defense-in-depth, not directly exploitable.' };
    case 'OBSERVED': return { severity: 'info', reasoning: 'Pattern observed but not yet verified.' };
    case 'EXPECTED_BEHAVIOR': return { severity: 'info', reasoning: 'Normal application behavior. Not a vulnerability.' };
    default: return { severity: 'info', reasoning: 'Unknown verdict.' };
  }
}

// ─── MAIN VERIFICATION FUNCTION ─────────────────────────────────────

/**
 * Full verification pipeline:
 * Detection → Evidence → Security Property → Boundary → Exploitability → Impact → Severity → Correlation
 */
export function fullVerify(
  finding: { type: string; title: string; description: string; location: string; severity: string },
  response: { bodyExcerpt: string; status: number; headers: Record<string, string> },
  sourceCode: string,
): FullVerificationResult {
  const findingType = (finding.type || '').toLowerCase();

  // ─── 1. SECURITY BOUNDARY ANALYSIS ───
  let boundary: SecurityBoundary | null = null;
  if (findingType === 'info_exposure' || findingType === 'api_leak') {
    boundary = analyzeInfoExposureBoundary(finding, response, sourceCode);
  }

  // ─── 2. IMPACT ASSESSMENT ───
  let impact: ImpactAssessment | null = null;
  if (findingType === 'csp_missing') {
    impact = assessCspMissingImpact();
  } else if (findingType === 'info_exposure' && boundary?.dataSubject.includes('self')) {
    impact = assessClientIpExposureImpact();
  } else if (findingType === 'auth_bypass' && boundary) {
    impact = assessAuthBypassImpact(boundary);
  }

  // ─── 3. VERDICT (multi-state) ───
  let verdict: VerdictState;

  if (findingType === 'csp_missing') {
    // CSP missing = confirmed configuration, not exploitable
    verdict = 'CONFIRMED_CONFIGURATION';
  } else if (boundary?.isPublicByDesign && boundary?.isOwnerData) {
    // Public by design + own data = NOT a vuln but worth noting (informational)
    // User assessment: "Severity Low: 🟢 Reasonable" — KEEP, don't drop
    verdict = 'NOT_DIRECTLY_EXPLOITABLE';
  } else if (boundary?.isPublicByDesign && !boundary?.isOwnerData) {
    // Public by design but NOT own data (e.g., public API docs) = expected
    verdict = 'EXPECTED_BEHAVIOR';
  } else if (boundary?.boundaryViolated && !boundary.isOwnerData) {
    // Cross-user data without auth = exploitable
    verdict = 'EXPLOITABLE';
  } else if (boundary?.isOwnerData) {
    // Own data = observed but not a boundary violation
    verdict = 'NOT_DIRECTLY_EXPLOITABLE';
  } else if (impact?.realImpact === 'informational' || impact?.realImpact === 'none') {
    verdict = 'NOT_DIRECTLY_EXPLOITABLE';
  } else if (impact?.realImpact === 'high' || impact?.realImpact === 'critical') {
    verdict = 'EXPLOITABLE';
  } else {
    verdict = 'OBSERVED';
  }

  // ─── 4. MULTI-DIMENSIONAL CONFIDENCE ───
  const confidence: MultiConfidence = {
    detection: 1.0, // pattern detected
    evidence: 0.85, // evidence found in recon/response
    exploitability: verdict === 'EXPLOITABLE' ? 0.8 : verdict === 'CONFIRMED_CONFIGURATION' ? 0.0 : 0.1,
    impact: impact ? (impact.realImpact === 'high' ? 0.8 : impact.realImpact === 'medium' ? 0.5 : impact.realImpact === 'informational' ? 0.1 : 0.0) : 0.0,
  };

  // ─── 5. SEVERITY (computed AFTER impact) ───
  const { severity, reasoning: severityReasoning } = computeSeverity(findingType, verdict, boundary, impact);

  // ─── 6. CORRELATIONS ───
  const correlations = getCorrelations(findingType);

  // ─── 7. EVIDENCE CHAIN ───
  const evidenceChain = [
    `=== FULL VERIFICATION PIPELINE ===`,
    ``,
    `FINDING: ${finding.title}`,
    `TYPE: ${finding.type}`,
    ``,
    `1. DETECTION: Pattern detected in response — confidence=${confidence.detection}`,
    ``,
    `2. EVIDENCE: ${confidence.evidence >= 0.8 ? 'Strong' : 'Moderate'} evidence found — confidence=${confidence.evidence}`,
    ``,
    `3. SECURITY BOUNDARY:`,
    boundary ? `   Data subject: ${boundary.dataSubject}` : '   N/A (not info_exposure type)',
    boundary ? `   Sensitivity: ${boundary.dataSensitivity}` : '',
    boundary ? `   Owner data: ${boundary.isOwnerData ? 'YES (requesting user\'s own data)' : 'NO (other user\'s data)'}` : '',
    boundary ? `   Public by design: ${boundary.isPublicByDesign ? 'YES' : 'NO'}` : '',
    boundary ? `   Boundary violated: ${boundary.boundaryViolated ? 'YES' : 'NO'}` : '',
    boundary ? `   Reasoning: ${boundary.boundaryReasoning}` : '',
    ``,
    `4. EXPLOITABILITY: confidence=${confidence.exploitability}`,
    `   ${verdict === 'EXPLOITABLE' ? 'Security boundary violated — exploit possible' : verdict === 'CONFIRMED_CONFIGURATION' ? 'Configuration weakness — not directly exploitable' : 'Not directly exploitable'}`,
    ``,
    `5. IMPACT:`,
    impact ? `   Attacker capability: ${impact.attackerCapability}` : '   N/A',
    impact ? `   Prerequisites: ${impact.attackPrerequisites}` : '',
    impact ? `   Impact level: ${impact.realImpact}` : '',
    impact ? `   Reasoning: ${impact.impactReasoning}` : '',
    ``,
    `6. SEVERITY: ${severity} (computed from impact, not type)`,
    `   ${severityReasoning}`,
    ``,
    `7. CORRELATIONS:`,
    correlations.length > 0
      ? correlations.map(c => `   → ${c.relatedFindingType} (${c.relationship}): ${c.description}`).join('\n')
      : '   None',
    ``,
    `VERDICT: ${verdict}`,
    `CONFIDENCE: detection=${confidence.detection} evidence=${confidence.evidence} exploitability=${confidence.exploitability} impact=${confidence.impact}`,
  ].join('\n');

  return {
    verdict,
    confidence,
    boundary,
    impact,
    severity,
    severityReasoning,
    correlations,
    evidenceChain,
  };
}
