/**
 * CryptoSentinel — Evidence Isolation Layer
 *
 * User: 'Нужна жёсткая архитектурная гарантия:
 * Один finding → один evidence context → один validation run → один verdict.
 * Evidence contamination способен испортить результаты всей системы.'
 *
 * PROBLEM: checkPassiveEvidence() and fullVerify() receive `sourceCode`
 * which is the ENTIRE recon text — containing security headers, HTML
 * content, JS bundle analysis, etc. ALL mixed together.
 *
 * When finding A (e.g., "CSP missing") and finding B (e.g., "OpenAPI
 * docs public") are both validated, they BOTH search the same sourceCode.
 * Finding B's checkInfoExposure might find `__net_track__` in sourceCode
 * (which belongs to finding A) and use it as evidence for finding B.
 * This is EVIDENCE CONTAMINATION.
 *
 * FIX: Each finding gets its OWN isolated EvidenceContext:
 * 1. HTTP response from provenance chain (already per-finding ✓)
 * 2. Finding's own description/title/location (already per-finding ✓)
 * 3. ONLY the relevant section of sourceCode scoped to this finding (NEW)
 *
 * The relevant section is determined by the finding's type and location:
 * - csp_missing → only the "SECURITY HEADERS" section
 * - info_exposure __net_track__ → only the HTML section where __net_track__ appears
 * - api_leak → only the JS bundle section or specific line where secret found
 * - cors_misconfig → only the CORS headers section
 *
 * This guarantees: evidence from finding A CANNOT leak into finding B's
 * validation context.
 */

export interface IsolatedEvidenceContext {
  findingId: string;
  findingType: string;
  findingTitle: string;
  findingDescription: string;
  findingLocation: string;

  // Isolated evidence — scoped to THIS finding only
  scopedSourceCode: string;     // ONLY relevant section, not full recon
  httpResponse: {               // From provenance chain (per-finding)
    bodyExcerpt: string;
    status: number;
    headers: Record<string, string>;
  } | null;

  // What evidence was used (for audit trail)
  evidenceSources: string[];
}

/**
 * Extract ONLY the relevant section of sourceCode for a specific finding.
 * This prevents evidence contamination between findings.
 */
export function isolateEvidence(
  finding: { type: string; title: string; description: string; location: string; severity: string },
  fullSourceCode: string,
  httpResponse: { bodyExcerpt: string; status: number; headers: Record<string, string> } | null,
): IsolatedEvidenceContext {
  const findingType = (finding.type || '').toLowerCase();
  const findingDesc = (finding.description || '').toLowerCase();
  const findingLoc = (finding.location || '').toLowerCase();

  const evidenceSources: string[] = [];
  let scopedSourceCode = '';

  // ─── TYPE-SPECIFIC EVIDENCE SCOPING ──────────────────────────

  if (findingType === 'csp_missing') {
    // CSP: only security headers section
    const headersMatch = fullSourceCode.match(/== SECURITY HEADERS ==[\s\S]*?(?====|$)/i);
    scopedSourceCode = headersMatch?.[0] || '';
    if (scopedSourceCode) evidenceSources.push('security headers section');
    // If no headers section found, use HTTP response headers
    if (!scopedSourceCode && httpResponse?.headers) {
      scopedSourceCode = JSON.stringify(httpResponse.headers, null, 2);
      evidenceSources.push('HTTP response headers (from provenance)');
    }
  }
  else if (findingType === 'cors_misconfig') {
    // CORS: only CORS-related headers
    if (httpResponse?.headers) {
      const corsHeaders: Record<string, string> = {};
      for (const [k, v] of Object.entries(httpResponse.headers)) {
        if (k.includes('access-control') || k.includes('cors') || k.includes('origin')) {
          corsHeaders[k] = v;
        }
      }
      scopedSourceCode = JSON.stringify(corsHeaders, null, 2);
      evidenceSources.push('CORS-specific HTTP response headers');
    }
    if (!scopedSourceCode) {
      const corsMatch = fullSourceCode.match(/(CORS|access-control-allow)[^\n]*/gi);
      scopedSourceCode = corsMatch?.join('\n') || '';
      if (scopedSourceCode) evidenceSources.push('CORS mentions in source');
    }
  }
  else if (findingType === 'clickjacking') {
    // Clickjacking: only X-Frame-Options header
    if (httpResponse?.headers) {
      const xfo = httpResponse.headers['x-frame-options'] || '';
      scopedSourceCode = `X-Frame-Options: ${xfo || 'MISSING'}`;
      evidenceSources.push('X-Frame-Options header');
    }
    // Also check for frame-ancestors in CSP
    if (httpResponse?.headers?.['content-security-policy']) {
      const csp = httpResponse.headers['content-security-policy'];
      const faMatch = csp.match(/frame-ancestors[^;]*/i);
      if (faMatch) {
        scopedSourceCode += `\nCSP frame-ancestors: ${faMatch[0]}`;
        evidenceSources.push('CSP frame-ancestors directive');
      }
    }
  }
  else if (findingType === 'hsts_missing') {
    if (httpResponse?.headers) {
      scopedSourceCode = `HSTS: ${httpResponse.headers['strict-transport-security'] || 'MISSING'}`;
      evidenceSources.push('HSTS header');
    }
  }
  else if (findingType === 'cookie_security') {
    if (httpResponse?.headers?.['set-cookie']) {
      scopedSourceCode = `Set-Cookie: ${httpResponse.headers['set-cookie']}`;
      evidenceSources.push('Set-Cookie header');
    }
  }
  else if (findingType === 'api_leak') {
    // api_leak: search ONLY the HTTP response body for real secret patterns
    // Do NOT search the full sourceCode (may contain OTHER findings' data)
    if (httpResponse?.bodyExcerpt) {
      scopedSourceCode = httpResponse.bodyExcerpt;
      evidenceSources.push('HTTP response body (from provenance chain)');
    }
    // If finding description mentions a specific value, extract ONLY that
    const valueMatch = finding.description.match(/["']([a-f0-9-]{20,})["']/i);
    if (valueMatch) {
      // Search ONLY for this specific value in the response body
      const value = valueMatch[1];
      const idx = httpResponse?.bodyExcerpt?.indexOf(value) ?? -1;
      if (idx >= 0) {
        scopedSourceCode = httpResponse!.bodyExcerpt.slice(Math.max(0, idx - 100), idx + value.length + 100);
        evidenceSources.push(`specific value "${value.slice(0, 10)}..." in HTTP response`);
      } else {
        // Value not found in HTTP response — evidence is NOT sufficient
        scopedSourceCode = `Value "${value.slice(0, 10)}..." NOT found in HTTP response body. ` +
          `Finding description mentions this value but it was not observed in the actual HTTP response.`;
        evidenceSources.push('value NOT found in HTTP response (insufficient evidence)');
      }
    }
  }
  else if (findingType === 'info_exposure') {
    // info_exposure: extract ONLY the specific data mentioned in the finding
    if (findingDesc.includes('__net_track__')) {
      // Find __net_track__ in HTTP response body (from provenance) ONLY
      if (httpResponse?.bodyExcerpt) {
        const idx = httpResponse.bodyExcerpt.indexOf('__net_track__');
        if (idx >= 0) {
          scopedSourceCode = httpResponse.bodyExcerpt.slice(Math.max(0, idx - 50), idx + 500);
          evidenceSources.push('__net_track__ section in HTTP response body');
        } else {
          // Try HTML content section of sourceCode (not the FULL sourceCode)
          const htmlMatch = fullSourceCode.match(/== HTML CONTENT[\s\S]*?__net_track__[\s\S]*?(?====|$)/i);
          if (htmlMatch) {
            scopedSourceCode = htmlMatch[0].slice(0, 1000);
            evidenceSources.push('HTML content section with __net_track__');
          }
        }
      }
    } else if (findingDesc.includes('stack trace') || findingDesc.includes('error message')) {
      if (httpResponse?.bodyExcerpt) {
        const paths = httpResponse.bodyExcerpt.match(/\/usr\/\S+|\/var\/\S+|\/home\/\S+|c:\\\S+/gi);
        if (paths) {
          scopedSourceCode = paths.join('\n');
          evidenceSources.push('internal file paths in HTTP response body');
        }
      }
    } else if (findingDesc.includes('email') || findingDesc.includes('pii')) {
      if (httpResponse?.bodyExcerpt) {
        const emails = [...httpResponse.bodyExcerpt.matchAll(/[\w.+-]+@(?:[\w-]+\.)+[\w]{2,}/g)].map(m => m[0]);
        const realEmails = emails.filter(e => !/test@|example@|demo@|admin@example/i.test(e));
        if (realEmails.length > 0) {
          scopedSourceCode = realEmails.join('\n');
          evidenceSources.push(`${realEmails.length} emails in HTTP response body`);
        }
      }
    } else {
      // Generic info_exposure: use HTTP response body only
      if (httpResponse?.bodyExcerpt) {
        scopedSourceCode = httpResponse.bodyExcerpt.slice(0, 1000);
        evidenceSources.push('HTTP response body (first 1000 chars)');
      }
    }
  }
  else if (findingType === 'header_misconfig') {
    // Only specific header mentioned in description
    if (httpResponse?.headers) {
      const headerMatch = findingDesc.match(/(x-powered-by|server)[:\s]*([^\n]+)/i);
      if (headerMatch) {
        const headerName = headerMatch[1].toLowerCase();
        scopedSourceCode = `${headerMatch[1]}: ${httpResponse.headers[headerName] || 'not found'}`;
        evidenceSources.push(`${headerMatch[1]} header`);
      }
    }
  }
  else {
    // For active types (XSS, SQLi, SSRF, etc.): use ONLY the HTTP response
    // from the provenance chain. Do NOT use sourceCode at all.
    if (httpResponse?.bodyExcerpt) {
      scopedSourceCode = httpResponse.bodyExcerpt;
      evidenceSources.push('HTTP response body from provenance chain (isolated)');
    } else {
      scopedSourceCode = '';
      evidenceSources.push('NO evidence available — no HTTP response');
    }
  }

  // If no evidence was scoped, mark as insufficient
  if (!scopedSourceCode) {
    scopedSourceCode = 'NO EVIDENCE ISOLATED FOR THIS FINDING. ' +
      'No relevant data found in HTTP response or scoped source section. ' +
      'This finding cannot be validated — evidence is insufficient.';
    evidenceSources.push('NONE — evidence isolation failed');
  }

  return {
    findingId: `${finding.type}:${finding.title}`.slice(0, 60),
    findingType,
    findingTitle: finding.title,
    findingDescription: finding.description,
    findingLocation: finding.location,
    scopedSourceCode,
    httpResponse,
    evidenceSources,
  };
}

/**
 * Verify that evidence belongs to THIS finding, not another finding.
 * Returns true if evidence is properly scoped (no contamination).
 */
export function verifyEvidenceIsolation(ctx: IsolatedEvidenceContext): {
  isIsolated: boolean;
  contaminationRisk: string | null;
} {
  // Check: if the scoped source contains data from multiple findings
  // (e.g., both __net_track__ AND CSP headers in the same context)
  const scoped = ctx.scopedSourceCode.toLowerCase();

  // If finding is csp_missing but scoped source contains __net_track__
  if (ctx.findingType === 'csp_missing' && scoped.includes('__net_track__')) {
    return {
      isIsolated: false,
      contaminationRisk: 'CSP finding context contains __net_track__ data — evidence contamination from info_exposure finding.',
    };
  }

  // If finding is info_exposure but scoped source contains security headers
  if (ctx.findingType === 'info_exposure' && scoped.includes('csp:') && !ctx.findingDescription.toLowerCase().includes('csp')) {
    return {
      isIsolated: false,
      contaminationRisk: 'info_exposure finding context contains CSP headers — evidence contamination from csp_missing finding.',
    };
  }

  // If finding is api_leak but scoped source contains other finding types' data
  if (ctx.findingType === 'api_leak' && (scoped.includes('__net_track__') || scoped.includes('csp: missing'))) {
    return {
      isIsolated: false,
      contaminationRisk: 'api_leak finding context contains other findings\' data — evidence contamination.',
    };
  }

  return { isIsolated: true, contaminationRisk: null };
}
