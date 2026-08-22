/**
 * generatePoc — LLM writes PoC report text on ALREADY CONFIRMED findings.
 *
 * Per Claude v10: "LLM только упаковывает уже доказанный HTTP-replay.
 * Не трогает severity, не предлагает ещё вектор."
 *
 * Input: confirmed finding (type, severity, evidence, payload, target, oracle)
 * Output: PoC report text (CWE, impact, steps, remediation)
 *
 * The LLM does NOT:
 *   - Detect new vulnerabilities
 *   - Change severity
 *   - Suggest additional attack vectors
 *   - Access the target URL
 *
 * The LLM ONLY:
 *   - Formats the already-proven HTTP evidence into readable text
 *   - Assigns CWE ID based on the finding type
 *   - Writes impact description
 *   - Writes reproduction steps (curl command)
 *   - Writes remediation recommendation
 */

import { callGLMRaw, DEFAULT_MODEL, type GLMMessage } from './glm';

export interface ConfirmedFinding {
  type: string;
  severity: string;
  evidence: string;
  payload: string;
  target: string;
  oracle: string;
  parameter?: string;
}

export interface PoCReport {
  cwe: string;
  impact: string;
  steps: string;
  remediation: string;
  curlReplay: string;
  rawReport: string;  // full markdown LLM response — for audit / debug
}

const CWE_MAP: Record<string, string> = {
  sqli: 'CWE-89 (SQL Injection)',
  reflected_xss: 'CWE-79 (Cross-site Scripting)',
  stored_xss: 'CWE-79 (Cross-site Scripting)',
  command_injection: 'CWE-78 (OS Command Injection)',
  file_inclusion: 'CWE-434 (Unrestricted Upload of File with Dangerous Type)',
  file_upload: 'CWE-434 (Unrestricted Upload of File with Dangerous Type)',
  csrf: 'CWE-352 (Cross-Site Request Forgery)',
  idor: 'CWE-639 (Authorization Bypass Through User-Controlled Key)',
  jwt_bypass: 'CWE-347 (Improper Verification of Cryptographic Signature)',
};

function buildPoCPrompt(finding: ConfirmedFinding): string {
  const cwe = CWE_MAP[finding.type] || 'CWE-? (Unknown)';
  
  return `You are a security report writer. You are given an ALREADY CONFIRMED vulnerability finding with hard HTTP evidence. Your job is to write a professional bug bounty report based ONLY on the provided evidence. Do NOT detect new vulnerabilities, do NOT change severity, do NOT suggest additional attack vectors.

CONFIRMED FINDING:
- Type: ${finding.type}
- Severity: ${finding.severity}
- CWE: ${cwe}
- Oracle: ${finding.oracle} (deterministic — zero false positives)
- Target: ${finding.target}
- Parameter: ${finding.parameter || 'N/A'}
- Payload: ${finding.payload}
- Evidence: ${finding.evidence}

Write a bug bounty report with these sections:

## Summary
[1-2 sentences describing the vulnerability]

## Impact
[What an attacker can do — based ONLY on the confirmed evidence]

## Reproduction
[Step-by-step curl commands to reproduce — use the actual payload and target from the evidence above]

## Remediation
[How to fix — specific to this vulnerability type]

Do NOT:
- Add findings not present in the evidence above
- Change the severity
- Suggest "additional vectors to test"
- Access any URL

Output ONLY the markdown report, nothing else.`;
}

export async function generatePoC(
  finding: ConfirmedFinding,
  apiKey: string,
  model: string = DEFAULT_MODEL,
): Promise<PoCReport | null> {
  try {
    const prompt = buildPoCPrompt(finding);
    console.log(`[generatePoc] Generating PoC for ${finding.type} on ${finding.target}`);

    // Per Claude v11 P1: use callGLMRaw (free-form text) — NOT analyzeWithGLM.
    // analyzeWithGLM hardcodes a smart-contract vuln-detection system prompt
    // and demands JSON output, which doesn't work for markdown report
    // generation. The previous implementation always returned null/empty
    // because the LLM followed the smart-contract prompt instead of the
    // report-generation prompt.
    const messages: GLMMessage[] = [
      {
        role: 'system',
        content: 'You are a security report writer. You write professional bug bounty reports in markdown based ONLY on provided evidence. You do NOT detect vulnerabilities, change severity, or suggest additional attack vectors. You output ONLY markdown text.',
      },
      { role: 'user', content: prompt },
    ];
    const reportText = await callGLMRaw(messages, {
      apiKey,
      model,
      temperature: 0.2,  // low temp for stable report formatting
      timeoutMs: 90_000,  // 90s — report writing shouldn't take 4 min
    });

    if (!reportText || reportText.trim().length === 0) {
      console.log('[generatePoc] LLM returned empty report');
      return null;
    }

    console.log(`[generatePoc] ✓ PoC generated (${reportText.length} chars)`);

    const cwe = CWE_MAP[finding.type] || 'CWE-?';
    // Build curl replay using finding.target + parameter + payload.
    // For GET IDOR: GET /vapi/api1/user/{id} with Authorization-Token header
    // (we leave the auth-token placeholder since the actual session token is
    // not part of the static PoC — testers replace <PEER_B_TOKEN> with their own).
    const isPost = finding.type.includes('upload') || finding.payload?.includes('POST');
    const curlReplay = isPost
      ? `curl -X POST '${finding.target}' -H 'Content-Type: application/json' -d '${finding.payload || '<PAYLOAD>'}'`
      : `curl -X GET '${finding.target}' -H 'Authorization-Token: <PEER_B_TOKEN>'`;

    // Extract sections from the LLM markdown response.
    // Falls back to the full report text if a section is missing.
    const sectionAfter = (header: string) => {
      const re = new RegExp(`##\\s*${header}\\s*([\\s\\S]*?)(?=\\n##\\s|$)`, 'i');
      const m = reportText.match(re);
      return m ? m[1].trim() : '';
    };

    return {
      cwe,
      impact: sectionAfter('Impact') || 'See full report below',
      steps: sectionAfter('Reproduction') || curlReplay,
      remediation: sectionAfter('Remediation') || 'See CWE guidance',
      curlReplay,
      rawReport: reportText,  // preserve full markdown for audit
    };
  } catch (e) {
    console.error(`[generatePoc] Failed: ${String(e).slice(0, 200)}`);
    return null;
  }
}
