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

import { analyzeWithGLM, DEFAULT_MODEL } from './glm';

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
    
    const response = await analyzeWithGLM(
      prompt,
      finding.type,
      { apiKey, model, timeoutMs: 60_000 },
      undefined,
    );
    
    if (!response || !response.findings || response.findings.length === 0) {
      console.log('[generatePoc] LLM returned no response');
      return null;
    }
    
    // The LLM returns findings in our standard format — but we only care
    // about the description field which contains the PoC report text
    const reportText = response.findings[0]?.description || '';
    
    if (!reportText) {
      console.log('[generatePoc] LLM returned empty report');
      return null;
    }
    
    const cwe = CWE_MAP[finding.type] || 'CWE-?';
    const curlReplay = `curl -X ${finding.type.includes('upload') ? 'POST' : 'GET'} '${finding.target}${finding.parameter ? '?' + finding.parameter + '=' + encodeURIComponent(finding.payload) : ''}'`;
    
    console.log(`[generatePoc] ✓ PoC generated (${reportText.length} chars)`);
    
    return {
      cwe,
      impact: reportText.split('## Impact')[1]?.split('##')[0]?.trim() || 'See evidence',
      steps: reportText.split('## Reproduction')[1]?.split('##')[0]?.trim() || curlReplay,
      remediation: reportText.split('## Remediation')[1]?.trim() || 'See CWE guidance',
      curlReplay,
    };
  } catch (e) {
    console.error(`[generatePoc] Failed: ${String(e).slice(0, 100)}`);
    return null;
  }
}
