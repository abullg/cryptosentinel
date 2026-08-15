/**
 * Active Vulnerability Validator — LLM-based with structured exploit testing
 *
 * This module replaces the EVM-based validator (which required @ethereumjs/vm
 * + solc, both very heavy packages that caused OOM on Render free plan).
 * 
 * The LLM-based validator sends a structured exploit scenario to GLM 5.2
 * and asks it to confirm/deny with specific evidence. This is not as strong
 * as real EVM execution, but it's much lighter and works on free hosting.
 */

import { verifyVulnerabilityOnChain } from './glm';

export interface ValidationResult {
  confirmed: boolean;
  evidence: string;
  gasUsed?: number;
}

/**
 * Validate a vulnerability using LLM-based exploit analysis.
 * This calls verifyVulnerabilityOnChain which sends the vulnerability
 * to GLM 5.2 with source code + blockchain data for confirmation.
 */
export async function activelyValidate(
  sourceCode: string,
  contractName: string,
  vuln: {
    type: string;
    title: string;
    severity: string;
    description: string;
    location: string;
  },
  apiKey?: string,
  model?: string,
): Promise<ValidationResult> {
  // Use LLM-based verification
  const config = apiKey && model ? { apiKey, model } : { apiKey: '', model: 'z-ai/glm-5.2' };
  
  if (!config.apiKey) {
    return {
      confirmed: false,
      evidence: 'No API key configured for active validation',
    };
  }

  try {
    const result = await verifyVulnerabilityOnChain(
      { title: vuln.title, type: vuln.type, severity: vuln.severity, description: vuln.description, location: vuln.location },
      sourceCode,
      'No on-chain data available — analyzing source code only.',
      config
    );
    return {
      confirmed: result.confirmed,
      evidence: result.evidence,
    };
  } catch (e: any) {
    return {
      confirmed: false,
      evidence: `Validation error: ${String(e).slice(0, 200)}`,
    };
  }
}
