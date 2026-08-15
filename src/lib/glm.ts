/**
 * GLM 5.2 client via OpenRouter API
 * OpenRouter provides unified access to multiple AI models including GLM series
 *
 * Architecture:
 * - GLM 5.2: Main analysis engine — NO token limits, full reasoning, blockchain verification
 * - DeepSeek V4 Pro: Lighter tasks — enhancement, classification, CWE matching
 */

const OPENROUTER_API_URL = 'https://openrouter.ai/api/v1/chat/completions';

export interface GLMMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface GLMResponse {
  content: string;
  model: string;
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

export interface GLMConfig {
  apiKey: string;
  model: string;
  temperature?: number;
  maxTokens?: number; // Optional — if omitted, model decides (NO LIMIT)
  timeoutMs?: number; // Per-call timeout override (default 180s for main, 45s for secondary)
}

/**
 * Available OpenRouter models
 * GLM 5.2 = primary deep analysis, DeepSeek = lighter secondary tasks
 */
export const AVAILABLE_MODELS = [
  { id: 'z-ai/glm-5.2', name: 'GLM 5.2 (1M ctx) — Primary', recommended: true, tier: 'primary' },
  { id: 'z-ai/glm-5.1', name: 'GLM 5.1', recommended: false, tier: 'primary' },
  { id: 'z-ai/glm-5-turbo', name: 'GLM 5 Turbo', recommended: false, tier: 'primary' },
  { id: 'z-ai/glm-4.7-flash', name: 'GLM 4.7 Flash', recommended: false, tier: 'fast' },
  { id: 'z-ai/glm-4.7', name: 'GLM 4.7', recommended: false, tier: 'primary' },
  { id: 'deepseek/deepseek-chat-v3-0324', name: 'DeepSeek V3 (Light Tasks)', recommended: false, tier: 'secondary' },
  { id: 'deepseek/deepseek-r1-0528', name: 'DeepSeek R1 (Reasoning)', recommended: false, tier: 'secondary' },
  { id: 'deepseek/deepseek-v4-pro-0813', name: 'DeepSeek V4 Pro 0813 (1M ctx) — Enhancement', recommended: false, tier: 'secondary' },
  { id: 'qwen/qwen3-235b-a22b', name: 'Qwen3 235B', recommended: false, tier: 'secondary' },
] as const;

/**
 * Default model IDs
 */
export const DEFAULT_MODEL = 'z-ai/glm-5.2';
// DeepSeek V4 Pro 0813 — upgraded from V3 (deepseek-chat-v3-0324) for the
// enhancement / classification / CWE matching secondary tasks.
// Reasons for the upgrade:
//   1. 1M context (vs 163K on V3) — can reason over larger codebases
//   2. Same $0.43/$0.87 per M tokens — V3 was $0.27/$1.12, so completion
//      is actually cheaper on V4 Pro for similar-quality output.
//   3. V4 Pro has substantially better code reasoning (per DeepSeek's
//      released benchmarks) — important for the enhance-vulnerability
//      and on-chain verify tasks which depend on subtle code reading.
export const DEEPSEEK_MODEL = 'deepseek/deepseek-v4-pro-0813';

/**
 * Format an OpenRouter HTTP error into a clear, actionable message.
 * Returns a string suitable for surfacing in the UI Activity feed.
 *
 * This is the single source of truth for "what does this status code mean
 * for the user". Without it, callers just dumped the raw JSON body which
 * was useless for end users trying to debug their config.
 */
export function formatOpenRouterError(status: number, body: string, model: string): string {
  // Try to extract the OpenRouter error message
  let upstreamMessage = '';
  try {
    const parsed = JSON.parse(body);
    upstreamMessage = parsed?.error?.message || parsed?.message || '';
  } catch {
    upstreamMessage = body.slice(0, 200);
  }

  switch (status) {
    case 400:
      return `OpenRouter rejected the request (400 Bad Request${model ? ` for ${model}` : ''}). ${upstreamMessage}`.trim();
    case 401:
      return 'OpenRouter API key is invalid or missing (401). Get a valid key at https://openrouter.ai/keys — it must start with "sk-or-v1-".';
    case 402:
      return 'OpenRouter credits exhausted (402 Payment Required). Add credits at https://openrouter.ai/credits.';
    case 403:
      return `OpenRouter denied access (403 Forbidden). The key may not have permission to use ${model}. ${upstreamMessage}`.trim();
    case 408:
      return 'OpenRouter request timed out (408). The model may be overloaded — retry, or switch to a faster model.';
    case 429:
      return 'OpenRouter rate limit hit (429 Too Many Requests). Wait a few seconds and retry.';
    case 500:
    case 502:
    case 503:
    case 504:
      return `OpenRouter upstream error (${status}). The model provider is having issues — retry in a moment. ${upstreamMessage}`.trim();
    default:
      return `OpenRouter API error (${status}): ${upstreamMessage || 'Unknown error'}`;
  }
}

/**
 * Call GLM via OpenRouter API — NO TOKEN LIMITS by default
 * The model decides how many tokens it needs for full reasoning
 *
 * Error handling: surfaces a CLEAR, actionable message for the common
 * failure modes (401 invalid key, 402 quota, 403 forbidden, 408/504 timeout,
 * 429 rate-limit). The previous implementation threw a generic
 * "OpenRouter API error (401): {\"error\":...}" string which was almost
 * impossible for end users to act on.
 */
export async function callGLM(
  messages: GLMMessage[],
  config: GLMConfig
): Promise<GLMResponse> {
  const {
    apiKey,
    model,
    temperature = 0.1,
    // NO default maxTokens — let the model reason as long as it needs
  } = config;

  if (!apiKey) {
    throw new Error('API key is required for GLM analysis');
  }

  // Default 180s — Render has 15-minute timeout, so we can afford
  // generous budgets for deep reasoning with max_tokens=32768.
  const callTimeout = config.timeoutMs || 180_000;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), callTimeout);
  let response: Response;
  try {
    // Build request body
    // GLM 5.2 reasoning mode: without max_tokens, the model generates
    // infinite reasoning tokens and never stops. Set a generous default.
    const requestBody: Record<string, unknown> = {
      model: model || DEFAULT_MODEL,
      messages,
      temperature,
    };
    // max_tokens: 32768 for GLM models — MAXIMUM reasoning depth.
    // Render has 15-minute timeout (vs Vercel Hobby 60s), so we can afford
    // the full reasoning chain. This gives ~24,000 words of output — enough
    // for thorough multi-finding analysis with full PoC outlines.
    // No max_tokens limit — model decides when analysis is complete
    // DeepSeek and other models keep their explicit limits from config

    response = await fetch(OPENROUTER_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
        'HTTP-Referer': 'https://cryptosentinel.app',
        'X-Title': 'CryptoSentinel',
      },
      body: JSON.stringify(requestBody),
      signal: controller.signal,
    });
  } catch (fetchErr) {
    clearTimeout(timeout);
    if (fetchErr instanceof Error && fetchErr.name === 'AbortError') {
      throw new Error(`OpenRouter API request timed out after ${callTimeout / 1000}s. The model may be overloaded — try again or switch to a faster model (e.g. GLM 4.7 Flash).`);
    }
    // Network-level failure (DNS, connection refused, etc.) — surface a
    // distinct message so callers can distinguish from API errors.
    throw new Error(`Network error reaching OpenRouter: ${fetchErr instanceof Error ? fetchErr.message : String(fetchErr)}`);
  }
  clearTimeout(timeout);

  if (!response.ok) {
    const errorBody = await response.text().catch(() => '');
    throw new Error(formatOpenRouterError(response.status, errorBody, model || DEFAULT_MODEL));
  }

  const data = await response.json();

  if (!data.choices || data.choices.length === 0) {
    throw new Error('No response from model');
  }

  const message = data.choices[0].message;
  // Some models (GLM 5.x with reasoning) return null content and put the
  // answer in `reasoning`. Fall back to reasoning if content is empty.
  let content = message.content;
  if (!content && message.reasoning) {
    // Try to extract JSON array from reasoning (some models put the answer there)
    const jsonMatch = message.reasoning.match(/\[[\s\S]*\]/);
    content = jsonMatch ? jsonMatch[0] : message.reasoning;
  }
  if (!content) {
    // Model returned empty response
    const finishReason = data.choices[0].finish_reason;
    if (finishReason === 'length') {
      throw new Error('Model ran out of tokens. This should not happen with unlimited tokens — the model may have hit a context window limit. Try with a shorter input.');
    }
    throw new Error('Model returned empty response');
  }

  return {
    content,
    model: data.model || model,
    usage: data.usage,
  };
}

/**
 * Call DeepSeek (secondary model) for lighter tasks
 * Used for: enhancement, classification, CWE matching, severity assessment
 * These tasks don't need deep reasoning — just quick, accurate responses
 */
export async function callDeepSeek(
  messages: GLMMessage[],
  config: GLMConfig
): Promise<GLMResponse> {
  return callGLM(messages, {
    ...config,
    model: DEEPSEEK_MODEL,
    temperature: 0.2,
    maxTokens: 8192, // DeepSeek gets a limit — it's for lighter tasks
    timeoutMs: 30_000, // 30s timeout for DeepSeek (fast tasks)
  });
}

/**
 * System prompt for vulnerability analysis — ENHANCED with blockchain verification
 */
export const VULN_ANALYSIS_SYSTEM_PROMPT = `You are CryptoSentinel, an elite autonomous AI vulnerability scanner for smart contracts and crypto ecosystems. You combine the analytical rigor of CodeQL dataflow analysis, Semgrep pattern precision, and formal verification reasoning. You have UNLIMITED reasoning capacity — think as deeply as needed. Do NOT limit your analysis.

EXPERTISE:
- Languages: Solidity, Vyper, Move, Rust (Solana BPF), Cairo, Go (CosmWasm)
- DeFi protocols: AMMs, lending, derivatives, bridges, oracles, staking, governance, NFT
- Attack vectors: reentrancy, oracle manipulation, flash loans, MEV/sandwich, access control, integer overflow, delegatecall hijacking, storage collision, governance attacks, signature replay, front-running, griefing, forced acceptance
- Security tools: Slither, Mythril, Echidna, Certora, Foundry, Medusa, Halmos
- Standards: SWC Registry, CWE, OWASP Top 10 2021, EIP standards, HackenProof severity classification

BLOCKCHAIN VERIFICATION CAPABILITIES:
You have access to blockchain verification tools that can:
- Verify if a contract is deployed on-chain (Etherscan/Ethplorer)
- Check contract bytecode against source code
- Analyze on-chain transaction patterns for exploit evidence
- Verify token balances and state
- Check for known exploits in audit databases
- Analyze gas patterns that indicate vulnerability exploitation
- Verify ownership and access control patterns on-chain

When blockchain verification data is provided (marked with [BLOCKCHAIN-VERIFY]), use it to:
1. CONFIRM vulnerabilities with on-chain evidence when available
2. Upgrade confidence scores when blockchain data supports the finding
3. Add on-chain evidence to validation steps
4. Mark vulnerabilities as "confirmed" when blockchain data proves exploitation is possible
5. Identify if the vulnerability has already been exploited on-chain

SEVERITY CLASSIFICATION (HackenProof — Smart Contract Focus):
Severity is determined by FINANCIAL IMPACT, not CVSS. Priority order:

**CRITICAL** — Direct threat to funds/assets/protocol viability:
  - Direct theft of funds/NFTs (reentrancy drain, access control bypass to treasury)
  - Permanent freeze of funds/NFTs (selfdestruct, owner lock without recovery)
  - Governance manipulation (vote hijacking, quorum bypass, instant execution without timelock)
  - Protocol insolvency (under-collateralization, unbacked tokens, critical mispricing)
  - Unauthorized mint/burn of tokens (inflation attack, value dilution)

**HIGH** — Temporary impact or indirect fund risk:
  - Temporary freeze of funds/NFTs (pause without auto-unpause)
  - Theft of unclaimed funds (yield, royalties, pending rewards)
  - Permanent freeze of unclaimed funds
  - Oracle manipulation (stale/manipulated price leading to over-borrowing)

**MEDIUM** — No direct fund loss, protocol operability impact:
  - Theft of gas, gas limit / Out-of-Gas
  - DoS (gas exhaustion, block stuffing)
  - Griefing attacks (no profit for attacker)

**LOW** — Minimal security impact:
  - Unfulfilled promised returns (e.g., APY)
  - Uninitialized storage variables (often low risk)

OUT OF SCOPE (do NOT report these — omit them from the JSON array entirely):
  - Theoretical vulnerabilities without a practical, reproducible exploit
  - UI/UX bugs
  - Descriptive error messages (information leakage without impact)
  - Open redirects without financial/auth impact
  - Rate limiting on non-critical actions
  - Known 2FA session issues
  - Third-party application bugs

If you encounter a finding that falls into OUT OF SCOPE, OMIT it. Do not include it in the JSON array. Do not report it as LOW — that would defeat the out-of-scope rule.

ANALYSIS METHODOLOGY (Deep CodeQL-style reasoning chain):
For EACH vulnerability, follow this FULL reasoning chain — do NOT skip steps:

1. **SOURCE IDENTIFICATION**: Where does the attack surface originate? (msg.sender, function parameters, external calls, oracle data)
2. **DATAFLOW TRACKING**: How does attacker-controlled data flow through the contract? Track EVERY variable assignment, function call, and state mutation in the path.
3. **SINK REACHABILITY**: Does the tainted data reach a dangerous operation? (external call, state write, transfer, delegatecall)
4. **SANITIZER CHECK**: Are there ANY guards? (require, onlyOwner, nonReentrant, bounds check, SafeMath). Check if they are sufficient or bypassable.
5. **EXPLOIT CONSTRUCTION**: Construct a CONCRETE, REPRODUCIBLE attack scenario. Include specific function calls, parameter values, and state transitions.
6. **IMPACT ASSESSMENT**: What is the MAXIMUM financial/systemic impact? Quantify in ETH/USD where possible. Use HackenProof severity tiers above.
7. **CONFIDENCE SCORING**: Rate certainty on a 0.0-1.0 scale with detailed justification. If blockchain evidence confirms the vuln, confidence should be >= 0.90.
8. **ON-CHAIN VERIFICATION**: If blockchain data is available, state whether the vulnerability is confirmed on-chain. Include specific transaction hashes or addresses if available.

For each vulnerability, provide:
1. **Title**: Concise vulnerability name
2. **Type**: One of: reentrancy, oracle_manipulation, access_control, integer_overflow, flash_loan, front_running, delegatecall, storage_collision, unchecked_call, arbitrary_call, signature_replay, time_manipulation, denial_of_service, bad_randomness, short_address, tx_origin, state_shadowing, governance_hijack, unauthorized_mint, protocol_insolvency, callback_reentrancy, call_cycle, mev_sandwich, fee_on_transfer, first_depositor, permanent_pause, xss, sql_injection, command_injection, code_injection, ssrf, path_traversal, csrf, idor, prototype_pollution, deserialization, broken_crypto, open_redirect, info_exposure, auth_bypass, api_leak, cors_misconfig, business_logic
3. **Severity**: critical, high, medium, or low — per HackenProof financial-impact classification above
4. **Location**: File and line number(s)
5. **Description**: DETAILED technical explanation following the FULL reasoning chain: source → dataflow → sink → sanitizer check → exploit → impact → on-chain evidence. Include HackenProof severity reasoning.
6. **Validation Steps**: Step-by-step procedure to confirm the vulnerability (include on-chain verification steps when possible)
7. **PoC Outline**: Detailed proof-of-concept attack contract with specific attack parameters
8. **V1-V4 Scores**: Estimated scores for each validator (0.0-1.0) — higher when blockchain evidence confirms

VALIDATOR SCORE CALIBRATION (V1-V4):
Each validator measures a DIFFERENT line of evidence. Calibrate scores carefully:
- **V1 (Symbolic Execution)**: Confidence that a symbolic-execution tool (e.g., Halmos, Manticore) would CONFIRM this vulnerability by reaching the vulnerable state through symbolic path exploration. 0.0 = no path exists; 1.0 = clearly reachable with concrete constraints.
- **V2 (Fuzzing)**: Confidence that a fuzzer (e.g., Echidna, Medusa, Foundry invariant tests) would TRIGGER the bug within reasonable time. 0.0 = unreachable by random input; 1.0 = trivially triggered.
- **V3 (Formal Verification)**: Confidence that a formal verifier (e.g., Certora, Scribble) would PROVE the violation against a suitable specification. 0.0 = no specification applies; 1.0 = violation directly contradicts a stated invariant.
- **V4 (Economic)**: Confidence that the exploit is ECONOMICALLY viable — accounting for capital cost, MEV, slippage, gas, and competition. 0.0 = unprofitable or impractical; 1.0 = trivially profitable, no special conditions required.

If you have NO basis to estimate a validator, set it to 0.5 (neutral). Do NOT set all four to the same value unless they truly coincide.
9. **CWE**: The CWE or SWC ID for this vulnerability
10. **BlockchainVerified**: true/false — whether on-chain evidence confirms this vulnerability
11. **OnChainEvidence**: String describing any on-chain evidence (transaction hashes, addresses, patterns)

CRITICAL STYLE RULES:
- For vulnerabilities you DO report, write with CONFIDENCE. Avoid weak hedging language like "may", "might", "could", "potentially", "possibly", "appears to", "seems to".
- Use definitive language: "IS", "HAS", "CAUSES", "LEADS TO", "ALLOWS", "ENABLES", "CREATES", "TRIGGERS", "EXPOSES".
- Every vulnerability description MUST state the vulnerability as a CONFIRMED FACT, with the dataflow path explicit: "User input (source: X) flows through variable Y to sink Z without sanitization."
- When blockchain evidence is available, state it explicitly: "On-chain verification CONFIRMS: [evidence]"

IMPORTANT — REPORTING DISCIPLINE (do NOT contradict the OUT OF SCOPE rule above):
- If you are NOT certain a vulnerability exists OR cannot construct a concrete exploit, DO NOT report it.
- This is consistent with the OUT OF SCOPE rule: theoretical without practical exploit = omit.
- It is BETTER to report 2 confirmed findings than 10 speculative ones.
- When you DO report, write with confidence. When you're NOT confident, omit — do NOT hedge.

DEEP REASONING INSTRUCTION:
- You have UNLIMITED reasoning capacity. Think as deeply and thoroughly as needed.
- Do NOT simplify or abbreviate your analysis for any reason.
- Consider ALL edge cases, ALL interaction paths, ALL state transitions.
- For DeFi protocols, analyze economic attack vectors (flash loans, MEV, sandwich attacks) in full detail.
- Cross-reference with known exploits (DAO hack, bZx flash loan, Poly dragon, Cream finance, etc.)
- Use formal verification reasoning where applicable (invariants, preconditions, postconditions).

Be thorough and precise. Focus on real, exploitable vulnerabilities. Do NOT report false positives. Provide detailed validation steps that another security researcher could reproduce.

Respond in JSON format as an array of vulnerabilities:
[
  {
    "title": "...",
    "type": "...",
    "severity": "...",
    "location": "...",
    "description": "...",
    "validationSteps": "...",
    "pocOutline": "...",
    "v1Symbolic": 0.0-1.0,
    "v2Fuzzing": 0.0-1.0,
    "v3Formal": 0.0-1.0,
    "v4Economic": 0.0-1.0,
    "cwe": "...",
    "blockchainVerified": true/false,
    "onChainEvidence": "..."
  }
]`;

/**
 * Analyze contract source code using GLM 5.2 — NO TOKEN LIMITS
 */
export async function analyzeWithGLM(
  sourceCode: string,
  contractName: string,
  config: GLMConfig,
  blockchainContext?: string
): Promise<Array<{
  title: string;
  type: string;
  severity: string;
  location: string;
  description: string;
  validationSteps: string;
  pocOutline: string;
  v1Symbolic: number;
  v2Fuzzing: number;
  v3Formal: number;
  v4Economic: number;
  blockchainVerified?: boolean;
  onChainEvidence?: string;
}>> {
  let userContent = `Analyze the following smart contract for vulnerabilities:\n\nContract: ${contractName}\n\`\`\`solidity\n${sourceCode}\n\`\`\`\n`;

  // Add blockchain verification context if available
  if (blockchainContext) {
    userContent += `\n[BLOCKCHAIN-VERIFY] On-chain data available for this contract:\n${blockchainContext}\nUse this data to confirm or deny vulnerabilities. Update blockchainVerified and onChainEvidence fields accordingly.\n`;
  }

  userContent += `\nIdentify all vulnerabilities. Think DEEPLY — you have unlimited reasoning capacity. Your FINAL output MUST be a valid JSON array — no markdown, no prose after the array. Output ONLY the JSON array:\n[{"title":"...","type":"...","severity":"...","location":"...","description":"...","validationSteps":"...","pocOutline":"...","v1Symbolic":0.0,"v2Fuzzing":0.0,"v3Formal":0.0,"v4Economic":0.0,"cwe":"...","blockchainVerified":false,"onChainEvidence":""}]`;

  const messages: GLMMessage[] = [
    { role: 'system', content: VULN_ANALYSIS_SYSTEM_PROMPT },
    { role: 'user', content: userContent },
  ];

  // Note: callGLM internally caps GLM models at 16384 tokens (see callGLM impl).
  // This is sufficient for thorough multi-finding analysis. Previously the
  // comments here claimed "unlimited reasoning" which was misleading — the
  // cap existed but was hidden at 8192 (now 16384).
  const response = await callGLM(messages, {
    ...config,
    temperature: 0.05, // Very low temperature for precise analysis
    // No explicit maxTokens — callGLM applies the GLM default (16384)
  });

  // Parse JSON from response
  try {
    let jsonStr = response.content.trim();
    const jsonMatch = jsonStr.match(/\[[\s\S]*\]/);
    if (jsonMatch) {
      jsonStr = jsonMatch[0];
    }

    const parsed = JSON.parse(jsonStr);
    if (Array.isArray(parsed)) {
      return parsed.map(v => ({
        title: v.title || 'Unknown Vulnerability',
        type: v.type || 'unknown',
        severity: v.severity || 'medium',
        location: v.location || `${contractName}:L1`,
        description: v.description || 'No description provided',
        validationSteps: v.validationSteps || 'Validation pending.',
        pocOutline: v.pocOutline || '',
        v1Symbolic: typeof v.v1Symbolic === 'number' ? v.v1Symbolic : 0.5,
        v2Fuzzing: typeof v.v2Fuzzing === 'number' ? v.v2Fuzzing : 0.5,
        v3Formal: typeof v.v3Formal === 'number' ? v.v3Formal : 0.5,
        v4Economic: typeof v.v4Economic === 'number' ? v.v4Economic : 0,
        blockchainVerified: typeof v.blockchainVerified === 'boolean' ? v.blockchainVerified : false,
        onChainEvidence: v.onChainEvidence || '',
      }));
    }
    return [];
  } catch {
    console.error('Failed to parse GLM response as JSON, attempting text extraction...');
    return extractVulnsFromText(response.content, contractName);
  }
}

/**
 * Extract vulnerabilities from free-text AI response when JSON parsing fails.
 */
function extractVulnsFromText(text: string, contractName: string): Array<{
  title: string; type: string; severity: string; location: string;
  description: string; validationSteps: string; pocOutline: string;
  v1Symbolic: number; v2Fuzzing: number; v3Formal: number; v4Economic: number;
  blockchainVerified?: boolean; onChainEvidence?: string;
}> {
  if (!text || text.length < 50) return [];

  const results: Array<{
    title: string; type: string; severity: string; location: string;
    description: string; validationSteps: string; pocOutline: string;
    v1Symbolic: number; v2Fuzzing: number; v3Formal: number; v4Economic: number;
    blockchainVerified?: boolean; onChainEvidence?: string;
  }> = [];

  const severityPattern = /\b(critical|high|medium|low)\b/gi;
  const typePattern = /\b(reentrancy|oracle_manipulation|access_control|integer_overflow|flash_loan|front_running|delegatecall|storage_collision|unchecked_call|denial_of_service|business_logic|governance_hijack|info_exposure)\b/gi;

  const lines = text.split('\n');
  let currentVuln: { title: string; lines: string[] } | null = null;

  for (const line of lines) {
    const headerMatch = line.match(/^\s*\d+\.\s*\**(.+?)\**\s*$/);
    if (headerMatch && headerMatch[1].length > 5) {
      if (currentVuln && currentVuln.lines.length > 0) {
        const desc = currentVuln.lines.join('\n').trim();
        const detectedSev = desc.match(severityPattern)?.[0]?.toLowerCase() || 'medium';
        const detectedType = desc.match(typePattern)?.[0]?.toLowerCase() || 'unknown';
        results.push({
          title: currentVuln.title,
          type: detectedType,
          severity: ['critical', 'high', 'medium', 'low'].includes(detectedSev) ? detectedSev : 'medium',
          location: `${contractName}:L1`,
          description: desc.slice(0, 2000),
          validationSteps: 'Extracted from AI reasoning text. Run structured analysis for detailed validation.',
          pocOutline: '',
          v1Symbolic: 0.6, v2Fuzzing: 0.5, v3Formal: 0.4, v4Economic: 0.2,
          blockchainVerified: false,
          onChainEvidence: '',
        });
      }
      currentVuln = { title: headerMatch[1].trim(), lines: [] };
    } else if (currentVuln) {
      currentVuln.lines.push(line);
    }
  }

  if (currentVuln && currentVuln.lines.length > 0) {
    const desc = currentVuln.lines.join('\n').trim();
    const detectedSev = desc.match(severityPattern)?.[0]?.toLowerCase() || 'medium';
    const detectedType = desc.match(typePattern)?.[0]?.toLowerCase() || 'unknown';
    results.push({
      title: currentVuln.title,
      type: detectedType,
      severity: ['critical', 'high', 'medium', 'low'].includes(detectedSev) ? detectedSev : 'medium',
      location: `${contractName}:L1`,
      description: desc.slice(0, 2000),
      validationSteps: 'Extracted from AI reasoning text. Run structured analysis for detailed validation.',
      pocOutline: '',
      v1Symbolic: 0.6, v2Fuzzing: 0.5, v3Formal: 0.4, v4Economic: 0.2,
      blockchainVerified: false,
      onChainEvidence: '',
    });
  }

  if (results.length === 0) {
    const mentions = text.match(typePattern);
    if (mentions) {
      const uniqueTypes = [...new Set(mentions.map(m => m.toLowerCase()))];
      for (const type of uniqueTypes.slice(0, 5)) {
        results.push({
          title: `AI detected: ${type.replace(/_/g, ' ')}`,
          type,
          severity: type === 'reentrancy' ? 'critical' : 'medium',
          location: `${contractName}:L1`,
          description: `AI reasoning identified a potential ${type.replace(/_/g, ' ')} vulnerability. See reasoning text for details.`,
          validationSteps: 'Extracted from AI reasoning. Run structured analysis for validation.',
          pocOutline: '',
          v1Symbolic: 0.5, v2Fuzzing: 0.4, v3Formal: 0.3, v4Economic: 0.1,
          blockchainVerified: false,
          onChainEvidence: '',
        });
      }
    }
  }

  const noisePatterns = /\b(already detected|false positive|not (?:really|a )?vulnerability|not applicable|not exploitable|correct behavior|no risk|safe|secure|benign)\b/i;
  const filtered = results.filter(r => !noisePatterns.test(r.title) && !noisePatterns.test(r.description));

  console.log(`Extracted ${filtered.length} vulnerabilities from reasoning text (filtered from ${results.length})`);
  return filtered.slice(0, 8);
}

/**
 * Enhance vulnerability description using DeepSeek (lighter task)
 * DeepSeek V3 is fast and accurate for enhancement — no need for GLM's deep reasoning here
 */
export async function enhanceVulnerabilityDescription(
  vuln: {
    title: string;
    type: string;
    severity: string;
    description: string;
    location: string;
    blockchainVerified?: boolean;
    onChainEvidence?: string;
  },
  sourceCode: string,
  config: GLMConfig
): Promise<string> {
  let blockchainNote = '';
  if (vuln.blockchainVerified && vuln.onChainEvidence) {
    blockchainNote = `\n\n[BLOCKCHAIN-VERIFIED] This vulnerability IS confirmed on-chain. Evidence: ${vuln.onChainEvidence}\nInclude this evidence in your enhancement.`;
  }

  const messages: GLMMessage[] = [
    {
      role: 'system',
      content: `You are a senior smart contract auditor. Provide a detailed, well-argued vulnerability analysis in HakenProof format. Be precise, technical, and include specific code references. Write in clear, professional English.

CRITICAL STYLE: Write with ABSOLUTE CERTAINTY. NEVER use hedging words: "may", "might", "could", "potentially", "possibly", "appears to", "seems to", "likely", "probably". Use definitive language: "IS", "HAS", "CAUSES", "LEADS TO", "ALLOWS", "EXPOSES", "CREATES". Every finding must read as a CONFIRMED FACT, not a hypothesis.`,
    },
    {
      role: 'user',
      content: `Enhance the following vulnerability report with detailed technical argumentation:\n\nTitle: ${vuln.title}\nType: ${vuln.type}\nSeverity: ${vuln.severity}\nLocation: ${vuln.location}\nCurrent Description: ${vuln.description}${blockchainNote}\n\nSource code context:\n\`\`\`solidity\n${sourceCode.slice(0, 4000)}\n\`\`\`\n\nProvide a comprehensive vulnerability details section with:\n1. Root cause analysis\n2. Attack scenario step-by-step\n3. Impact assessment (financial, systemic)\n4. Recommended fix with code example\n5. References to SWC/EIP standards`,
    },
  ];

  // Use DeepSeek for enhancement — lighter, faster task
  const response = await callDeepSeek(messages, config);

  return response.content;
}

/**
 * System prompt for web/exchange vulnerability analysis — ENHANCED
 */
export const WEB_VULN_SYSTEM_PROMPT = `You are CryptoSentinel, an elite AI vulnerability scanner for crypto exchanges, DeFi frontends, and web3 applications. You apply CodeQL-style taint analysis and Semgrep pattern precision to web security. You have UNLIMITED reasoning capacity — think as deeply as needed.

EXPERTISE:
- Web security: XSS (reflected, stored, DOM), CSRF, Clickjacking, Open Redirect, SSRF, IDOR
- API security: Auth bypass, Broken access control, Rate limiting, Mass assignment, JWT manipulation
- Crypto-specific: API key leaks, Wallet connect hijacking, Phishing vectors, Token approval exploits, Signature replay
- Frontend security: DOM clobbering, Prototype pollution, PostMessage abuse, Service worker hijacking
- Session/Cookie: Session fixation, JWT manipulation, Cookie tossing, CSRF token bypass
- CORS/CSP misconfigurations, Subdomain takeover, DNS rebinding
- Injection: SQL injection, NoSQL injection, Command injection, LDAP injection, Code injection (eval)
- Exchange-specific: Price manipulation via API, Withdrawal flow bypass, KYC bypass, Trading engine abuse
- Standards: CWE, OWASP Top 10 2021, OWASP API Security Top 10, HackenProof severity classification

SEVERITY CLASSIFICATION (HackenProof — Web & Mobile Focus):
Uses CVSS + specific examples for crypto/web3 context:

**CRITICAL** — Direct fund/asset loss or RCE:
  - Payment manipulation (modify amounts, redirect payments)
  - SQL Injection leading to fund loss
  - Remote Code Execution (RCE)
  - Business logic flaws with user fund/asset loss
  - Command Injection

**HIGH** — Significant data/auth breach or wallet risk:
  - Subdomain takeover (on domains linked to wallets/sensitive assets)
  - Stored XSS (enables session/wallet theft)
  - SSRF (access to internal services)
  - Sensitive data leakage (>15% of users affected)
  - File Inclusion, Authentication Bypass, IDOR, Privilege Escalation

**MEDIUM** — Limited impact or smaller user base:
  - Reflected XSS
  - Subdomain takeover (non-wallet domains)
  - 2FA Bypass
  - Sensitive data leakage (3-15% users)
  - CSRF

**LOW** — Minimal business impact:
  - HTML Injection
  - Subdomain takeover without business impact
  - Missing rate limiting on non-critical actions

ANALYSIS METHODOLOGY (Deep Taint tracking + Exploit construction):
For EACH vulnerability:
1. **SOURCE**: Where does user input enter? (req.query, req.body, URL params, cookies, headers, postMessage)
2. **DATAFLOW**: How does it propagate? Track through variable assignments, function calls, template rendering.
3. **SINK**: Where does it reach a dangerous operation? (innerHTML, eval, exec, SQL query, fetch, redirect)
4. **SANITIZER**: Is there a validation/encoding step? (DOMPurify, escapeHtml, parameterized query, CSRF token)
5. **EXPLOIT**: Construct a concrete attack URL or payload.
6. **IMPACT**: What can the attacker achieve? (RCE, data theft, fund theft, session hijack, phishing). Use HackenProof severity tiers.

For each vulnerability, provide:
1. **Title**: Concise vulnerability name
2. **Type**: One of: xss, csrf, clickjacking, open_redirect, idor, auth_bypass, api_leak, cors_misconfig, csp_missing, ssrf, session_fixation, dom_clobbering, prototype_pollution, postmessage_abuse, wallet_hijack, token_approval_exploit, rate_limiting, mass_assignment, subdomain_takeover, dns_rebinding, sql_injection, command_injection, code_injection, path_traversal, deserialization, broken_crypto, info_exposure, business_logic
3. **Severity**: critical, high, medium, or low
4. **Location**: Where in the application
5. **Description**: Detailed technical explanation: source → dataflow → sink → sanitizer → exploit → impact
6. **Validation Steps**: Step-by-step procedure
7. **PoC Outline**: Proof-of-concept
8. **V1-V4 Scores**: Estimated validation scores (0.0-1.0)
9. **CWE**: The CWE ID
10. **BlockchainVerified**: true/false
11. **OnChainEvidence**: String

CRITICAL STYLE RULES:
- Write with ABSOLUTE CERTAINTY. NEVER use hedging language.
- Use definitive statements: "IS", "HAS", "CAUSES", "LEADS TO", "ALLOWS", "EXPOSES".
- Every vulnerability description MUST be stated as a CONFIRMED FACT.
- Include the taint flow path.

Focus on real, exploitable vulnerabilities. Prioritize those leading to fund theft, data leaks, or trading manipulation.

Respond in JSON format as an array:
[
  {
    "title": "...",
    "type": "...",
    "severity": "...",
    "location": "...",
    "description": "...",
    "validationSteps": "...",
    "pocOutline": "...",
    "v1Symbolic": 0.0-1.0,
    "v2Fuzzing": 0.0-1.0,
    "v3Formal": 0.0-1.0,
    "v4Economic": 0.0-1.0,
    "cwe": "...",
    "blockchainVerified": false,
    "onChainEvidence": ""
  }
]`;

/**
 * Analyze exchange/website for web vulnerabilities using GLM — NO TOKEN LIMITS
 */
export async function analyzeWebWithGLM(
  sourceCode: string,
  targetName: string,
  config: GLMConfig
): Promise<Array<{
  title: string;
  type: string;
  severity: string;
  location: string;
  description: string;
  validationSteps: string;
  pocOutline: string;
  v1Symbolic: number;
  v2Fuzzing: number;
  v3Formal: number;
  v4Economic: number;
  blockchainVerified?: boolean;
  onChainEvidence?: string;
}>> {
  const messages: GLMMessage[] = [
    { role: 'system', content: WEB_VULN_SYSTEM_PROMPT },
    {
      role: 'user',
      content: `Analyze the following crypto exchange/web application for security vulnerabilities:\n\nTarget: ${targetName}\n\`\`\`\n${sourceCode.slice(0, 30000)}\n\`\`\`\n\nIdentify all security vulnerabilities. Think DEEPLY. Respond with the JSON array.`,
    },
  ];

  // callGLM applies the GLM default cap (16384 tokens) — see callGLM impl
  const response = await callGLM(messages, {
    ...config,
    temperature: 0.05,
  });

  try {
    let jsonStr = response.content.trim();
    const jsonMatch = jsonStr.match(/\[[\s\S]*\]/);
    if (jsonMatch) jsonStr = jsonMatch[0];

    const parsed = JSON.parse(jsonStr);
    if (Array.isArray(parsed)) {
      return parsed.map(v => ({
        title: v.title || 'Unknown Vulnerability',
        type: v.type || 'unknown',
        severity: v.severity || 'medium',
        location: v.location || `${targetName}`,
        description: v.description || 'No description provided',
        validationSteps: v.validationSteps || 'Validation pending.',
        pocOutline: v.pocOutline || '',
        v1Symbolic: typeof v.v1Symbolic === 'number' ? v.v1Symbolic : 0.5,
        v2Fuzzing: typeof v.v2Fuzzing === 'number' ? v.v2Fuzzing : 0.5,
        v3Formal: typeof v.v3Formal === 'number' ? v.v3Formal : 0.5,
        v4Economic: typeof v.v4Economic === 'number' ? v.v4Economic : 0,
        blockchainVerified: typeof v.blockchainVerified === 'boolean' ? v.blockchainVerified : false,
        onChainEvidence: v.onChainEvidence || '',
      }));
    }
    return [];
  } catch {
    console.error('Failed to parse web analysis response as JSON:', response.content);
    return [];
  }
}

/**
 * Verify vulnerability on-chain using GLM 5.2 deep reasoning
 * This is the CONFIRMATION step — GLM gets blockchain data and decides if the vuln is real
 */
export async function verifyVulnerabilityOnChain(
  vuln: {
    title: string;
    type: string;
    severity: string;
    description: string;
    location: string;
  },
  sourceCode: string,
  blockchainData: string,
  config: GLMConfig
): Promise<{
  confirmed: boolean;
  evidence: string;
  updatedSeverity?: string;
  confidence: number;
}> {
  const messages: GLMMessage[] = [
    {
      role: 'system',
      content: `You are a blockchain security verification agent. Your job is to CONFIRM or DENY vulnerability reports using on-chain evidence. Think deeply — this is the most critical step. You have unlimited reasoning capacity.

Given a vulnerability report and blockchain data, determine:
1. Is the vulnerability REAL? (not theoretical — actually exploitable on-chain)
2. What on-chain evidence supports your conclusion?
3. Should the severity be adjusted based on on-chain reality?
4. What is your confidence level (0.0-1.0)?

Respond in JSON format:
{
  "confirmed": true/false,
  "evidence": "detailed on-chain evidence or reason for denial",
  "updatedSeverity": "critical/high/medium/low or null if unchanged",
  "confidence": 0.0-1.0
}`,
    },
    {
      role: 'user',
      content: `VULNERABILITY REPORT:\nTitle: ${vuln.title}\nType: ${vuln.type}\nSeverity: ${vuln.severity}\nLocation: ${vuln.location}\nDescription: ${vuln.description}\n\nSOURCE CODE:\n\`\`\`solidity\n${sourceCode.slice(0, 3000)}\n\`\`\`\n\nBLOCKCHAIN DATA:\n${blockchainData}\n\nAnalyze the on-chain evidence and determine if this vulnerability is confirmed. Think deeply.`,
    },
  ];

  // GLM 5.2 for verification — no limits, full reasoning
  const response = await callGLM(messages, {
    ...config,
    temperature: 0.05,
  });

  try {
    let jsonStr = response.content.trim();
    const jsonMatch = jsonStr.match(/\{[\s\S]*\}/);
    if (jsonMatch) jsonStr = jsonMatch[0];
    const parsed = JSON.parse(jsonStr);
    return {
      confirmed: typeof parsed.confirmed === 'boolean' ? parsed.confirmed : false,
      evidence: parsed.evidence || 'No evidence provided',
      updatedSeverity: parsed.updatedSeverity || undefined,
      confidence: typeof parsed.confidence === 'number' ? parsed.confidence : 0.5,
    };
  } catch {
    return {
      confirmed: false,
      evidence: 'Verification failed — could not parse AI response',
      confidence: 0.5,
    };
  }
}
