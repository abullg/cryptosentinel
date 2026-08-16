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

  // VPS KVM 2 (Hostinger, 8GB RAM) — no serverless timeout limits, BUT
  // GLM 5.2 with unlimited reasoning can enter infinite loops. Cap at
  // 120s (2 min) — this is enough for deep analysis of even large
  // codebases; if it takes longer, the model is stuck in a reasoning
  // loop and should be aborted.
  // 5 min timeout (previous setting) caused the '40 min hang' — each
  // retry waited 5 min, and with multiple findings × retries it stacked.
  const callTimeout = config.timeoutMs || 120_000; // 2 min
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

CRITICAL EVIDENCE RULES (READ CAREFULLY — VIOLATING THESE INVALIDATES THE REPORT):

You MUST distinguish three strictly different evidence tiers. Mixing them is the #1 quality failure mode.

**TIER 1 — Confirmed configuration weakness / code smell (OBSERVATION only):**
  Something is technically missing or non-ideal in the code, observable via static review, but you have NOT constructed a concrete exploit.
  Examples: missing zero-check on a parameter, use of tx.origin, use of block.timestamp for randomness, missing event emission on a state change, missing timelock on admin functions.
  These are NOT vulnerabilities by themselves. They are weaknesses that COULD become exploitable under specific conditions you have not yet demonstrated.
  → Severity: LOW at most, unless paired with a Tier 2 finding.
  → Title format: "Missing zero-check on <param>" / "Use of tx.origin in <function>" — NOT "Use of tx.origin enables auth bypass".
  → Description format: "Observation: line N of <file> uses tx.origin for authorization. No concrete auth-bypass chain demonstrated — this is a defense-in-depth weakness."
  → Do NOT speculate about exploit chains in the description. Save that for the validationSteps field.

**TIER 2 — Confirmed vulnerability (PROVEN exploit chain):**
  You have demonstrated a complete chain: a SOURCE where attacker-controlled data enters (msg.sender, function param, external call, oracle data), a DATAFLOW that propagates it without sufficient sanitization, and a SINK where it causes harm (external call, state write, transfer). All three must be concrete, not hypothetical.
  Examples: reentrancy with a proven external call before state update, access control bypass with a proven attacker address calling a privileged function, integer overflow with concrete parameter values that trigger it.
  → Severity: matches the actual financial impact of the proven chain (MEDIUM/HIGH/CRITICAL per HackenProof tiers above).
  → Title format: "Reentrancy in <function> via <external call>" / "Access control bypass on <function>".
  → Description format: "SOURCE: <concrete input>. DATAFLOW: <trace through code, line by line>. SINK: <concrete dangerous operation>. SANITIZER: <none found, or name and why insufficient>. EXPLOIT: <concrete attack scenario with function calls, params, state transitions>. IMPACT: <quantified financial/systemic impact>."

**TIER 3 — Confirmed high-impact chain (PROVEN vuln + amplifying factor):**
  A Tier 2 vulnerability combined with a Tier 1 weakness or external condition that materially amplifies its impact.
  Example: proven reentrancy (Tier 2) + missing nonReentrant modifier elsewhere in flow (Tier 1) + flash-loan available to amplify capital (external condition) → critical fund-drain chain.
  → Severity: HIGH or CRITICAL — but ONLY when both halves are proven.
  → You MUST cite the Tier 2 finding by title and the Tier 1 finding by title.

**FORBIDDEN LOGICAL LEAPS (these will cause your output to be rejected):**

1. You may NOT turn a Tier 1 observation into a Tier 2 vulnerability.
   - BAD: "Use of tx.origin → auth bypass possible → fund theft" (conflates tiers).
   - GOOD: "Use of tx.origin in transfer() (Tier 1, LOW)" as a separate finding. If you also have a proven auth-bypass chain, add a SEPARATE Tier 3 finding that cites both.

2. You may NOT use the words "possible", "could", "may", "might", "if attacked", "potentially" inside a Tier 2 or Tier 3 description.
   - If you find yourself writing "an attacker could call...", you have NOT proven the chain. Downgrade to Tier 1 or omit the finding entirely (per the OUT OF SCOPE rule below).

3. You may NOT claim a dataflow exists just because a pattern is "common" or "typical" in DeFi contracts.
   - BAD: "Flash loans commonly manipulate AMM price oracles → price manipulation possible"
   - GOOD: "Line N of getReserves() reads spot price from Uniswap V2 pair. Line N+10 of borrow() uses this price without TWAP. Attacker can flash-borrow 90% of pool, manipulate spot price by 35%, borrow 42% over collateralization, repay with profit. Concrete exploit attached."

4. You may NOT claim "ACTIVE VALIDATION PASSED" or "On-chain evidence CONFIRMS" unless blockchain data actually validates the SPECIFIC claim.
   - "Contract deployed at 0x... CONFIRMED" does NOT confirm a reentrancy exists.
   - Match the evidence to the claim precisely.

5. Severity MUST match the evidence tier:
   - Tier 1 alone → LOW
   - Tier 2 proven but limited impact (e.g. griefing without profit) → MEDIUM
   - Tier 2 proven with fund-theft impact → HIGH or CRITICAL
   - Tier 3 (Tier 2 + amplifying Tier 1 + economic viability) → CRITICAL

6. You may NOT make absolutist claims about impact amplification.
   - FORBIDDEN: "any tx.origin use makes the contract critical" (false — depends on whether tx.origin is actually used for authorization on a privileged function).
   - CORRECT phrasing: "use of tx.origin for authorization on a privileged function MAY allow auth bypass IF an attacker can trick a privileged user into calling the attacker's contract; the actual exploitability depends on whether such a path exists."
   - When discussing a Tier 1 weakness that COULD amplify a Tier 2, always qualify with the specific conditions required.

7. You may NOT use the word "CONFIRMED" unless the validation scope is 'target'.
   - "LAB-VALIDATED" means the exploit chain works in a local Foundry EVM. This proves technical viability ONLY, not that the deployed contract is exploitable (bytecode may differ, admin controls may exist on-chain, state may differ).
   - "TARGET-VALIDATED" means the exploit was verified against the actual deployed contract (e.g. via a real on-chain call against the production address).
   - "THEORETICAL" means no runtime validation was performed — static analysis / AI reasoning only.
   - Use the matching label exactly. Never write "[ACTIVE VALIDATION PASSED]" or "Exploit succeeded on local EVM" without the LAB-VALIDATED qualifier — those phrases imply target-level confirmation.

**STYLE:**
- Use precise, technical language. State exactly what you observed and exactly what you did NOT observe.
- Hedging is REQUIRED when the evidence is incomplete. "Likely", "probable", "appears to" are correct language when you have not proven the chain.
- Do NOT use marketing words ("devastating", "severe" as adjectives — only use the severity enum value).

IMPORTANT — REPORTING DISCIPLINE:
- If you are NOT certain a vulnerability exists OR cannot construct a concrete exploit, DO NOT report it as Tier 2 or Tier 3.
- Either downgrade it to Tier 1 (with LOW severity) or omit it entirely (per the OUT OF SCOPE rule above).
- It is BETTER to report 2 confirmed Tier 2 findings than 10 speculative ones.
- A small number of high-confidence findings is FAR more valuable than a large number of speculative ones.

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

CRITICAL EVIDENCE RULES:
- Match language strength to actual evidence strength.
- If the vulnerability was already proven (concrete source → dataflow → sink → exploit), use definitive language: "IS", "HAS", "CAUSES", "LEADS TO", "ALLOWS".
- If the vulnerability is an OBSERVATION only (a missing check, a code smell, a configuration weakness), use observational language: "is missing", "does not include", "uses X pattern" — and DO NOT speculate about exploit chains in the description.
- FORBIDDEN: turning a configuration observation into a confirmed exploit chain. "Missing CSP header" is an observation; it does NOT become "XSS execution possible → wallet hijack" unless you have separately proven an XSS dataflow.
- Use "may", "could", "appears to" only when the evidence is genuinely incomplete — and if so, downgrade the finding rather than elevating its impact language.`,
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

CRITICAL EVIDENCE RULES (READ CAREFULLY — VIOLATING THESE INVALIDATES THE REPORT):

You MUST distinguish three strictly different evidence tiers. Mixing them is the #1 quality failure mode.

**TIER 1 — Confirmed configuration weakness (OBSERVATION only):**
  Something is technically missing or misconfigured, observable via direct HTTP request, header inspection, or static code review.
  Examples: missing CSP header, missing HSTS, missing X-Frame-Options, missing rate limiting on a public endpoint, presence of inline scripts.
  These are NOT vulnerabilities by themselves. They are weaknesses that COULD amplify the impact of an actual vulnerability.
  → Severity: LOW at most, unless paired with a Tier 2 finding.
  → Title format: "Missing X header" / "Y not configured" — NOT "Missing X enables Z".
  → Description format: "HTTP response from <url> does not contain X header. Confirmed via direct request. This is a defense-in-depth weakness; it does not by itself constitute an exploit."
  → Do NOT speculate about exploit chains in the description. Save that for the validationSteps field.

**TIER 2 — Confirmed vulnerability (PROVEN exploit chain):**
  You have demonstrated a complete chain: a SOURCE where attacker-controlled data enters, a DATAFLOW that propagates it without sanitization, and a SINK where it executes. All three must be concrete, not hypothetical.
  Examples: reflected XSS with a proven ?param= to innerHTML dataflow, SQL injection with a proven ' OR 1=1 payload, IDOR with a proven userId=N parameter that returns another user's data.
  → Severity: matches the actual impact of the proven chain (MEDIUM/HIGH/CRITICAL).
  → Title format: "Reflected XSS via <param> in <function>" / "SQL injection in <query>".
  → Description format: "SOURCE: <concrete input>. DATAFLOW: <trace through code>. SINK: <concrete dangerous operation>. SANITIZER: <none found, or name>. EXPLOIT: <working payload or URL>. IMPACT: <what attacker achieves>."

**TIER 3 — Confirmed high-impact chain (PROVEN vuln + amplifying factor):**
  A Tier 2 vulnerability combined with a Tier 1 weakness that materially amplifies its impact.
  Example: proven reflected XSS (Tier 2) + missing CSP (Tier 1) + Web3 wallet integration detected on the page → high-impact chain (XSS can hijack wallet connections because no CSP blocks inline script execution).
  → Severity: HIGH or CRITICAL — but ONLY when both halves are proven.
  → You MUST cite the Tier 2 finding by title and the Tier 1 finding by title.

**FORBIDDEN LOGICAL LEAPS (these will cause your output to be rejected):**

1. You may NOT turn a Tier 1 observation into a Tier 2 vulnerability.
   - BAD: "Missing CSP → XSS execution possible → wallet hijack" (this conflates tiers).
   - GOOD: "Missing CSP header (Tier 1, LOW)" as a separate finding. If you also have a proven XSS, add a SEPARATE Tier 3 finding that cites both.

2. You may NOT use the words "possible", "could", "may", "might", "if attacked", "potentially" inside a Tier 2 or Tier 3 description.
   - If you find yourself writing "an attacker could inject...", you have NOT proven the chain. Downgrade to Tier 1 or remove the finding.

3. You may NOT claim a dataflow exists just because an API pattern is common in the codebase.
   - BAD: "innerHTML, document.write, eval patterns common in Nuxt/Vite bundles → untrusted input reaches these sinks"
   - GOOD: "Line 47 of login.js: document.getElementById('username').innerHTML = req.query.name — proven dataflow from ?name= to innerHTML sink, no sanitization."

4. You may NOT claim "ACTIVE VALIDATION PASSED" or "On-chain evidence CONFIRMS" unless you have actually validated the specific claim.
   - "CSP MISSING CONFIRMED" validates only that CSP is missing — it does NOT validate that XSS is exploitable.
   - Do not append "[ACTIVE VALIDATION PASSED]" to a Tier 1 finding to make it sound like Tier 2.

5. Severity MUST match the evidence tier:
   - Tier 1 alone → LOW
   - Tier 2 proven but limited impact (e.g. reflected XSS on a non-sensitive page) → MEDIUM
   - Tier 2 proven with sensitive impact (e.g. stored XSS, SQL injection) → HIGH
   - Tier 3 (Tier 2 + amplifying Tier 1 + sensitive context like wallet integration) → HIGH or CRITICAL

6. You may NOT make absolutist claims about impact amplification.
   - FORBIDDEN: "transforms any low-severity XSS into a critical, high-impact exploit" (this is false — an XSS with limited context, e.g. a 30-char reflected param on a marketing page, may stay LOW even without CSP).
   - FORBIDDEN: "exponentially increases the damage of XSS".
   - CORRECT phrasing: "absence of CSP removes a defense-in-depth layer that could have constrained script execution; the actual impact amplification depends on the specific XSS context, the data accessible to the script, and the presence of other mitigations."
   - When discussing a Tier 1 weakness that COULD amplify a Tier 2, always qualify: "may increase impact IF a Tier 2 vulnerability exists in the same context, and IF that context provides access to sensitive assets."

7. You may NOT make absolutist claims about browser behavior.
   - FORBIDDEN: "browser has no restriction on which scripts may execute" (false — Same-Origin Policy, CORS, cookie attributes, X-Frame-Options all still apply).
   - FORBIDDEN: "all scripts execute with full page privileges" without qualification.
   - CORRECT phrasing: "CSP does not add an additional restriction on script sources or inline execution; SOP, CORS, and cookie attribute protections remain in effect."

8. You may NOT use the word "CONFIRMED" unless the validation scope is 'target'.
   - "LAB-VALIDATED" means the exploit chain works in a local controlled environment (e.g. local Foundry EVM, local HTTP mock). This proves technical viability ONLY, not production exploitability.
   - "TARGET-VALIDATED" means a real request was sent to the production target and the payload was reflected/executed in the response.
   - "THEORETICAL" means no runtime validation was performed.
   - When describing a finding, use the matching label exactly. Never write "[ACTIVE VALIDATION PASSED]" — use the specific scope label instead.

**STYLE:**
- Use precise, technical language. Avoid marketing words ("devastating", "critical", "severe" as adjectives — only use them as the severity enum value).
- State exactly what you observed and exactly what you did NOT observe.
- If you cannot complete a Tier 2 chain, say so explicitly: "Source and sink identified, but no proven dataflow between them — downgrade to Tier 1 observation."
- Hedging is REQUIRED when the evidence is incomplete. "Likely", "probable", "appears to" are correct language when you have not proven the chain.

Focus on real, exploitable vulnerabilities. A small number of high-confidence findings is FAR more valuable than a large number of speculative ones. If you only find 1-2 truly confirmed vulnerabilities, that is a successful analysis.

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
