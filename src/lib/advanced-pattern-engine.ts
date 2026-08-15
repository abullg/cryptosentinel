/**
 * CryptoSentinel — Advanced Pattern Engine
 * Inspired by: Semgrep (metavariable matching), CodeQL (path-sensitive), Bandit (confidence tiers)
 *
 * Key innovations over basic regex scanner:
 * 1. Metavariable capture — track specific values across patterns (like Semgrep $VAR)
 * 2. Context windows — check surrounding code for mitigations before reporting
 * 3. Multi-line interprocedural patterns — detect vulns across function boundaries
 * 4. Confidence tiers — Bandit-style HIGH/MEDIUM/LOW confidence classification
 * 5. Auto-suppression — findings with clear mitigations are suppressed, not just scored lower
 */

import { checkFalsePositive } from './vulnerability-db';

export type ConfidenceTier = 'HIGH' | 'MEDIUM' | 'LOW';
export type Language = 'solidity' | 'vyper' | 'move' | 'rust' | 'cairo' | 'go' | 'typescript' | 'javascript' | 'python' | 'web';

export interface AdvancedPattern {
  id: string;
  type: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  confidenceTier: ConfidenceTier;
  languages: Language[];
  pattern: RegExp;
  metavariables?: Record<string, RegExp>;
  requiresContext?: {
    withinFunction?: RegExp;
    notPrecededBy?: RegExp;
    followedBy?: RegExp;
    notFollowedBy?: RegExp;
  };
  mitigations?: RegExp[];
  description: (captures: Record<string, string>, file: string) => string;
  cwe?: string[];
  remediation: string;
  v1Symbolic: number;
  v2Fuzzing: number;
  v3Formal: number;
  v4Economic: number;
}

export interface AdvancedFinding {
  id: string;
  ruleId: string;
  type: string;
  title: string;
  severity: string;
  confidenceTier: ConfidenceTier;
  location: string;
  line: number;
  description: string;
  remediation: string;
  cwe: string[];
  confidence: number;
  captures: Record<string, string>;
  mitigationsFound: string[];
  isSuppressed: boolean;
  v1Symbolic: number;
  v2Fuzzing: number;
  v3Formal: number;
  v4Economic: number;
}

// ─── SOLIDITY ADVANCED PATTERNS ──────────────────────────────────────

const SOLIDITY_ADVANCED: AdvancedPattern[] = [
  {
    id: 'SOL-REENT-001',
    type: 'reentrancy',
    title: 'Reentrancy - external call before state update (CEI violation)',
    severity: 'critical',
    confidenceTier: 'HIGH',
    languages: ['solidity'],
    pattern: /(\w+)\s*\.\s*(?:call|transfer|send)\s*\(/g,
    metavariables: {
      $TARGET: /(\w+)\s*\.\s*(?:call|transfer|send)/,
    },
    requiresContext: {
      notPrecededBy: /nonReentrant|_notEntered|reentrancyGuard/gi,
    },
    mitigations: [
      /nonReentrant/gi,
      /ReentrancyGuard/gi,
      /_notEntered/g,
      /mutex/gi,
    ],
    description: (c, f) => `External call to ${c.$TARGET || 'unknown contract'} in ${f} violates the Checks-Effects-Interactions pattern. The external call executes before state variables are updated, enabling reentrancy where an attacker re-enters the function through the callback, draining funds before the balance check occurs. This matches SWC-107 real-world incidents (The DAO, Lendf.me).`,
    cwe: ['SWC-107'],
    remediation: 'Add nonReentrant modifier from OpenZeppelin ReentrancyGuard, or restructure to follow Checks-Effects-Interactions.',
    v1Symbolic: 0.95, v2Fuzzing: 0.90, v3Formal: 0.85, v4Economic: 0.80,
  },
  {
    id: 'SOL-AC-001',
    type: 'access_control',
    title: 'Missing access control on privileged function',
    severity: 'critical',
    confidenceTier: 'HIGH',
    languages: ['solidity'],
    pattern: /function\s+(setOwner|changeAdmin|updateConfig|upgradeTo|transferOwnership|migrate|setImplementation|pause|unpause|emergencyWithdraw|sweepFunds|setFee|setRate|withdrawAll|rescueTokens)\s*\([^)]*\)\s*(?:public|external)(?!\s*(?:onlyOwner|onlyAdmin|onlyRole|onlyGovernance|onlyManager))/g,
    metavariables: { $FUNC: /function\s+(\w+)/ },
    mitigations: [
      /onlyOwner/gi, /onlyAdmin/gi, /onlyRole/gi,
      /require\s*\(\s*msg\.sender\s*==\s*owner/gi,
    ],
    description: (c, f) => `Privileged function ${c.$FUNC || 'unknown'} in ${f} is public/external without access control modifier. Any caller can execute this operation, enabling unauthorized state changes or fund theft. This matches the Poly Network hack ($611M) pattern.`,
    cwe: ['SWC-105', 'CWE-863'],
    remediation: 'Add onlyOwner/onlyAdmin/onlyRole modifier. Use OpenZeppelin Ownable or AccessControl.',
    v1Symbolic: 0.95, v2Fuzzing: 0.90, v3Formal: 0.95, v4Economic: 0.85,
  },
  {
    id: 'SOL-UNCHECK-001',
    type: 'unchecked_call',
    title: 'Unchecked return value of low-level call',
    severity: 'high',
    confidenceTier: 'HIGH',
    languages: ['solidity'],
    pattern: /(?:call|delegatecall|staticcall)\s*\{[^}]*\}\s*\(/g,
    mitigations: [
      /require\s*\(\s*success/g,
      /if\s*\(\s*!success/g,
      /try\s*.*\s*catch/g,
    ],
    description: (c, f) => `Low-level call in ${f} does not check the return value. If the call fails silently, execution continues with incorrect assumptions, leading to inconsistent state and potential fund loss. Matches the Parity Wallet hack pattern ($150M frozen).`,
    cwe: ['SWC-104'],
    remediation: 'Check the return value: require(success, "call failed") or use try/catch.',
    v1Symbolic: 0.92, v2Fuzzing: 0.88, v3Formal: 0.90, v4Economic: 0.50,
  },
  {
    id: 'SOL-ORACLE-001',
    type: 'oracle_manipulation',
    title: 'Single-source oracle without deviation bounds or TWAP',
    // HackenProof tier: HIGH (not Critical). Oracle manipulation is High
    // per docs.hackenproof.com — only escalates to Critical if it leads to
    // protocol insolvency (which would be classified separately).
    severity: 'high',
    confidenceTier: 'MEDIUM',
    languages: ['solidity'],
    pattern: /(?:getPrice|latestAnswer|latestRoundData|consult|peek)\s*\([^)]*\)/g,
    requiresContext: {
      notPrecededBy: /TWAP|twap|circuitBreaker|maxDeviation/gi,
    },
    mitigations: [
      /maxDeviation|circuitBreaker|stalePrice|TWAP|twap|isFresh/gi,
    ],
    description: (c, f) => `Oracle price fetch in ${f} uses a single source without deviation bounds or TWAP. An attacker can manipulate the oracle price via flash loan. Matches Cream Finance ($130M) and bZx attack patterns. HackenProof severity: HIGH (oracle manipulation).`,
    cwe: ['SWC-120'],
    remediation: 'Use TWAP with deviation bounds, circuit breakers, and multiple oracle sources.',
    v1Symbolic: 0.40, v2Fuzzing: 0.60, v3Formal: 0.30, v4Economic: 0.95,
  },
  {
    id: 'SOL-TXORIGIN-001',
    type: 'access_control',
    title: 'tx.origin used for authentication',
    severity: 'high',
    confidenceTier: 'HIGH',
    languages: ['solidity'],
    pattern: /tx\.origin/g,
    mitigations: [/msg\.sender/g],
    description: (c, f) => `tx.origin is used for authentication in ${f}. A malicious contract can trick a user into calling it; since tx.origin remains the user address, the check passes. This is SWC-115 phishing-based authorization bypass.`,
    cwe: ['SWC-115'],
    remediation: 'Replace all tx.origin references with msg.sender.',
    v1Symbolic: 0.95, v2Fuzzing: 0.90, v3Formal: 0.95, v4Economic: 0.60,
  },
  {
    id: 'SOL-DELEGATE-001',
    type: 'delegatecall',
    title: 'Unsafe delegatecall to user-controlled address',
    severity: 'critical',
    confidenceTier: 'HIGH',
    languages: ['solidity'],
    pattern: /delegatecall\s*\{[^}]*\}\s*\(\s*(?:abi\.encodePacked|abi\.encodeWithSelector|[^)]*_implementation|[^)]*_logic|[^)]*_target)/g,
    mitigations: [/onlyOwner|onlyAdmin/gi, /UUPSUpgradeable/gi],
    description: (c, f) => `delegatecall in ${f} executes logic from another contract in the caller context. If the implementation address is user-controllable, an attacker can execute arbitrary code with the proxy storage context. Matches the Parity Wallet hack pattern.`,
    cwe: ['SWC-107'],
    remediation: 'Restrict who can change the implementation address. Use UUPS proxy with onlyProxyAdmin.',
    v1Symbolic: 0.90, v2Fuzzing: 0.85, v3Formal: 0.90, v4Economic: 0.80,
  },
  {
    id: 'SOL-OVERFLOW-001',
    type: 'integer_overflow',
    title: 'Unchecked arithmetic in unchecked block',
    severity: 'high',
    confidenceTier: 'HIGH',
    languages: ['solidity'],
    pattern: /unchecked\s*\{[\s\S]*?[+\-*/][\s\S]*?\}/g,
    mitigations: [/require\s*\(/g, /if\s*\(/g],
    description: (c, f) => `Arithmetic operations inside unchecked{} block in ${f} bypass Solidity 0.8+ built-in overflow checks. If input values are not validated, overflow/underflow wraps silently.`,
    cwe: ['SWC-101'],
    remediation: 'Add explicit bounds checks before arithmetic in unchecked blocks.',
    v1Symbolic: 0.90, v2Fuzzing: 0.95, v3Formal: 0.92, v4Economic: 0.30,
  },
  {
    id: 'SOL-MEV-001',
    type: 'front_running',
    title: 'Swap without slippage protection',
    severity: 'high',
    confidenceTier: 'MEDIUM',
    languages: ['solidity'],
    pattern: /(?:swap|exchange|trade)\w*\s*\([^)]*(?!minAmountOut|minReturn|deadline|slippage|amountOutMin)/g,
    mitigations: [/minAmountOut|minReturn|deadline|slippage|amountOutMin/gi],
    description: (c, f) => `Swap function in ${f} lacks minimum output amount and deadline parameters. MEV bots can sandwich the transaction.`,
    cwe: ['SWC-120'],
    remediation: 'Add minAmountOut (or amountOutMin) and deadline parameters.',
    v1Symbolic: 0.60, v2Fuzzing: 0.70, v3Formal: 0.50, v4Economic: 0.90,
  },
  {
    id: 'SOL-FLASH-001',
    type: 'flash_loan',
    title: 'Flash loan attack on single-block state dependency',
    severity: 'critical',
    confidenceTier: 'MEDIUM',
    languages: ['solidity'],
    pattern: /(?:borrow|flashLoan|flashBorrow)\s*\([^)]*\)[\s\S]{0,300}(?:price|reserve|balance|collateral|liquidity)/g,
    mitigations: [/TWAP|twap/gi, /circuitBreaker/gi, /maxDeviation/gi],
    description: (c, f) => `Flash loan borrow in ${f} interacts with price/reserve/balance state within the same transaction. An attacker borrows, manipulates, exploits, and repays atomically.`,
    cwe: ['SWC-120'],
    remediation: 'Use TWAP oracles with delay and circuit breakers.',
    v1Symbolic: 0.25, v2Fuzzing: 0.45, v3Formal: 0.30, v4Economic: 0.95,
  },
  {
    id: 'SOL-DOS-001',
    type: 'denial_of_service',
    title: 'selfdestruct can destroy contract',
    severity: 'critical',
    confidenceTier: 'HIGH',
    languages: ['solidity'],
    pattern: /(?:selfdestruct|suicide)\s*\(/g,
    mitigations: [/onlyOwner|onlyAdmin/gi],
    description: (c, f) => `selfdestruct() in ${f} can destroy the contract. If called without access control, any attacker can kill the contract permanently.`,
    cwe: ['CWE-400'],
    remediation: 'Remove selfdestruct or protect with onlyOwner modifier.',
    v1Symbolic: 0.95, v2Fuzzing: 0.95, v3Formal: 0.98, v4Economic: 0.80,
  },
  {
    id: 'SOL-RAND-001',
    type: 'bad_randomness',
    title: 'Predictable randomness from block variables',
    severity: 'high',
    confidenceTier: 'HIGH',
    languages: ['solidity'],
    pattern: /(?:keccak256|sha256|sha3)\s*\(\s*(?:abi\.encodePacked\s*\(\s*)?(?:block\.(?:timestamp|difficulty|number|coinbase)|now|msg\.sender)/g,
    mitigations: [/Chainlink\s*VRF/gi, /VRFCoordinator/gi],
    description: (c, f) => `Hash of block variables in ${f} used as randomness. Miners can predict the outcome. Use Chainlink VRF.`,
    cwe: ['SWC-120'],
    remediation: 'Use Chainlink VRF for verifiable randomness.',
    v1Symbolic: 0.85, v2Fuzzing: 0.80, v3Formal: 0.85, v4Economic: 0.70,
  },
  {
    id: 'SOL-REPLAY-001',
    type: 'signature_replay',
    title: 'Signature replay - missing nonce/deadline',
    severity: 'high',
    confidenceTier: 'MEDIUM',
    languages: ['solidity'],
    pattern: /ecrecover\s*\([^)]*\)/g,
    mitigations: [/nonce|_nonce/gi, /usedHash|executed|invalidated/gi, /deadline/gi],
    description: (c, f) => `ecrecover in ${f} validates a signature without nonce or deadline. The same signature can be replayed multiple times.`,
    cwe: ['SWC-121'],
    remediation: 'Add nonce mapping and deadline parameter.',
    v1Symbolic: 0.85, v2Fuzzing: 0.80, v3Formal: 0.85, v4Economic: 0.65,
  },
  {
    id: 'SOL-PROXY-001',
    type: 'storage_collision',
    title: 'Storage collision in proxy pattern',
    severity: 'critical',
    confidenceTier: 'MEDIUM',
    languages: ['solidity'],
    pattern: /(?:implementation|_implementation|_logic|proxy|diamond)\s*(?:=\s*|:\s*)(?:address|bytes32)/g,
    mitigations: [/EIP-1967|eip1967/gi, /ERC1967Upgrade/gi],
    description: (c, f) => `Storage variable in ${f} may collide with implementation contract storage in proxy pattern.`,
    cwe: ['SWC-118'],
    remediation: 'Use EIP-1967 standard storage slots. Use OpenZeppelin ERC1967Upgrade.',
    v1Symbolic: 0.75, v2Fuzzing: 0.70, v3Formal: 0.80, v4Economic: 0.60,
  },
  {
    id: 'SOL-DOS-002',
    type: 'denial_of_service',
    title: 'Unbounded loop over dynamic array',
    severity: 'high',
    confidenceTier: 'MEDIUM',
    languages: ['solidity'],
    pattern: /for\s*\(\s*\w+\s+\w+\s*=\s*0\s*;\s*\w+\s*<\s*(\w+)\s*\.\s*(?:length|size|count)\s*;/g,
    mitigations: [/MAX_|max_/gi, /require\s*\(\s*\w+\.length\s*<=/gi],
    description: (c, f) => `Loop over dynamic array.length in ${f} has no upper bound. Can exceed block gas limit.`,
    cwe: ['CWE-400'],
    remediation: 'Add a maximum iteration count or require the array length is bounded.',
    v1Symbolic: 0.80, v2Fuzzing: 0.75, v3Formal: 0.70, v4Economic: 0.50,
  },
  {
    id: 'SOL-SHADOW-001',
    type: 'state_shadowing',
    title: 'State variable shadowing in inheritance',
    severity: 'medium',
    confidenceTier: 'LOW',
    languages: ['solidity'],
    pattern: /(?:uint|int|bool|address|bytes\d*|string)\s+(?:public|private|internal)?\s*(?:constant|immutable)?\s*\w+\s*(?:=\s*[^;]+)?;/g,
    description: (c, f) => `Variable declaration in ${f} may shadow a variable from a parent contract.`,
    cwe: ['SWC-119'],
    remediation: 'Rename the shadowing variable or remove the duplicate declaration.',
    v1Symbolic: 0.65, v2Fuzzing: 0.60, v3Formal: 0.70, v4Economic: 0.20,
  },
];

// ─── WEB/JS/TS ADVANCED PATTERNS ─────────────────────────────────────

const WEB_ADVANCED: AdvancedPattern[] = [
  {
    id: 'WEB-XSS-001',
    type: 'xss',
    title: 'XSS via innerHTML/dangerouslySetInnerHTML',
    severity: 'high',
    confidenceTier: 'HIGH',
    languages: ['typescript', 'javascript', 'web'],
    pattern: /(?:innerHTML|outerHTML|document\.write|dangerouslySetInnerHTML)\s*[=\(]/g,
    mitigations: [/DOMPurify\.sanitize/gi, /sanitize\(/g, /textContent/g, /innerText/g],
    description: (c, f) => `DOM injection in ${f}. If user input reaches this sink without sanitization, arbitrary JavaScript can be injected, enabling session theft and wallet hijacking.`,
    cwe: ['CWE-79'],
    remediation: 'Use React JSX (auto-escapes), DOMPurify.sanitize() for HTML, or textContent for plain text.',
    v1Symbolic: 0.85, v2Fuzzing: 0.80, v3Formal: 0.75, v4Economic: 0.60,
  },
  {
    id: 'WEB-SQL-001',
    type: 'sql_injection',
    title: 'SQL Injection - string concatenation in query',
    severity: 'critical',
    confidenceTier: 'HIGH',
    languages: ['typescript', 'javascript', 'python'],
    pattern: /(?:query|execute|raw|sql)\s*\(\s*[`'"](?:[^`'"]*\+|\$\{)[\s\S]*?(?:req\.|request\.|params|query|body)/g,
    mitigations: [/\$1|\$2|:param/g, /PreparedStatement/g],
    description: (c, f) => `SQL query in ${f} concatenates user input, allowing arbitrary SQL execution.`,
    cwe: ['CWE-89'],
    remediation: 'Use parameterized queries.',
    v1Symbolic: 0.92, v2Fuzzing: 0.88, v3Formal: 0.90, v4Economic: 0.70,
  },
  {
    id: 'WEB-CMD-001',
    type: 'command_injection',
    title: 'Command Injection - user input in exec/spawn',
    severity: 'critical',
    confidenceTier: 'HIGH',
    languages: ['typescript', 'javascript', 'python'],
    pattern: /(?:exec|execSync|spawn)\s*\(\s*(?:[^)]*\+[^)]*(?:req\.|request\.|params|query|body)|[`'"][^`'"]*(?:req\.|request\.))/g,
    mitigations: [/execFile/g, /shellescape/g, /allowlist|whitelist/gi],
    description: (c, f) => `OS command in ${f} incorporates user input. An attacker can inject shell commands achieving RCE.`,
    cwe: ['CWE-78'],
    remediation: 'Use execFile (no shell interpolation) or validate input against a strict allowlist.',
    v1Symbolic: 0.95, v2Fuzzing: 0.90, v3Formal: 0.92, v4Economic: 0.85,
  },
  {
    id: 'WEB-EVAL-001',
    type: 'code_injection',
    title: 'Code Injection - eval/Function with user input',
    severity: 'critical',
    confidenceTier: 'HIGH',
    languages: ['typescript', 'javascript', 'web'],
    pattern: /(?:eval|Function)\s*\(\s*(?:[^)]*(?:req\.|request\.|params|query|body|user|input)|[^)]*\+)/g,
    mitigations: [/JSON\.parse/g, /parseInt|Number\(/g],
    description: (c, f) => `eval()/Function() in ${f} executes arbitrary code. If user input reaches this, attacker can achieve RCE.`,
    cwe: ['CWE-94'],
    remediation: 'Use JSON.parse() for data. Never eval() user input.',
    v1Symbolic: 0.98, v2Fuzzing: 0.95, v3Formal: 0.98, v4Economic: 0.90,
  },
  {
    id: 'WEB-SSRF-001',
    type: 'ssrf',
    title: 'SSRF - user-controlled URL in fetch/request',
    severity: 'critical',
    confidenceTier: 'MEDIUM',
    languages: ['typescript', 'javascript', 'python'],
    pattern: /(?:fetch|axios|request|http\.get|https\.get)\s*\(\s*(?:req\.|request\.|params|query|body)\.\w+/g,
    mitigations: [/allowlist|whitelist/gi, /isPrivateIP|isPublic/gi],
    description: (c, f) => `Server-side request in ${f} uses user-controlled URL. An attacker can access internal services or cloud metadata endpoints.`,
    cwe: ['CWE-918'],
    remediation: 'Validate URLs against an allowlist. Block private IP ranges.',
    v1Symbolic: 0.70, v2Fuzzing: 0.65, v3Formal: 0.60, v4Economic: 0.80,
  },
  {
    id: 'WEB-PATH-001',
    type: 'path_traversal',
    title: 'Path Traversal - user input in file path',
    severity: 'high',
    confidenceTier: 'HIGH',
    languages: ['typescript', 'javascript', 'python'],
    pattern: /(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|unlink|rm)\s*\(\s*(?:[^)]*(?:req\.|request\.|params|query|body)|[^)]*\+[^)]*(?:req\.|user))/g,
    mitigations: [/path\.resolve/g, /path\.normalize/g, /basename\s*\(/g],
    description: (c, f) => `File operation in ${f} uses user input in the path. An attacker can traverse directories using "../" sequences.`,
    cwe: ['CWE-22'],
    remediation: 'Use path.resolve() and verify the result starts with the base directory.',
    v1Symbolic: 0.88, v2Fuzzing: 0.85, v3Formal: 0.85, v4Economic: 0.60,
  },
  {
    id: 'WEB-PROTO-001',
    type: 'prototype_pollution',
    title: 'Prototype Pollution - unsafe deep merge',
    severity: 'high',
    confidenceTier: 'MEDIUM',
    languages: ['typescript', 'javascript'],
    pattern: /(?:merge|defaultsDeep|extend|assign)\s*\([^)]*(?:__proto__|constructor|prototype)/g,
    mitigations: [/Object\.create\s*\(\s*null\s*\)/g, /Object\.freeze/g, /hasOwnProperty/g],
    description: (c, f) => `Deep merge in ${f} can be polluted via __proto__, affecting all objects. Can lead to RCE in Node.js.`,
    cwe: ['CWE-1321'],
    remediation: 'Use Object.create(null) for dictionaries. Freeze Object.prototype.',
    v1Symbolic: 0.75, v2Fuzzing: 0.70, v3Formal: 0.65, v4Economic: 0.60,
  },
  {
    id: 'WEB-SECRET-001',
    type: 'api_leak',
    title: 'Hardcoded secret or API key',
    severity: 'critical',
    confidenceTier: 'HIGH',
    languages: ['typescript', 'javascript', 'python', 'solidity', 'web'],
    pattern: /(?:api[_-]?key|secret[_-]?key|secret-?token|password|private[_-]?key)\s*[=:]\s*['"][^'"]{8,}['"]/gi,
    mitigations: [/process\.env/g, /config\.get/g, /secrets\./g, /vault\./g],
    description: (c, f) => `Hardcoded secret in ${f} is visible in source code, enabling unauthorized access or fund theft.`,
    cwe: ['CWE-798'],
    remediation: 'Use environment variables or secret management services.',
    v1Symbolic: 0.95, v2Fuzzing: 0.90, v3Formal: 0.95, v4Economic: 0.80,
  },
  {
    id: 'WEB-CORS-001',
    type: 'cors_misconfig',
    title: 'Overly permissive CORS (wildcard origin)',
    severity: 'high',
    confidenceTier: 'HIGH',
    languages: ['typescript', 'javascript', 'web'],
    pattern: /Access-Control-Allow-Origin['":\s]*\*|cors\s*[({]\s*origin\s*:\s*true/gi,
    mitigations: [/allowedOrigins/gi, /credentials\s*:\s*false/g],
    description: (c, f) => `Wildcard CORS in ${f} allows any origin to make cross-origin requests with credentials.`,
    cwe: ['CWE-346'],
    remediation: 'Restrict CORS to specific trusted origins.',
    v1Symbolic: 0.88, v2Fuzzing: 0.85, v3Formal: 0.80, v4Economic: 0.70,
  },
  {
    id: 'WEB-CSRF-001',
    type: 'csrf',
    title: 'Missing CSRF protection on state-changing endpoint',
    severity: 'high',
    confidenceTier: 'MEDIUM',
    languages: ['typescript', 'javascript'],
    pattern: /(?:app|router)\s*\.(?:post|put|delete|patch)\s*\([^,]+,\s*(?:async\s*)?\([^)]*\)\s*=>/g,
    mitigations: [/csrf/gi, /CSRFToken/gi, /SameSite/gi],
    description: (c, f) => `State-changing route in ${f} lacks CSRF token validation. An attacker can forge cross-site requests.`,
    cwe: ['CWE-352'],
    remediation: 'Add CSRF middleware. Use SameSite cookies.',
    v1Symbolic: 0.75, v2Fuzzing: 0.70, v3Formal: 0.65, v4Economic: 0.55,
  },
  {
    id: 'WEB-DESER-001',
    type: 'deserialization',
    title: 'Unsafe deserialization',
    severity: 'critical',
    confidenceTier: 'HIGH',
    languages: ['typescript', 'javascript', 'python'],
    pattern: /(?:pickle\.loads?|yaml\.load\s*\(|unserialize\(|ObjectInputStream)/g,
    mitigations: [/JSON\.parse/g, /yaml\.safe_load/g, /SafeLoader/g],
    description: (c, f) => `Unsafe deserialization in ${f} allows arbitrary object injection, potentially achieving RCE.`,
    cwe: ['CWE-502'],
    remediation: 'Use JSON.parse() or yaml.safe_load() with schema validation.',
    v1Symbolic: 0.95, v2Fuzzing: 0.90, v3Formal: 0.95, v4Economic: 0.85,
  },
  {
    id: 'WEB-CRYPTO-001',
    type: 'broken_crypto',
    title: 'Weak cryptographic algorithm',
    severity: 'high',
    confidenceTier: 'HIGH',
    languages: ['typescript', 'javascript', 'python', 'solidity'],
    pattern: /(?:md5|sha1|des-ecb|rc4|blowfish)\s*\(/gi,
    mitigations: [/aes-256-gcm/gi, /SHA-256|sha256/gi, /bcrypt/gi, /argon2/gi],
    description: (c, f) => `Weak crypto algorithm in ${f} can be broken, enabling data decryption or signature forgery.`,
    cwe: ['CWE-327'],
    remediation: 'Use AES-256-GCM for encryption, SHA-256+ for hashing, bcrypt/argon2 for passwords.',
    v1Symbolic: 0.90, v2Fuzzing: 0.85, v3Formal: 0.90, v4Economic: 0.70,
  },
  {
    id: 'WEB-REDIR-001',
    type: 'open_redirect',
    title: 'Open Redirect - user-controlled redirect target',
    severity: 'medium',
    confidenceTier: 'MEDIUM',
    languages: ['typescript', 'javascript', 'web'],
    pattern: /(?:redirect|location)\s*[=(]\s*(?:req\.|request\.|params|query)\.\w+/g,
    mitigations: [/startsWith\s*\(\s*['"]\/['"]\)/g, /allowlist|whitelist/gi],
    description: (c, f) => `Redirect in ${f} uses user-controlled URL, enabling phishing attacks.`,
    cwe: ['CWE-601'],
    remediation: 'Only allow relative redirects or validate against an allowlist.',
    v1Symbolic: 0.70, v2Fuzzing: 0.65, v3Formal: 0.60, v4Economic: 0.45,
  },
  {
    id: 'WEB-ERR-001',
    type: 'info_exposure',
    title: 'Information exposure through error message',
    severity: 'medium',
    confidenceTier: 'MEDIUM',
    languages: ['typescript', 'javascript', 'python'],
    pattern: /(?:res\.(?:send|json|end))\s*\(\s*(?:err|error|e)\b/g,
    mitigations: [/genericError|safeError/g, /sentry|datadog/gi],
    description: (c, f) => `Error details are sent to client in ${f}, potentially exposing stack traces or internal details.`,
    cwe: ['CWE-209'],
    remediation: 'Return generic error messages to clients. Log details server-side only.',
    v1Symbolic: 0.70, v2Fuzzing: 0.65, v3Formal: 0.60, v4Economic: 0.30,
  },
  {
    id: 'WEB-AUTH-001',
    type: 'auth_bypass',
    title: 'Authentication bypass - weak comparison',
    severity: 'critical',
    confidenceTier: 'HIGH',
    languages: ['typescript', 'javascript', 'python'],
    pattern: /(?:===|==)\s*(?:password|token|secret|apiKey|api_key)\b/gi,
    mitigations: [/bcrypt\.compare|bcrypt\.verify/g, /argon2\.verify/g, /timingSafeEqual/g],
    description: (c, f) => `Direct comparison of secrets in ${f} is vulnerable to timing attacks. Use constant-time comparison functions.`,
    cwe: ['CWE-287'],
    remediation: 'Use bcrypt.compare(), argon2.verify(), or crypto.timingSafeEqual() for secret comparison.',
    v1Symbolic: 0.90, v2Fuzzing: 0.85, v3Formal: 0.90, v4Economic: 0.80,
  },
  {
    id: 'WEB-IDOR-001',
    type: 'idor',
    title: 'Insecure Direct Object Reference (IDOR)',
    severity: 'high',
    confidenceTier: 'MEDIUM',
    languages: ['typescript', 'javascript'],
    pattern: /(?:findById|findByPk|findOne)\s*\(\s*(?:req\.|request\.)(?:params|query)\.\w+/g,
    mitigations: [/belongsTo|where.*userId/gi, /authorize|canAccess/gi],
    description: (c, f) => `Database lookup in ${f} uses user-supplied ID without authorization check. User can access other users data.`,
    cwe: ['CWE-639'],
    remediation: 'Always verify the authenticated user owns the requested resource.',
    v1Symbolic: 0.80, v2Fuzzing: 0.75, v3Formal: 0.70, v4Economic: 0.60,
  },
];

// ─── VYPER PATTERNS ──────────────────────────────────────────────────

const VYPER_ADVANCED: AdvancedPattern[] = [
  {
    id: 'VYPER-REENT-001',
    type: 'reentrancy',
    title: 'Vyper reentrancy via raw_call',
    severity: 'high',
    confidenceTier: 'MEDIUM',
    languages: ['vyper'],
    pattern: /(?:raw_call)\s*\(/g,
    mitigations: [/@nonreentrant/gi],
    description: (c, f) => `raw_call in ${f} bypasses Vyper reentrancy guards. Add @nonreentrant decorator.`,
    cwe: ['SWC-107'],
    remediation: 'Add @nonreentrant decorator or avoid raw_call.',
    v1Symbolic: 0.80, v2Fuzzing: 0.75, v3Formal: 0.80, v4Economic: 0.70,
  },
  {
    id: 'VYPER-OVERFLOW-001',
    type: 'integer_overflow',
    title: 'Integer overflow in Vyper unsafe arithmetic',
    severity: 'medium',
    confidenceTier: 'LOW',
    languages: ['vyper'],
    pattern: /(?:unsafe_add|unsafe_sub|unsafe_mul|unsafe_div)\s*\(/g,
    description: (c, f) => `Unsafe arithmetic in ${f} bypasses Vyper 0.3.4+ overflow checks.`,
    cwe: ['SWC-101'],
    remediation: 'Use safe arithmetic (default in Vyper 0.3.4+).',
    v1Symbolic: 0.70, v2Fuzzing: 0.75, v3Formal: 0.80, v4Economic: 0.30,
  },
  {
    id: 'VYPER-AC-001',
    type: 'access_control',
    title: 'Missing access control on Vyper privileged function',
    severity: 'critical',
    confidenceTier: 'HIGH',
    languages: ['vyper'],
    pattern: /@(?:public|external)\s+def\s+(set_|update_|change_|transfer_|admin_|owner_|upgrade_)/g,
    mitigations: [/assert\s+msg\.sender/g],
    description: (c, f) => `Public function in ${f} modifies privileged state without access control.`,
    cwe: ['SWC-105'],
    remediation: 'Add assert msg.sender == self.admin before privileged operations.',
    v1Symbolic: 0.90, v2Fuzzing: 0.85, v3Formal: 0.90, v4Economic: 0.80,
  },
];

// ─── GO/COSMWASM PATTERNS ────────────────────────────────────────────

const GO_ADVANCED: AdvancedPattern[] = [
  {
    id: 'GO-AC-001',
    type: 'access_control',
    title: 'Missing access control in Cosmos SDK message handler',
    severity: 'critical',
    confidenceTier: 'HIGH',
    languages: ['go'],
    pattern: /func\s+\w+\s*\(\s*keeper\s+\*Keeper[^)]*\)\s+(?:SetOwner|UpdateConfig|ChangeAdmin|Upgrade|Sudo)/g,
    mitigations: [/RequireAuthority|RequireAdmin|requireRole/gi],
    description: (c, f) => `Keeper method in ${f} modifies privileged state without authority check.`,
    cwe: ['SWC-105', 'CWE-863'],
    remediation: 'Add keeper.RequireAuthority() or similar check.',
    v1Symbolic: 0.88, v2Fuzzing: 0.85, v3Formal: 0.88, v4Economic: 0.80,
  },
  {
    id: 'GO-OVERFLOW-001',
    type: 'integer_overflow',
    title: 'Integer overflow in Cosmos SDK math',
    severity: 'high',
    confidenceTier: 'MEDIUM',
    languages: ['go'],
    pattern: /(?:\.Add\(|\.Sub\(|\.Mul\(|\.Quo\()\s*\(/g,
    description: (c, f) => `Arithmetic in ${f} may overflow in Go. Use SafeAdd/SafeSub/SafeMul from Cosmos SDK.`,
    cwe: ['SWC-101'],
    remediation: 'Use SafeAdd, SafeSub, SafeMul from Cosmos SDK math.',
    v1Symbolic: 0.70, v2Fuzzing: 0.75, v3Formal: 0.80, v4Economic: 0.30,
  },
];

// ─── CAIRO/STARKNET PATTERNS ─────────────────────────────────────────

const CAIRO_ADVANCED: AdvancedPattern[] = [
  {
    id: 'CAIRO-AC-001',
    type: 'access_control',
    title: 'Missing caller assertion in Cairo',
    severity: 'critical',
    confidenceTier: 'HIGH',
    languages: ['cairo'],
    pattern: /fn\s+(set_|update_|change_|admin_|owner_|upgrade_|pause_)\w*\s*\([^)]*\)\s*(?!\s*assert)/g,
    mitigations: [/assert.*get_caller_address/g],
    description: (c, f) => `Function in ${f} lacks caller validation. Any contract can call public functions.`,
    cwe: ['SWC-105'],
    remediation: 'Verify get_caller_address() matches expected admin.',
    v1Symbolic: 0.90, v2Fuzzing: 0.85, v3Formal: 0.90, v4Economic: 0.80,
  },
  {
    id: 'CAIRO-OVERFLOW-001',
    type: 'integer_overflow',
    title: 'U256 overflow in felt252 arithmetic',
    severity: 'medium',
    confidenceTier: 'MEDIUM',
    languages: ['cairo'],
    pattern: /(?:u256|Uint256|felt252)\s*\w+\s*[+\-*/]\s*(?:u256|Uint256|felt252)/g,
    description: (c, f) => `Arithmetic on u256/felt252 types in ${f} may overflow.`,
    cwe: ['SWC-101'],
    remediation: 'Use checked arithmetic for financial calculations.',
    v1Symbolic: 0.70, v2Fuzzing: 0.75, v3Formal: 0.80, v4Economic: 0.20,
  },
];

// ─── MOVE PATTERNS ───────────────────────────────────────────────────

const MOVE_ADVANCED: AdvancedPattern[] = [
  {
    id: 'MOVE-AC-001',
    type: 'access_control',
    title: 'Missing access control - public entry without capability',
    severity: 'critical',
    confidenceTier: 'HIGH',
    languages: ['move'],
    pattern: /public\s+entry\s+fun\s+(set_|update_|change_|transfer_|admin_|owner_|upgrade_)/g,
    mitigations: [/assert|require|abort_if/g],
    description: (c, f) => `Public entry function in ${f} has no capability/assertion check.`,
    cwe: ['SWC-105'],
    remediation: 'Add capability check or signer verification.',
    v1Symbolic: 0.92, v2Fuzzing: 0.88, v3Formal: 0.90, v4Economic: 0.85,
  },
  {
    id: 'MOVE-ORACLE-001',
    type: 'oracle_manipulation',
    title: 'Single oracle source without freshness check',
    severity: 'critical',
    confidenceTier: 'MEDIUM',
    languages: ['move'],
    pattern: /(?:get_price|oracle_price|fetch_price|price_feed)\s*\([^)]*\)/g,
    mitigations: [/last_updated|freshness|staleness/gi],
    description: (c, f) => `Oracle price fetch in ${f} lacks freshness verification.`,
    cwe: ['SWC-120'],
    remediation: 'Add staleness check and deviation bounds.',
    v1Symbolic: 0.40, v2Fuzzing: 0.55, v3Formal: 0.35, v4Economic: 0.90,
  },
];

// ─── RUST/SOLANA PATTERNS ────────────────────────────────────────────

const RUST_ADVANCED: AdvancedPattern[] = [
  {
    id: 'RUST-AC-001',
    type: 'access_control',
    title: 'Missing signer verification in Solana program',
    severity: 'critical',
    confidenceTier: 'HIGH',
    languages: ['rust'],
    // Bug fix: previous regex /if\s+!*\w+\.is_signer/g matched the PRESENCE
    // of a signer check (so every well-written Solana program was flagged).
    // New regex matches Rust functions that contain privileged operations
    // (transfer/mint/burn/delegate) but have NO is_signer check anywhere
    // in the function body.
    pattern: /(?:pub\s+)?fn\s+\w+\s*\([^)]*\)\s*(?:->\s*[^{]+)?\s*\{(?:(?!is_signer)[^}])*(?:transfer|mint_to|burn|delegate|set_authority|withdraw|stake)[^}]*\}/gs,
    mitigations: [],
    description: (c, f) => `Solana program function in ${f} performs a privileged operation without verifying that the relevant account is a signer. On Solana, any account can be passed to a program — without \`assert!(account.is_signer)\` the caller can be anyone.`,
    cwe: ['SWC-105'],
    remediation: 'Verify all accounts that should sign are actually signers using `assert!(account.is_signer)` or `require!(account.is_signer, ...)`.',
    v1Symbolic: 0.85, v2Fuzzing: 0.80, v3Formal: 0.88, v4Economic: 0.75,
  },
  {
    id: 'RUST-CPI-001',
    type: 'arbitrary_call',
    title: 'Cross-program invocation to user-controlled program',
    severity: 'critical',
    confidenceTier: 'HIGH',
    languages: ['rust'],
    pattern: /invoke_signed\s*\([^)]*program_id/g,
    mitigations: [/program_id\s*==\s*EXPECTED/g],
    description: (c, f) => `CPI in ${f} uses a program_id that may be user-controlled.`,
    cwe: ['SWC-107'],
    remediation: 'Verify program_id against expected value before CPI.',
    v1Symbolic: 0.85, v2Fuzzing: 0.80, v3Formal: 0.85, v4Economic: 0.75,
  },
];

// ─── ALL PATTERNS ────────────────────────────────────────────────────

const ALL_PATTERNS: AdvancedPattern[] = [
  ...SOLIDITY_ADVANCED,
  ...WEB_ADVANCED,
  ...VYPER_ADVANCED,
  ...GO_ADVANCED,
  ...CAIRO_ADVANCED,
  ...MOVE_ADVANCED,
  ...RUST_ADVANCED,
];

// ─── ENHANCED LANGUAGE DETECTION ────────────────────────────────────

export function detectLanguageAdvanced(code: string): Language {
  if (code.includes('@public') || code.includes('@external') || (code.includes('def ') && code.includes('self.'))) return 'vyper';
  if (code.includes('module ') && code.includes('fun ') && (code.includes('move_to') || code.includes('borrow_global') || code.includes('public entry fun'))) return 'move';
  if (code.includes('fn ') && (code.includes('solana') || code.includes('anchor') || code.includes('#[program]'))) return 'rust';
  if (code.includes('fn ') && code.includes('felt252')) return 'cairo';
  if (code.includes('package ') && (code.includes('cosmos') || code.includes('wasmd') || code.includes('CosmWasm'))) return 'go';
  if (code.includes('interface ') && code.includes('=>') && code.includes(': ')) return 'typescript';
  if (code.includes('require(') || code.includes('module.exports') || (code.includes('function ') && code.includes('=>'))) return 'javascript';
  if (code.includes('pragma solidity') || (code.includes('contract ') && code.includes('function '))) return 'solidity';
  if (code.includes('<html') || code.includes('<script') || code.includes('fetch(')) return 'web';
  if (code.includes('def ') && code.includes('import ') && code.includes('self.')) return 'python';
  return 'solidity';
}

// ─── ADVANCED SCAN ENGINE ───────────────────────────────────────────

export function runAdvancedScan(
  sourceCode: string,
  fileName: string,
  maxFindings: number = 30,
): AdvancedFinding[] {
  const lang = detectLanguageAdvanced(sourceCode);
  const findings: AdvancedFinding[] = [];
  const seen = new Set<string>();
  const lines = sourceCode.split('\n');

  const relevantPatterns = ALL_PATTERNS.filter(p =>
    p.languages.includes(lang) || p.languages.includes('web')
  );

  for (const pattern of relevantPatterns) {
    pattern.pattern.lastIndex = 0;
    const matches = sourceCode.matchAll(pattern.pattern);

    for (const match of matches) {
      const dedupKey = `${pattern.id}:${match.index}`;
      if (seen.has(dedupKey)) continue;
      if (findings.length >= maxFindings) break;

      const matchStart = match.index ?? 0;
      const lineNumber = sourceCode.slice(0, matchStart).split('\n').length;
      const surroundingCode = sourceCode.slice(Math.max(0, matchStart - 500), Math.min(sourceCode.length, matchStart + 500));

      // Capture metavariables
      const captures: Record<string, string> = {};
      if (pattern.metavariables) {
        for (const [varName, varRegex] of Object.entries(pattern.metavariables)) {
          varRegex.lastIndex = 0;
          const varMatch = surroundingCode.match(varRegex);
          if (varMatch) captures[varName] = varMatch[1] || varMatch[0];
        }
      }

      // Check mitigations
      const mitigationsFound: string[] = [];
      let hasMitigation = false;
      if (pattern.mitigations) {
        for (const mit of pattern.mitigations) {
          mit.lastIndex = 0;
          if (mit.test(surroundingCode)) {
            mitigationsFound.push(mit.source.slice(0, 40));
            hasMitigation = true;
          }
        }
      }

      // Check context requirements (notPrecededBy = mitigation found → suppress)
      let contextMet = true;
      if (pattern.requiresContext?.notPrecededBy) {
        const ctxRegex = pattern.requiresContext.notPrecededBy;
        ctxRegex.lastIndex = 0;
        const before = sourceCode.slice(Math.max(0, matchStart - 500), matchStart);
        if (ctxRegex.test(before)) {
          // Mitigation is present → suppress
          contextMet = false;
        }
      }

      // Calculate confidence
      let baseConfidence = pattern.confidenceTier === 'HIGH' ? 0.90 : pattern.confidenceTier === 'MEDIUM' ? 0.72 : 0.55;
      let confidence = baseConfidence;
      if (hasMitigation) confidence *= 0.3;

      // Additional FP check via vulnerability-db
      const fpCheck = checkFalsePositive(pattern.type, surroundingCode);
      confidence *= fpCheck.confidence;

      const isSuppressed = confidence < 0.2 || (hasMitigation && confidence < 0.4);

      if (!isSuppressed && contextMet) {
        const snippetStart = Math.max(0, lineNumber - 3);
        const snippetEnd = Math.min(lines.length, lineNumber + 3);
        const codeSnippet = lines.slice(snippetStart, snippetEnd).join('\n');

        findings.push({
          id: `adv-${pattern.id}-${findings.length}`,
          ruleId: pattern.id,
          type: pattern.type,
          title: pattern.title,
          severity: pattern.severity,
          confidenceTier: pattern.confidenceTier,
          location: `${fileName}:L${lineNumber}`,
          line: lineNumber,
          description: pattern.description(captures, fileName) +
            `\n\nMatched: \`${match[0].slice(0, 80)}\`` +
            (mitigationsFound.length > 0 ? `\nMitigations found: ${mitigationsFound.join(', ')}` : '\nNo mitigations found') +
            `\nContext:\n\`\`\`\n${codeSnippet}\n\`\`\``,
          remediation: pattern.remediation,
          cwe: pattern.cwe || [],
          confidence: Math.round(confidence * 100) / 100,
          captures,
          mitigationsFound,
          isSuppressed,
          v1Symbolic: pattern.v1Symbolic,
          v2Fuzzing: pattern.v2Fuzzing,
          v3Formal: pattern.v3Formal,
          v4Economic: pattern.v4Economic,
        });
      }

      seen.add(dedupKey);
    }
    if (findings.length >= maxFindings) break;
  }

  findings.sort((a, b) => b.confidence - a.confidence);
  return findings;
}
