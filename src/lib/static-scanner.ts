/**
 * CryptoSentinel — Static Pattern Scanner
 * Detects real vulnerabilities via code pattern matching (regex/heuristics).
 * Language-aware: Solidity, Vyper, Move, Rust (Solana), Cairo (StarkNet).
 *
 * This runs BEFORE AI analysis to catch obvious bugs,
 * and serves as the fallback when no API key is available.
 */
import { createHash } from 'crypto';

export interface StaticFinding {
  type: string;
  title: string;
  severity: string;
  location: string;
  description: string;
  confidence: number;
  v1Symbolic: number;
  v2Fuzzing: number;
  v3Formal: number;
  v4Economic: number;
  patternTag: string;
}

interface Pattern {
  type: string;
  title: string;
  severity: string;
  regex: RegExp;
  description: (match: RegExpMatchArray, file: string) => string;
  confidence: number;
  v1: number; v2: number; v3: number; v4: number;
}

// ─── SOLIDITY PATTERNS ────────────────────────────────────────────────

const SOLIDITY_PATTERNS: Pattern[] = [
  // Reentrancy
  {
    type: 'reentrancy',
    title: 'Reentrancy vulnerability — external call before state update',
    severity: 'critical',
    regex: /(\w+)\s*\.\s*(call|transfer|send)\s*\([^)]*\)[\s\S]*?(?!require)[\s\S]*?\1\s*\[/g,
    description: (m, f) => `External call via ${m[0].slice(0, 40)} in ${f} executes before state variables are updated. An attacker re-enters the function through the external call callback, draining funds before the balance check occurs. This violates the Checks-Effects-Interactions pattern (SWC-107).`,
    confidence: 0.88, v1: 0.95, v2: 0.90, v3: 0.85, v4: 0.80,
  },
  {
    type: 'reentrancy',
    title: 'Reentrancy via low-level call without state update guard',
    severity: 'critical',
    regex: /(?:call|delegatecall|staticcall)\s*\{[^}]*\}\s*\(/g,
    description: (m, f) => `Low-level ${m[0].slice(0, 30)} in ${f} does not check return value and does not follow Checks-Effects-Interactions. This enables reentrancy attacks where an attacker can re-enter during the external call (SWC-107).`,
    confidence: 0.82, v1: 0.90, v2: 0.85, v3: 0.80, v4: 0.70,
  },

  // Unchecked external call
  {
    type: 'unchecked_call',
    title: 'Unchecked return value of external call',
    severity: 'high',
    regex: /(?:transfer|send|call|delegatecall|staticcall)\s*[({][^;]*?;\s*(?!require|if|assert)/g,
    description: (m, f) => `External call ${m[0].slice(0, 40)} in ${f} does not check the return value. If the call fails silently, execution continues with incorrect assumptions. This leads to inconsistent state and potential fund loss (SWC-104).`,
    confidence: 0.85, v1: 0.92, v2: 0.88, v3: 0.90, v4: 0.50,
  },

  // Access control
  {
    type: 'access_control',
    title: 'Missing access control on privileged function',
    severity: 'critical',
    regex: /function\s+(setOwner|changeAdmin|updateConfig|upgradeTo|transferOwnership|migrate|setImplementation|pause|unpause|emergencyWithdraw|sweepFunds)\s*\([^)]*\)\s*(?:public|external)(?!\s*(?:onlyOwner|onlyAdmin|onlyRole|onlyGovernance|modifier))/g,
    description: (m, f) => `Function ${m[0].slice(0, 40)} in ${f} is public/external without access control modifier. Any caller can execute this privileged operation, enabling unauthorized state changes, fund theft, or protocol takeover (SWC-105).`,
    confidence: 0.90, v1: 0.95, v2: 0.90, v3: 0.95, v4: 0.85,
  },
  {
    type: 'access_control',
    title: 'tx.origin used for authorization',
    severity: 'high',
    regex: /tx\.origin/g,
    description: (m, f) => `tx.origin is used for authorization in ${f}. A malicious contract can trick a user into calling it, and since tx.origin remains the user's address, the check passes. This enables phishing-based authorization bypass (SWC-115). Use msg.sender instead.`,
    confidence: 0.88, v1: 0.95, v2: 0.90, v3: 0.95, v4: 0.60,
  },

  // Integer overflow/underflow
  {
    type: 'integer_overflow',
    title: 'Unchecked arithmetic in unchecked block',
    severity: 'high',
    regex: /unchecked\s*\{[^}]*[+\-*/][^}]*\}/gs,
    description: (m, f) => `Arithmetic operations inside unchecked{} block in ${f} bypass Solidity 0.8+ built-in overflow checks. If input values are not properly validated, overflow/underflow wraps around silently, leading to incorrect balances or bypassing of require checks (SWC-101).`,
    confidence: 0.82, v1: 0.90, v2: 0.95, v3: 0.92, v4: 0.30,
  },

  // Delegatecall
  {
    type: 'delegatecall',
    title: 'Unsafe delegatecall to user-controlled address',
    severity: 'critical',
    regex: /delegatecall\s*\{[^}]*\}\s*\(\s*(?:abi\.encodePacked|abi\.encodeWithSelector|[^)]*_implementation|[^)]*_logic|[^)]*_target)/g,
    description: (m, f) => `delegatecall in ${f} executes logic from another contract in the context of the caller. If the implementation address is user-controllable or lacks proper access control, an attacker can execute arbitrary code with the proxy's storage context, hijacking all funds and state (SWC-112).`,
    confidence: 0.87, v1: 0.90, v2: 0.85, v3: 0.90, v4: 0.80,
  },

  // Oracle manipulation — HackenProof tier: HIGH (not critical)
  // Per docs.hackenproof.com: "Oracle manipulation (stale/manipulated price
  // leading to over-borrowing)" is explicitly classified as HIGH severity.
  // Previously hard-coded as critical — that over-classified every oracle
  // finding by one tier.
  {
    type: 'oracle_manipulation',
    title: 'Single-source oracle without deviation bounds',
    severity: 'high',
    regex: /(?:getPrice|latestAnswer|latestRoundData|consult|peek)\s*\([^)]*\)[\s\S]{0,200}(?!maxDeviation|circuitBreaker|stalePrice)/g,
    description: (m, f) => `Oracle price fetch in ${f} uses a single source without deviation bounds or circuit breaker. An attacker can manipulate the oracle price via flash loan, causing the protocol to use stale or manipulated prices. This enables over-borrowing, under-collateralization, and fund extraction (SWC-120). HackenProof severity: HIGH (oracle manipulation is High, not Critical — temporary impact unless it leads to protocol insolvency).`,
    confidence: 0.75, v1: 0.40, v2: 0.60, v3: 0.30, v4: 0.95,
  },

  // Front-running / MEV
  {
    type: 'front_running',
    title: 'Swap without minimum output and deadline',
    severity: 'high',
    regex: /(?:swap|exchange|trade)\w*\s*\([^)]*(?!minAmountOut|minReturn|deadline|slippage)/g,
    description: (m, f) => `Swap function ${m[0].slice(0, 40)} in ${f} lacks minimum output amount and deadline parameters. MEV bots can sandwich the transaction: front-running with a buy to inflate price, then back-running with a sell. User receives fewer tokens than expected (MEV-001).`,
    confidence: 0.78, v1: 0.60, v2: 0.70, v3: 0.50, v4: 0.90,
  },

  // Flash loan attack
  {
    type: 'flash_loan',
    title: 'Flash loan attack vector on single-block state dependency',
    severity: 'critical',
    regex: /(?:borrow|flashLoan|flashBorrow)\s*\([^)]*\)[\s\S]{0,300}(?:price|reserve|balance|collateral|liquidity)/g,
    description: (m, f) => `Flash loan borrow pattern in ${f} interacts with price/reserve/balance state within the same transaction. An attacker borrows a large amount via flash loan, manipulates protocol state (reserves, oracle, collateral ratio), exploits the manipulation, and repays the loan — all atomically. Net profit without capital risk (ECON-001).`,
    confidence: 0.72, v1: 0.25, v2: 0.45, v3: 0.30, v4: 0.95,
  },

  // Storage collision
  {
    type: 'storage_collision',
    title: 'Storage collision in proxy pattern',
    severity: 'critical',
    regex: /(?:implementation|_implementation|_logic|proxy|diamond)\s*(?:=\s*|:\s*)(?:address|bytes32)/g,
    description: (m, f) => `Storage variable ${m[0].slice(0, 40)} in ${f} may collide with implementation contract storage in proxy pattern. If the proxy and implementation share the same storage slot, writes to one corrupt the other. This enables ownership hijacking or fund theft (SWC-118).`,
    confidence: 0.70, v1: 0.75, v2: 0.70, v3: 0.80, v4: 0.60,
  },

  // Self-destruct / suicide
  {
    type: 'denial_of_service',
    title: 'selfdestruct/SELFDESTRUCT can destroy contract',
    severity: 'critical',
    regex: /(?:selfdestruct|suicide)\s*\(/g,
    description: (m, f) => `selfdestruct() in ${f} can destroy the contract and send all ETH to an arbitrary address. If called without proper access control, any attacker can kill the contract, causing permanent denial of service and fund loss for all users (SWC-106).`,
    confidence: 0.92, v1: 0.95, v2: 0.95, v3: 0.98, v4: 0.80,
  },

  // Arbitrary external call
  {
    type: 'arbitrary_call',
    title: 'Arbitrary external call to user-supplied address',
    severity: 'critical',
    regex: /(?:call|delegatecall)\s*\{[^}]*\}\s*\((?:[^)]*_to|[^)]*_target|[^)]*_addr|[^)]*recipient|[^)]*callback)/g,
    description: (m, f) => `External call in ${f} targets a user-supplied address. An attacker provides a malicious contract address that re-enters the vulnerable function, steals funds, or manipulates state. This is a severe access control violation (SWC-136).`,
    confidence: 0.85, v1: 0.90, v2: 0.85, v3: 0.88, v4: 0.75,
  },

  // Time manipulation
  {
    type: 'time_manipulation',
    title: 'Timestamp/block.number used for critical logic',
    severity: 'medium',
    regex: /(?:block\.timestamp|now|block\.number)\s*[<>=!]+/g,
    description: (m, f) => `Comparison with ${m[0].slice(0, 30)} in ${f} for critical logic. Miners can manipulate block.timestamp by ~15 seconds and block.number by choosing when to include transactions. Time-dependent conditions can be gamed by miners for profit (SWC-116).`,
    confidence: 0.65, v1: 0.70, v2: 0.60, v3: 0.65, v4: 0.50,
  },

  // Bad randomness
  {
    type: 'bad_randomness',
    title: 'Predictable randomness from block variables',
    severity: 'high',
    regex: /(?:keccak256|sha256|sha3)\s*\(\s*(?:abi\.encodePacked\s*\(\s*)?(?:block\.(?:timestamp|difficulty|number|coinbase)|now|msg\.sender)/g,
    description: (m, f) => `Hash of block variables in ${f} used as randomness. Block.timestamp, difficulty, and number are known/controllable by miners. An attacker (especially a miner) can predict the outcome and always win lotteries, games, or randomized distributions (SWC-120). Use Chainlink VRF instead.`,
    confidence: 0.80, v1: 0.85, v2: 0.80, v3: 0.85, v4: 0.70,
  },

  // Uninitialized storage pointer — HackenProof tier: LOW
  // Per docs.hackenproof.com: "Uninitialized storage variables (often low
  // risk)" is explicitly listed under LOW severity. Previously hard-coded
  // as 'high' — that over-classified these findings by two tiers.
  {
    type: 'storage_collision',
    title: 'Uninitialized storage pointer',
    severity: 'low',
    regex: /(?:storage\s+\w+;|Storage\s+\w+;)(?!\s*\w+\s*=)/g,
    description: (m, f) => `Uninitialized storage variable in ${f} points to storage slot 0 by default. Any write to this variable overwrites the data at slot 0 (typically owner or other critical state). This is a storage collision risk (SWC-109). HackenProof severity: LOW (uninitialized storage variables are typically low risk per docs.hackenproof.com).`,
    confidence: 0.82, v1: 0.90, v2: 0.85, v3: 0.95, v4: 0.60,
  },

  // DoS via gas limit
  {
    type: 'denial_of_service',
    title: 'Unbounded loop over dynamic array',
    severity: 'high',
    regex: /for\s*\(\s*\w+\s+\w+\s*=\s*0\s*;\s*\w+\s*<\s*(\w+)\s*\.\s*(?:length|size|count)\s*;/g,
    description: (m, f) => `Loop over ${m[1] || 'dynamic array'}.length in ${f} has no upper bound. If the array grows large enough, the function exceeds the block gas limit and becomes permanently unusable. Attackers can add elements to block withdrawals, claims, or other critical operations (SWC-128).`,
    confidence: 0.72, v1: 0.80, v2: 0.75, v3: 0.70, v4: 0.50,
  },

  // Signature replay
  {
    type: 'signature_replay',
    title: 'Signature replay — missing nonce/deadline check',
    severity: 'high',
    regex: /ecrecover\s*\([^)]*\)[\s\S]{0,200}(?!nonce|_nonce|usedHash|executed|invalidated)/g,
    description: (m, f) => `ecrecover in ${f} validates a signature without checking nonce or deadline. The same valid signature can be replayed multiple times, enabling duplicate operations (double-spend, double-claim, double-approval). Add a nonce mapping and deadline parameter (SWC-121).`,
    confidence: 0.78, v1: 0.85, v2: 0.80, v3: 0.85, v4: 0.65,
  },

  // Shadowing
  {
    type: 'state_shadowing',
    title: 'State variable shadowing in inheritance',
    severity: 'medium',
    regex: /(?:uint|int|bool|address|bytes\d*|string)\s+(?:public|private|internal)?\s*(?:constant|immutable)?\s*\w+\s*(?:=\s*[^;]+)?;/g,
    description: (m, f) => `Variable declaration in ${f} may shadow a variable from a parent contract. When both parent and child define the same variable name, the child's version hides the parent's, leading to incorrect state reads/writes and potential fund loss (SWC-119).`,
    confidence: 0.55, v1: 0.65, v2: 0.60, v3: 0.70, v4: 0.20,
  },

  // Assembly usage
  {
    type: 'access_control',
    title: 'Inline assembly bypasses safety checks',
    severity: 'high',
    regex: /assembly\s*\{[^}]*\}/gs,
    description: (m, f) => `Inline assembly in ${f} bypasses Solidity's safety features (overflow checks, access control, memory safety). Assembly blocks can read/write arbitrary storage slots, manipulate memory, and execute operations that would be flagged in normal Solidity. Review carefully for intentional or accidental vulnerabilities.`,
    confidence: 0.60, v1: 0.70, v2: 0.65, v3: 0.75, v4: 0.30,
  },

  // ─── NEW PATTERNS — HackenProof Critical categories previously missing ──

  // Unauthorized mint/burn — HackenProof Critical: "Unauthorized mint/burn of tokens"
  // Detects mint() functions without access control. Critical because it
  // dilutes holder value or enables direct theft via mint-to-attacker.
  {
    type: 'unauthorized_mint',
    title: 'Unauthorized mint — mint() without access control',
    severity: 'critical',
    regex: /function\s+(?:mint|_mint|mintTo|mintBatch|issue|airdrop)\s*\([^)]*\)\s*(?:public|external)(?!\s*(?:onlyOwner|onlyAdmin|onlyRole|onlyMinter|onlyGovernance|modifier))/g,
    description: (m, f) => `Mint function ${m[0].slice(0, 40)} in ${f} is public/external without access control. Any caller can mint arbitrary tokens to themselves, diluting holder value or enabling direct theft. HackenProof severity: Critical (unauthorized mint/burn of tokens — inflation attack, value dilution).`,
    confidence: 0.92, v1: 0.95, v2: 0.92, v3: 0.98, v4: 0.90,
  },

  // Governance hijack — HackenProof Critical: "Governance manipulation (vote hijacking, quorum bypass, instant execution without timelock)"
  // Detects governance functions (vote, propose, execute) without timelock
  // or quorum. Critical because governance manipulation enables protocol takeover.
  {
    type: 'governance_hijack',
    title: 'Governance function without timelock or quorum',
    severity: 'critical',
    regex: /function\s+(?:execute|queue|propose|vote|castVote|delegate|setVote)\s*\([^)]*\)\s*(?:public|external)(?![\s\S]{0,200}(?:timelock|delay|quorum|_quorum))/g,
    description: (m, f) => `Governance function ${m[0].slice(0, 40)} in ${f} executes without timelock delay or quorum verification. An attacker with voting power (e.g. via flash loan) can pass a malicious proposal and execute it in the same transaction, bypassing community review. HackenProof severity: Critical (governance manipulation — vote hijacking, quorum bypass, instant execution without timelock).`,
    confidence: 0.85, v1: 0.88, v2: 0.82, v3: 0.90, v4: 0.85,
  },

  // Protocol insolvency — HackenProof Critical: "Protocol insolvency (under-collateralization, unbacked tokens, critical mispricing)"
  // Detects collateral ratio checks that allow under-collateralization,
  // or borrow functions without sufficient collateral verification.
  {
    type: 'protocol_insolvency',
    title: 'Borrow/withdraw without sufficient collateral check',
    severity: 'critical',
    regex: /function\s+(?:borrow|withdraw|redeem|liquidate)\s*\([^)]*\)\s*(?:public|external)(?![\s\S]{0,300}(?:collateralRatio|_collateralRatio|require.*collateral|healthFactor|liquidationThreshold|_ltv))/g,
    description: (m, f) => `Function ${m[0].slice(0, 40)} in ${f} allows borrowing/withdrawal without verifying sufficient collateral ratio, health factor, or liquidation threshold. An attacker can borrow more than their collateral supports, leaving the protocol under-collateralized (insolvent). HackenProof severity: Critical (protocol insolvency — under-collateralization, unbacked tokens).`,
    confidence: 0.78, v1: 0.72, v2: 0.78, v3: 0.75, v4: 0.95,
  },
];

// ─── MOVE PATTERNS ────────────────────────────────────────────────────

const MOVE_PATTERNS: Pattern[] = [
  {
    type: 'access_control',
    title: 'Missing access control — public entry without capability check',
    severity: 'critical',
    regex: /public\s+entry\s+fun\s+(set_|update_|change_|transfer_|admin_|owner_|upgrade_|pause_|config_)/g,
    description: (m, f) => `Public entry function ${m[0].slice(0, 40)} in ${f} has no capability/assertion check. In Move, any signer can call public entry functions. Without verifying the signer has admin/owner capability, any user can modify critical protocol state.`,
    confidence: 0.88, v1: 0.92, v2: 0.88, v3: 0.90, v4: 0.85,
  },
  {
    type: 'reentrancy',
    title: 'Cross-module resource manipulation without global invariant check',
    severity: 'high',
    regex: /(?:borrow_global_mut|move_from|move_to)\s*<[^>]+>\s*\([^)]*\)[\s\S]{0,200}(?:transfer|withdraw|send)/g,
    description: (m, f) => `Resource mutation via ${m[0].slice(0, 40)} in ${f} followed by external transfer without global invariant verification. While Move's resource model prevents classic reentrancy, cross-module interactions can still violate invariants if a module is upgraded or if the resource is temporarily in an inconsistent state during the operation.`,
    confidence: 0.70, v1: 0.75, v2: 0.70, v3: 0.80, v4: 0.55,
  },
  {
    type: 'integer_overflow',
    title: 'Unchecked arithmetic in Move',
    severity: 'high',
    regex: /(?:(?:\d+\s*\*\s*\d+|\w+\s*\*\s*\w+)|(?:\w+\s*\+\s*\w+))\s*;(?!\s*\/\/\s*overflow\s*safe)/g,
    description: (m, f) => `Arithmetic operation in ${f} without explicit overflow check. While Move aborts on overflow by default, the abort may leave the resource in an inconsistent state if it occurs between multiple mutations. Ensure operations are atomic and validated before mutation.`,
    confidence: 0.58, v1: 0.65, v2: 0.70, v3: 0.75, v4: 0.20,
  },
  {
    type: 'oracle_manipulation',
    title: 'Single oracle source without freshness check',
    severity: 'high',
    regex: /(?:get_price|oracle_price|fetch_price|price_feed)\s*\([^)]*\)[\s\S]{0,200}(?!last_updated|timestamp|freshness|staleness)/g,
    description: (m, f) => `Oracle price fetch in ${f} lacks freshness/staleness verification. Without checking the timestamp of the last oracle update, the protocol may use stale prices that don't reflect current market conditions. An attacker can exploit price delays or manipulate on-chain oracles. HackenProof severity: HIGH (oracle manipulation is High, not Critical).`,
    confidence: 0.72, v1: 0.40, v2: 0.55, v3: 0.35, v4: 0.90,
  },
  {
    type: 'denial_of_service',
    title: 'Unbounded iteration over dynamic table/vector',
    severity: 'high',
    regex: /(?:while|loop)\s*\([^)]*(?:length|size|len)\s*[<>]/g,
    description: (m, f) => `Loop bounded by dynamic collection length in ${f} can exceed gas limits. In Move, tables and vectors can grow unboundedly. If a function iterates over all entries, an attacker can bloat the collection to cause out-of-gas failures, permanently blocking operations.`,
    confidence: 0.68, v1: 0.75, v2: 0.70, v3: 0.65, v4: 0.40,
  },
];

// ─── RUST (SOLANA BPF) PATTERNS ──────────────────────────────────────

const RUST_PATTERNS: Pattern[] = [
  // Missing signer verification in Solana program — Bug fix:
  // The previous regex /if\s+!*\w+\.is_signer/g matched the PRESENCE of a
  // signer check (e.g., `if account.is_signer` or `if !account.is_signer`),
  // then claimed the check was MISSING. Every Solana program with a
  // CORRECT signer check was flagged as vulnerable.
  //
  // Correct approach: this regex now matches Solana instruction-handler
  // functions that contain privileged operations (transfer, mint, burn,
  // delegate) but lack ANY is_signer check in the body. We look for the
  // privileged op AND the absence of is_signer on the same line range.
  {
    type: 'access_control',
    title: 'Missing signer verification in Solana program',
    severity: 'critical',
    // Matches functions containing privileged ops without any is_signer check
    // within the function body. Negative lookahead ensures we don't match
    // functions that DO have a signer check.
    regex: /(?:pub\s+)?fn\s+\w+\s*\([^)]*\)\s*(?:->\s*[^{]+)?\{(?:(?!is_signer)[^}])*(?:transfer|mint_to|burn|delegate|set_authority|withdraw|stake)[^}]*\}/gs,
    description: (m, f) => `Solana program function in ${f} performs a privileged operation (transfer/mint/burn/delegate) without verifying that the relevant account is a signer. On Solana, any account can be passed to a program instruction — without assert!(account.is_signer) the caller can be anyone, enabling unauthorized fund movement or state mutation.`,
    confidence: 0.78, v1: 0.85, v2: 0.80, v3: 0.88, v4: 0.75,
  },
  {
    type: 'integer_overflow',
    title: 'Unchecked arithmetic in Solana BPF program',
    severity: 'high',
    regex: /(?:\.checked_add|\.checked_sub|\.checked_mul)\s*\(\)\s*\.ok_or/g,
    description: (m, f) => `While checked arithmetic is used in ${f}, the error handling via ok_or may silently continue with incorrect state. Ensure the error variant properly halts instruction execution and doesn't leave accounts in an inconsistent state.`,
    confidence: 0.60, v1: 0.70, v2: 0.75, v3: 0.80, v4: 0.25,
  },
  {
    type: 'arbitrary_call',
    title: 'Cross-program invocation to user-controlled program',
    severity: 'critical',
    regex: /invoke_signed\s*\([^)]*program_id/g,
    description: (m, f) => `Cross-program invocation (CPI) in ${f} uses a program_id that may be user-controlled. If the program_id is not verified against an expected value, an attacker can substitute a malicious program that returns fabricated data or executes arbitrary logic.`,
    confidence: 0.80, v1: 0.85, v2: 0.80, v3: 0.85, v4: 0.75,
  },
];

// ─── CAIRO (STARKNET) PATTERNS ────────────────────────────────────────

const CAIRO_PATTERNS: Pattern[] = [
  {
    type: 'access_control',
    title: 'Missing caller validation in Cairo contract',
    severity: 'critical',
    regex: /fn\s+(set_|update_|change_|admin_|owner_|upgrade_|pause_)\w*\s*\([^)]*\)\s*(?!\s*assert)/g,
    description: (m, f) => `Function ${m[0].slice(0, 40)} in ${f} lacks caller validation. In Cairo/StarkNet, any contract can call public functions. Without verifying get_caller_address() matches the expected admin/owner, any caller can modify privileged state.`,
    confidence: 0.85, v1: 0.90, v2: 0.85, v3: 0.90, v4: 0.80,
  },
  {
    type: 'integer_overflow',
    title: 'U256 overflow in Cairo felt252 arithmetic',
    severity: 'medium',
    regex: /(?:u256|Uint256|felt252)\s*\w+\s*[+\-*/]\s*(?:u256|Uint256|felt252)/g,
    description: (m, f) => `Arithmetic on u256/felt252 types in ${f} may overflow. While felt252 has a large prime field, u256 operations can overflow if not using checked arithmetic. Ensure wide arithmetic or explicit overflow checks for financial calculations.`,
    confidence: 0.60, v1: 0.70, v2: 0.75, v3: 0.80, v4: 0.20,
  },
];

// ─── GENERIC WEB PATTERNS ─────────────────────────────────────────────

const WEB_PATTERNS: Pattern[] = [
  {
    type: 'xss',
    title: 'Reflected XSS via innerHTML or document.write',
    severity: 'critical',
    regex: /(?:innerHTML|outerHTML|document\.write)\s*[=\(]/g,
    description: (m, f) => `DOM manipulation via ${m[0].slice(0, 30)} in ${f} directly injects content into the page. If user input reaches this sink without sanitization, an attacker can inject arbitrary JavaScript, steal session tokens, manipulate wallet connections, or redirect transactions.`,
    confidence: 0.80, v1: 0.85, v2: 0.80, v3: 0.75, v4: 0.60,
  },
  {
    type: 'api_leak',
    title: 'Hardcoded API key or secret',
    severity: 'critical',
    regex: /(?:api[_-]?key|secret|token|password|private[_-]?key)\s*[=:]\s*['"][^'"]{8,}['"]/gi,
    description: (m, f) => `Hardcoded secret in ${f}. API keys, private keys, or passwords embedded in client-side code are visible to anyone inspecting the page source or network requests. This enables unauthorized API access, fund theft (if private key), or account takeover.`,
    confidence: 0.92, v1: 0.95, v2: 0.90, v3: 0.95, v4: 0.80,
  },
  {
    type: 'cors_misconfig',
    title: 'Overly permissive CORS configuration',
    severity: 'high',
    regex: /Access-Control-Allow-Origin['":\s]*\*|cors\s*[({]\s*origin\s*:\s*true/gi,
    description: (m, f) => `Wildcard CORS in ${f} allows any origin to make cross-origin requests with credentials. An attacker's website can read authenticated responses from the target, stealing user data, session tokens, or wallet state. Restrict to specific trusted origins.`,
    confidence: 0.82, v1: 0.88, v2: 0.85, v3: 0.80, v4: 0.70,
  },
];

// ─── SCANNER ENGINE ───────────────────────────────────────────────────

function detectLanguage(code: string): 'solidity' | 'move' | 'rust' | 'cairo' | 'web' {
  if (code.includes('module ') && code.includes('fun ') && (code.includes('move_to') || code.includes('borrow_global') || code.includes('public entry fun') || code.includes('transfer::'))) return 'move';
  if (code.includes('fn ') && (code.includes('solana') || code.includes('anchor') || code.includes('#[program]'))) return 'rust';
  if (code.includes('fn ') && code.includes('felt252')) return 'cairo';
  if (code.includes('pragma solidity') || code.includes('contract ') || code.includes('function ') && code.includes('uint256')) return 'solidity';
  if (code.includes('<html') || code.includes('<script') || code.includes('fetch(') || code.includes('axios')) return 'web';
  return 'solidity'; // default
}

function getPatterns(lang: string): Pattern[] {
  switch (lang) {
    case 'move': return MOVE_PATTERNS;
    case 'rust': return RUST_PATTERNS;
    case 'cairo': return CAIRO_PATTERNS;
    case 'web': return WEB_PATTERNS;
    default: return SOLIDITY_PATTERNS;
  }
}

/**
 * Run static pattern analysis on source code.
 * Returns findings with confidence scores.
 *
 * Bug fixes vs prior version:
 * 1. Dedup key now includes line number (previously: type:title collapsed
 *    3 reentrancy sites in the same contract into 1 finding). Now we keep
 *    all distinct locations of the same pattern.
 * 2. Findings are sorted by confidence DESCENDING BEFORE the 15-finding
 *    cap is applied. Previously, low-confidence patterns that matched
 *    early in the source would consume the entire cap, silently dropping
 *    high-confidence findings later in the file.
 */
export function runStaticScan(sourceCode: string, fileName: string): StaticFinding[] {
  const lang = detectLanguage(sourceCode);
  const patterns = getPatterns(lang);
  const findings: StaticFinding[] = [];
  // Dedup key now includes line number so multiple sites of the same
  // pattern are reported as separate findings (e.g. 3 reentrancy sites
  // produce 3 findings, not 1).
  const seen = new Set<string>();

  // Split into lines for location tracking
  const lines = sourceCode.split('\n');

  for (const pattern of patterns) {
    // Reset regex lastIndex
    pattern.regex.lastIndex = 0;

    const matches = sourceCode.matchAll(pattern.regex);
    for (const match of matches) {
      // Find line number FIRST so we can include it in dedup key
      const matchStart = match.index ?? 0;
      const lineNumber = sourceCode.slice(0, matchStart).split('\n').length;

      // Dedup: same pattern at the same line is the same finding,
      // but same pattern at a DIFFERENT line is a distinct finding.
      const dedupKey = `${pattern.type}:${pattern.title}:L${lineNumber}`;
      if (seen.has(dedupKey)) continue;
      seen.add(dedupKey);

      // Extract code snippet (3 lines around match)
      const snippetStart = Math.max(0, lineNumber - 2);
      const snippetEnd = Math.min(lines.length, lineNumber + 2);
      const codeSnippet = lines.slice(snippetStart, snippetEnd).join('\n');

      findings.push({
        type: pattern.type,
        title: pattern.title,
        severity: pattern.severity,
        location: `${fileName}:L${lineNumber}`,
        description: pattern.description(match, fileName) +
          `\n\nMatched pattern: \`${match[0].slice(0, 80)}\`` +
          `\nCode context:\n\`\`\`\n${codeSnippet}\n\`\`\``,
        confidence: pattern.confidence,
        v1Symbolic: pattern.v1,
        v2Fuzzing: pattern.v2,
        v3Formal: pattern.v3,
        v4Economic: pattern.v4,
        patternTag: pattern.type,
      });
    }
  }

  // Sort by confidence DESCENDING first — so the cap keeps the most
  // important findings. Previously the cap was applied during the loop,
  // which silently dropped later high-confidence findings.
  findings.sort((a, b) => b.confidence - a.confidence);

  // Apply the per-scan cap AFTER sorting (high-confidence findings win)
  return findings.slice(0, 30);
}
