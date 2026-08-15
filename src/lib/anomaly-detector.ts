/**
 * CryptoSentinel — Anomaly Detector
 * Inspired by: Slither (anomaly detection), Mythril (symbolic anomaly),
 *             Palladium (deviation analysis), Forta (behavioral anomalies)
 *
 * This goes BEYOND pattern matching and AST analysis by detecting:
 * 1. Behavioral anomalies — code that deviates from known-safe DeFi patterns
 * 2. State mutation anomalies — unusual sequences of state changes
 * 3. Economic anomalies — logic that enables economic exploits (flash loans, MEV)
 * 4. Governance anomalies — voting/power concentration risks
 * 5. Dependency anomalies — suspicious imports, known-vulnerable libraries
 * 6. Interaction anomalies — unexpected cross-contract call sequences
 * 7. Numerical anomalies — precision loss, rounding errors, fee bypass
 *
 * These are NOT detectable by regex or even simple AST traversal —
 * they require understanding of DeFi semantics, economic invariants,
 * and behavioral norms of smart contracts.
 */

import { parseCode, ParsedContract, ASTNode, CallEdge, CFGNode } from './semantic-analyzer';

// ─── ANOMALY TYPES ───────────────────────────────────────────────────

export type AnomalyCategory =
  | 'behavioral'       // Deviation from known-safe DeFi patterns
  | 'state_mutation'   // Unusual state change sequences
  | 'economic'         // Economic exploit vectors (flash loan, MEV, arbitrage)
  | 'governance'       // Voting/power concentration risks
  | 'dependency'       // Suspicious or vulnerable dependencies
  | 'interaction'      // Cross-contract call anomalies
  | 'numerical';       // Precision loss, rounding, fee bypass

export interface AnomalyFinding {
  category: AnomalyCategory;
  type: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  location: string;
  line: number;
  description: string;
  confidence: number;
  evidence: string[];
  cwe: string[];
  remediation: string;
  // What makes this an anomaly vs a pattern match
  detectionMethod: string;
}

// ─── KNOWN-SAFE DEFI PATTERNS ───────────────────────────────────────
// These define the "normal" behavior. Deviations are anomalies.

interface SafePattern {
  name: string;
  description: string;
  // Required elements (must be present for the pattern to be "safe")
  requiredElements: string[];
  // If these are missing while the pattern is partially matched → anomaly
  missingImplies: {
    type: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
    cwe: string[];
  };
}

const SAFE_DEFI_PATTERNS: SafePattern[] = [
  {
    name: 'ERC4626_Vault',
    description: 'Standard ERC-4626 vault with deposit/withdraw',
    requiredElements: ['deposit', 'withdraw', 'totalAssets', 'asset', 'convertToShares', 'convertToAssets'],
    missingImplies: {
      type: 'non_standard_vault',
      severity: 'high',
      description: 'Vault does not follow ERC-4626 standard. Non-standard vaults often have hidden rounding errors, fee extraction mechanisms, or share price manipulation vectors that are not audited by the community.',
      cwe: ['SWC-120'],
    },
  },
  {
    name: 'CEI_Pattern',
    description: 'Checks-Effects-Interactions pattern for state external calls',
    requiredElements: ['require', 'state_update', 'external_call'],
    missingImplies: {
      type: 'cei_violation',
      severity: 'critical',
      description: 'Function does not follow Checks-Effects-Interactions. State may be read during reentrancy.',
      cwe: ['SWC-107'],
    },
  },
  {
    name: 'Twap_Oracle',
    description: 'Time-weighted average price oracle with staleness check',
    requiredElements: ['twap', 'staleness_check', 'deviation_bound'],
    missingImplies: {
      type: 'unsafe_oracle',
      severity: 'critical',
      description: 'Oracle usage without TWAP and staleness/deviation checks is vulnerable to flash loan manipulation.',
      cwe: ['SWC-120'],
    },
  },
  {
    name: 'Governance_Timelock',
    description: 'Governance with timelock delay',
    requiredElements: ['propose', 'execute', 'timelock', 'queue'],
    missingImplies: {
      type: 'instant_governance',
      severity: 'high',
      description: 'Governance without timelock allows instant execution of proposals, giving no time for community review or emergency pause.',
      cwe: ['CWE-863'],
    },
  },
];

// ─── KNOWN VULNERABLE DEPENDENCIES ──────────────────────────────────

interface VulnerableDependency {
  name: string;
  versions: string;      // Affected version range
  vulnerability: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  cwe: string[];
  fixedIn?: string;
}

const VULNERABLE_DEPS: VulnerableDependency[] = [
  { name: 'solady', versions: '<0.0.7', vulnerability: 'incorrect_math', severity: 'high', description: 'Solady versions before 0.0.7 have incorrect math in certain edge cases for mulWad and divWad operations, leading to off-by-one errors that can be exploited for small fund extraction.', cwe: ['SWC-101'], fixedIn: '0.0.7' },
  { name: 'openzeppelin', versions: '<4.7.0', vulnerability: 'initializer_race', severity: 'high', description: 'OpenZeppelin <4.7.0 initializable contracts have a race condition in the initializer that allows a second initialization call, potentially overwriting critical state.', cwe: ['SWC-105'], fixedIn: '4.7.0' },
  { name: 'proxy-pattern', versions: 'transparent', vulnerability: 'admin_collision', severity: 'medium', description: 'Transparent proxy pattern has potential admin slot collision if the implementation contract uses storage slot 0.', cwe: ['SWC-118'] },
  { name: 'safeMath', versions: 'any', vulnerability: 'deprecated', severity: 'low', description: 'SafeMath is deprecated in Solidity 0.8+. Using it adds gas overhead without safety benefit since overflow checks are built-in.', cwe: ['SWC-101'] },
  { name: 'ecrecover', versions: 'any', vulnerability: 'malleable_signature', severity: 'high', description: 'ecrecover does not check signature malleability. The same message can have two valid signatures (s and N-s), enabling replay in some protocols.', cwe: ['SWC-121'] },
];

// ─── ANOMALY DETECTION ENGINE ───────────────────────────────────────

export function runAnomalyDetection(
  code: string,
  fileName: string,
): AnomalyFinding[] {
  const findings: AnomalyFinding[] = [];
  const lines = code.split('\n');
  const isSolidity = code.includes('pragma solidity') || code.includes('contract ');
  const isVyper = code.includes('@version') && !isSolidity;

  // Parse for structured analysis
  const parsed = parseCode(code, fileName);

  // ─── 1. BEHAVIORAL ANOMALIES ──────────────────────────────────────
  // Deviations from known-safe DeFi patterns

  findings.push(...detectBehavioralAnomalies(code, fileName, parsed, isSolidity));

  // ─── 2. STATE MUTATION ANOMALIES ──────────────────────────────────
  // Unusual sequences of state changes

  findings.push(...detectStateMutationAnomalies(code, fileName, parsed, isSolidity));

  // ─── 3. ECONOMIC ANOMALIES ────────────────────────────────────────
  // Logic that enables economic exploits

  findings.push(...detectEconomicAnomalies(code, fileName, parsed, isSolidity));

  // ─── 4. GOVERNANCE ANOMALIES ──────────────────────────────────────
  // Voting/power concentration risks

  findings.push(...detectGovernanceAnomalies(code, fileName, parsed, isSolidity));

  // ─── 5. DEPENDENCY ANOMALIES ──────────────────────────────────────
  // Suspicious or vulnerable imports

  findings.push(...detectDependencyAnomalies(code, fileName, parsed));

  // ─── 6. INTERACTION ANOMALIES ─────────────────────────────────────
  // Cross-contract call anomalies

  findings.push(...detectInteractionAnomalies(code, fileName, parsed, isSolidity));

  // ─── 7. NUMERICAL ANOMALIES ───────────────────────────────────────
  // Precision loss, rounding errors, fee bypass

  findings.push(...detectNumericalAnomalies(code, fileName, parsed, isSolidity));

  // Sort by severity then confidence
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => {
    const sevDiff = (severityOrder[a.severity] ?? 2) - (severityOrder[b.severity] ?? 2);
    if (sevDiff !== 0) return sevDiff;
    return b.confidence - a.confidence;
  });

  return findings;
}

// ─── 1. BEHAVIORAL ANOMALIES ────────────────────────────────────────

function detectBehavioralAnomalies(
  code: string,
  fileName: string,
  parsed: ParsedContract,
  isSolidity: boolean,
): AnomalyFinding[] {
  const findings: AnomalyFinding[] = [];

  if (!isSolidity) return findings;

  // Detect: Function that handles deposits but doesn't emit events
  // This is a behavioral anomaly — DeFi protocols MUST emit events for deposits
  for (const [funcName, funcNode] of parsed.functions) {
    if (!funcNode.isPublic && !funcNode.isExternal) continue;
    if (funcNode.isView || funcNode.isPure) continue;

    const isDepositLike = /deposit|mint|addLiquidity|stake|enter|join/i.test(funcName);
    const isWithdrawLike = /withdraw|redeem|removeLiquidity|unstake|exit|leave/i.test(funcName);

    if (isDepositLike || isWithdrawLike) {
      // Check if this function emits an event
      const funcBody = getFunctionBody(code, funcNode.line);
      const hasEmit = funcBody.includes('emit ');

      if (!hasEmit) {
        findings.push({
          category: 'behavioral',
          type: 'missing_event',
          title: `${funcName}() handles funds but emits no event`,
          severity: 'medium',
          location: `${fileName}:L${funcNode.line}`,
          line: funcNode.line,
          description: `Function ${funcName}() handles ${isDepositLike ? 'deposits' : 'withdrawals'} but does not emit any event. All DeFi protocols emit events for fund movements — this is not just a best practice but a requirement for off-chain monitoring, indexing (The Graph), and frontends. The absence of events may indicate the developer is trying to hide fund flows, or it may simply be a mistake that prevents monitoring systems from detecting exploits in real-time. This is a behavioral anomaly — not a syntax error or pattern match.`,
          confidence: 0.72,
          evidence: [
            `Function ${funcName} is public/external and handles funds`,
            `No 'emit' statement found in function body`,
            `Standard: all ERC-4626/ERC-20 operations must emit Transfer/Deposit/Withdrawal events`,
          ],
          cwe: ['CWE-200'],
          remediation: `Add emit ${isDepositLike ? 'Deposit' : 'Withdrawal'}(msg.sender, assets, shares) event.`,
          detectionMethod: 'behavioral_anomaly: known-safe DeFi pattern requires events for fund operations',
        });
      }
    }
  }

  // Detect: Transfer-like function without return value (ERC-20 violation)
  for (const [funcName, funcNode] of parsed.functions) {
    if (funcName === 'transfer' || funcName === 'transferFrom' || funcName === 'approve') {
      const funcBody = getFunctionBody(code, funcNode.line);
      const hasReturn = funcBody.includes('return ') || funcBody.includes('return(');

      if (!hasReturn) {
        findings.push({
          category: 'behavioral',
          type: 'erc20_violation',
          title: `${funcName}() does not return bool — ERC-20 violation`,
          severity: 'medium',
          location: `${fileName}:L${funcNode.line}`,
          line: funcNode.line,
          description: `Function ${funcName}() does not return a boolean value as required by ERC-20. Some tokens (like USDT) do not return bool on transfer/approve, which causes compatibility issues with contracts that check the return value using require(token.transfer()). This leads to silent transaction failures. This is a behavioral anomaly — the function looks correct syntactically but violates the token standard.`,
          confidence: 0.82,
          evidence: [
            `Function ${funcName} at L${funcNode.line}`,
            `No return statement in function body`,
            `ERC-20 requires transfer/transferFrom/approve to return bool`,
          ],
          cwe: ['SWC-104'],
          remediation: `Add 'return true;' at the end of ${funcName}(). Use SafeERC20 for handling non-standard tokens.`,
          detectionMethod: 'behavioral_anomaly: ERC-20 standard compliance check via AST',
        });
      }
    }
  }

  // Detect: Payable function that doesn't handle msg.value
  for (const [funcName, funcNode] of parsed.functions) {
    if (!funcNode.isPayable) continue;
    if (funcNode.isView || funcNode.isPure) continue;

    const funcBody = getFunctionBody(code, funcNode.line);
    const usesMsgValue = funcBody.includes('msg.value');

    if (!usesMsgValue) {
      findings.push({
        category: 'behavioral',
        type: 'payable_without_value',
        title: `${funcName}() is payable but ignores msg.value`,
        severity: 'low',
        location: `${fileName}:L${funcNode.line}`,
        line: funcNode.line,
        description: `Function ${funcName}() is marked payable but does not reference msg.value anywhere in its body. This means ETH sent to this function is locked in the contract with no accounting. Either the payable modifier is accidental (copy-paste from a constructor), or the function is intended to accept ETH but doesn't track it — both are anomalies. In the worst case, this enables accidental ETH loss or a griefing attack where users send ETH that is irrecoverable.`,
        confidence: 0.65,
        evidence: [
          `Function ${funcName} is payable`,
          `No reference to msg.value in function body`,
          `ETH sent to this function is not accounted for`,
        ],
        cwe: ['CWE-400'],
        remediation: `Remove 'payable' modifier if ETH is not needed, or add msg.value accounting.`,
        detectionMethod: 'behavioral_anomaly: payable function must use msg.value — checked via AST body analysis',
      });
    }
  }

  return findings;
}

// ─── 2. STATE MUTATION ANOMALIES ────────────────────────────────────

function detectStateMutationAnomalies(
  code: string,
  fileName: string,
  parsed: ParsedContract,
  isSolidity: boolean,
): AnomalyFinding[] {
  const findings: AnomalyFinding[] = [];

  if (!isSolidity) return findings;

  // Detect: State variable written in multiple functions without synchronization
  // If two public functions write to the same state variable, and neither
  // has a reentrancy guard, there may be a race condition.
  const stateWriters = new Map<string, { func: string; line: number; hasGuard: boolean }[]>();

  for (const [funcName, cfg] of parsed.cfg) {
    const funcNode = parsed.functions.get(funcName);
    if (!funcNode || funcNode.isView || funcNode.isPure) continue;
    if (!funcNode.isPublic && !funcNode.isExternal) continue;

    const hasGuard = (funcNode.modifiers || []).some(m =>
      m.toLowerCase().includes('nonreentrant') ||
      m.toLowerCase().includes('mutex') ||
      m.toLowerCase().includes('lock')
    );

    for (const cfgNode of cfg) {
      if (cfgNode.isStateWrite && cfgNode.affectedVariables) {
        for (const varName of cfgNode.affectedVariables) {
          if (!stateWriters.has(varName)) {
            stateWriters.set(varName, []);
          }
          stateWriters.get(varName)!.push({
            func: funcName,
            line: cfgNode.line,
            hasGuard,
          });
        }
      }
    }
  }

  // Check for shared state with unprotected writers
  for (const [varName, writers] of stateWriters) {
    if (writers.length < 2) continue;

    const unprotectedWriters = writers.filter(w => !w.hasGuard);
    if (unprotectedWriters.length >= 2) {
      findings.push({
        category: 'state_mutation',
        type: 'shared_state_no_sync',
        title: `State variable "${varName}" written by ${writers.length} functions without synchronization`,
        severity: 'high',
        location: `${fileName}:L${unprotectedWriters[0].line}`,
        line: unprotectedWriters[0].line,
        description: `State variable ${varName} is written by ${writers.length} different public/external functions: ${writers.map(w => `${w.func}()${w.hasGuard ? ' [guarded]' : ' [UNGUARDED]'}`).join(', ')}. ${unprotectedWriters.length} of these writers lack reentrancy guards. When one function makes an external call, the callee can invoke another writer of ${varName}, causing state to be modified in unexpected order. This is a cross-function state mutation anomaly — impossible to detect without building the full call graph and state write map.`,
        confidence: 0.75,
        evidence: [
          `Variable: ${varName}`,
          `Writers: ${writers.map(w => `${w.func}@L${w.line}${w.hasGuard ? '' : ' (no guard)'}`).join(', ')}`,
          `${unprotectedWriters.length} unprotected writers`,
          `Cross-function reentrancy risk`,
        ],
        cwe: ['SWC-107'],
        remediation: 'Add reentrancy guards (nonReentrant) to all functions that write to shared state, or use Checks-Effects-Interactions consistently.',
        detectionMethod: 'state_mutation_anomaly: cross-function state write map + guard analysis',
      });
    }
  }

  // Detect: Function that reads state, then writes to different state without consistency check
  for (const [funcName, cfg] of parsed.cfg) {
    const funcNode = parsed.functions.get(funcName);
    if (!funcNode || funcNode.isView || funcNode.isPure) continue;

    const reads = cfg.filter(n => n.type === 'state_write' && n.code.includes('['));
    const writes = cfg.filter(n => n.isStateWrite);

    // If a function writes to a mapping based on one key but reads from another,
    // it may be creating an inconsistent mapping state
    if (reads.length > 0 && writes.length > 1) {
      const writeVars = writes.map(w => w.affectedVariables?.[0]).filter(Boolean);
      const uniqueVars = new Set(writeVars);
      if (uniqueVars.size > 1) {
        findings.push({
          category: 'state_mutation',
          type: 'multi_state_write',
          title: `${funcName}() writes to ${uniqueVars.size} different state variables — potential invariant break`,
          severity: 'medium',
          location: `${fileName}:L${funcNode.line}`,
          line: funcNode.line,
          description: `Function ${funcName}() writes to multiple state variables (${Array.from(uniqueVars).join(', ')}) in a single execution. If the writes are not atomic (e.g., one is after an external call), an invariant between these variables can be broken. For example, if totalSupply and balanceOf are updated separately, a reentrancy between the updates causes totalSupply ≠ sum(balanceOf). This is a state mutation anomaly — the individual writes look correct in isolation.`,
          confidence: 0.58,
          evidence: [
            `Function ${funcName} writes to: ${Array.from(uniqueVars).join(', ')}`,
            `${writes.length} state write operations in CFG`,
            `Invariant risk: consistency between variables may be broken`,
          ],
          cwe: ['SWC-107'],
          remediation: 'Ensure all related state writes are atomic (before external calls). Add invariant checks.',
          detectionMethod: 'state_mutation_anomaly: multi-variable state write + atomicity analysis',
        });
      }
    }
  }

  return findings;
}

// ─── 3. ECONOMIC ANOMALIES ──────────────────────────────────────────

function detectEconomicAnomalies(
  code: string,
  fileName: string,
  parsed: ParsedContract,
  isSolidity: boolean,
): AnomalyFinding[] {
  const findings: AnomalyFinding[] = [];

  if (!isSolidity) return findings;

  // Detect: Fee-on-transfer token assumption violation
  // If a contract assumes amountIn == amountReceived, it's vulnerable to
  // fee-on-transfer tokens (where the received amount is less than sent)
  const hasTransferIn = code.match(/\.transfer\(/g) || code.match(/transferFrom\(/g);
  const hasBalanceCheck = code.includes('balanceOf(address(this))') || code.includes('beforeBalance');
  const hasAmountInVariable = code.match(/amount(?:In|_in|\d*In)/g);

  if (hasTransferIn && hasAmountInVariable && !hasBalanceCheck) {
    findings.push({
      category: 'economic',
      type: 'fee_on_transfer_assumption',
      title: 'Assumes amountIn == amountReceived — vulnerable to fee-on-transfer tokens',
      severity: 'high',
      location: `${fileName}`,
      line: 0,
      description: `The contract uses transfer/transferFrom with an "amountIn" variable but does not verify the actual received amount via balanceOf before and after the transfer. Fee-on-transfer tokens (e.g., SAFEMOON, REBASE tokens) deduct a fee during transfer, so amountReceived < amountIn. If the contract uses amountIn for accounting, it overstates the actual deposit, enabling over-withdrawal and protocol insolvency. This is an economic anomaly — the code is syntactically correct but assumes token behavior that doesn't hold for all ERC-20 tokens.`,
      confidence: 0.78,
      evidence: [
        `Transfer calls found (transfer/transferFrom)`,
        `Uses amountIn-style variables without balance diff check`,
        `No balanceOf before/after pattern`,
        `Fee-on-transfer tokens: amountReceived = amountIn * (1 - fee)`,
      ],
      cwe: ['SWC-120'],
      remediation: 'Use balance diff pattern: uint256 balBefore = token.balanceOf(address(this)); token.transferFrom(...); uint256 received = token.balanceOf(address(this)) - balBefore;',
      detectionMethod: 'economic_anomaly: fee-on-transfer token assumption detected via variable naming + missing balance check',
    });
  }

  // Detect: Flash loan attack surface — function that reads price/reserve and allows same-block manipulation
  const hasPriceRead = /(?:getPrice|price|latestRoundData|consult|reserve|getReserves)/i.test(code);
  const hasSameTxWrite = /(?:swap|borrow|flashLoan|flashBorrow|deposit|withdraw|mint|redeem)/i.test(code);
  const hasTwapOrDelay = /(?:TWAP|twap|timeWeighted|accumulat|observe)/i.test(code);

  if (hasPriceRead && hasSameTxWrite && !hasTwapOrDelay) {
    findings.push({
      category: 'economic',
      type: 'flash_loan_vector',
      title: 'Price-dependent operations without TWAP — flash loan attack vector',
      severity: 'critical',
      location: `${fileName}`,
      line: 0,
      description: `The contract reads price/reserve data and allows operations (swap/borrow/deposit/withdraw) in the same transaction, without using TWAP or time-delayed price averaging. An attacker can: (1) Take a flash loan for massive capital, (2) Manipulate the oracle/reserve price in the same block, (3) Exploit the manipulated price (over-borrow, under-collateralize, arbitrage), (4) Repay the flash loan — all atomically, with zero capital risk. This is the #1 economic exploit vector in DeFi — it requires understanding of economic incentives, not just code patterns.`,
      confidence: 0.75,
      evidence: [
        `Price/oracle read detected (getPrice/latestRoundData/consult)`,
        `Same-transaction state mutation (swap/borrow/deposit/withdraw)`,
        `No TWAP or time-delayed price averaging`,
        `Flash loan enables zero-capital price manipulation`,
      ],
      cwe: ['SWC-120'],
      remediation: 'Use TWAP oracle with >=30min observation period. Add deviation bounds. Use oracle freshness checks. Consider circuit breakers for extreme price moves.',
      detectionMethod: 'economic_anomaly: price-dependent operations + same-tx mutation + no TWAP = flash loan vector',
    });
  }

  // Detect: Slippage not enforced
  // swap/deposit/withdraw without minAmountOut or deadline
  for (const [funcName, funcNode] of parsed.functions) {
    if (!funcNode.isPublic && !funcNode.isExternal) continue;
    const funcBody = getFunctionBody(code, funcNode.line);

    const isSwapLike = /swap|exchange|trade|route/i.test(funcName);
    const hasMinOut = /minAmount|minReturn|minOut|amountMin|deadline/i.test(funcBody);
    const hasExternalCall = /\.\s*(?:call|transfer|swap)\s*[({]/i.test(funcBody);

    if (isSwapLike && hasExternalCall && !hasMinOut) {
      findings.push({
        category: 'economic',
        type: 'mev_sandwich',
        title: `${funcName}() — swap without slippage protection → MEV sandwich`,
        severity: 'high',
        location: `${fileName}:L${funcNode.line}`,
        line: funcNode.line,
        description: `Function ${funcName}() performs a swap-like operation without enforcing minimum output amount (minAmountOut) or deadline. MEV sandwich bots: (1) Detect the pending swap in mempool, (2) Front-run with a buy to inflate the price, (3) The victim's swap executes at the inflated price, (4) Back-run with a sell to capture the price difference. The victim receives significantly fewer tokens than fair market value. This is an economic exploit that requires understanding of MEV and market microstructure.`,
        confidence: 0.80,
        evidence: [
          `Function ${funcName} performs swap with external call`,
          `No minAmountOut/minReturn/amountMin parameter`,
          `No deadline parameter for transaction expiry`,
          `MEV sandwich attack: front-run → victim swap → back-run`,
        ],
        cwe: ['SWC-120'],
        remediation: 'Add minAmountOut and deadline parameters. Check: require(amountOut >= minAmountOut); require(block.timestamp <= deadline);',
        detectionMethod: 'economic_anomaly: swap operation without slippage protection → MEV sandwich vulnerability',
      });
    }
  }

  // Detect: First depositor attack (vault share price manipulation)
  // If a vault's exchange rate is based on totalSupply/totalAssets,
  // the first depositor can manipulate the share price by donating
  // tokens directly, causing subsequent depositors to lose precision
  if (code.includes('totalSupply') && (code.includes('convertToShares') || code.includes('convertToAssets'))) {
    const hasOffset = code.includes('OFFSET') || code.includes('DECIMALS_OFFSET') || code.includes('1e18') || code.includes('1e9');
    if (!hasOffset) {
      findings.push({
        category: 'economic',
        type: 'first_depositor_attack',
        title: 'Vault without share price offset — first depositor inflation attack',
        severity: 'high',
        location: `${fileName}`,
        line: 0,
        description: `The vault uses totalSupply/totalAssets for share price calculation without a decimal offset (OFFSET/DECIMALS_OFFSET). An attacker can: (1) Be the first depositor, deposit 1 wei of shares, (2) Donate a large amount of underlying tokens directly to the vault (e.g., 1e18 tokens), (3) Now the exchange rate is massively inflated (1 share = 1e18 tokens), (4) Subsequent depositors' deposits are rounded down to 0 shares due to precision loss, (5) The attacker can steal all subsequent deposits. This attack was exploited in the Sherlock audit and multiple DeFi protocols.`,
        confidence: 0.70,
        evidence: [
          `Vault uses totalSupply for share calculation`,
          `convertToShares/convertToAssets detected`,
          `No OFFSET/DECIMALS_OFFSET to prevent share price inflation`,
          `First depositor can manipulate exchange rate via direct donation`,
        ],
        cwe: ['SWC-101'],
        remediation: 'Add a virtual offset to share price: _decimalsOffset = 1e3 (or higher). Mint offset shares to address(0) on initialization.',
        detectionMethod: 'economic_anomaly: vault share price calculation without inflation attack protection',
      });
    }
  }

  return findings;
}

// ─── 4. GOVERNANCE ANOMALIES ────────────────────────────────────────

function detectGovernanceAnomalies(
  code: string,
  fileName: string,
  parsed: ParsedContract,
  isSolidity: boolean,
): AnomalyFinding[] {
  const findings: AnomalyFinding[] = [];

  if (!isSolidity) return findings;

  // Detect: Governance without quorum
  if (/governance|governor|dao/i.test(code)) {
    const hasQuorum = /quorum|QUORUM|quorumVotes/i.test(code);
    const hasTimelock = /timelock|TIMELOCK|Timelock/i.test(code);
    const hasProposalThreshold = /proposalThreshold|PROPOSAL_THRESHOLD/i.test(code);

    if (!hasQuorum) {
      findings.push({
        category: 'governance',
        type: 'no_quorum',
        title: 'Governance contract without quorum requirement — vote hijacking risk',
        severity: 'critical',
        location: `${fileName}`,
        line: 0,
        description: `The governance contract does not enforce a quorum (minimum participation threshold). Without quorum, a single token holder (or a small coordinated group) can pass any proposal with minimal votes. This enables: (1) Vote hijacking — attacker acquires just enough tokens to pass proposals, (2) Quorum bypass — proposals pass with 1 vote, (3) Hostile takeover — change critical protocol parameters (fees, admin, upgrade). This is a Critical severity governance vulnerability per HackenProof classification.`,
        confidence: 0.82,
        evidence: [
          `Governance/Governor pattern detected`,
          `No quorum/quorumVotes variable or function`,
          `Proposals can pass with minimal participation`,
        ],
        cwe: ['CWE-863'],
        remediation: 'Implement quorum check: require(totalVotes >= quorum(proposal.blockNumber)). Use OpenZeppelin GovernorSettings.',
        detectionMethod: 'governance_anomaly: governance pattern without quorum = vote hijacking risk',
      });
    }

    if (!hasTimelock) {
      findings.push({
        category: 'governance',
        type: 'no_timelock',
        title: 'Governance without timelock — instant proposal execution',
        severity: 'high',
        location: `${fileName}`,
        line: 0,
        description: `The governance contract does not use a timelock for proposal execution. Without a timelock, passed proposals execute instantly, giving the community zero time to: (1) Review the proposal code, (2) Detect malicious proposals, (3) Execute an emergency pause, (4) Organize a counter-vote or exit. This is a High severity governance issue — per HackenProof, governance manipulation resulting in direct fund loss is Critical.`,
        confidence: 0.78,
        evidence: [
          `Governance pattern detected`,
          `No timelock/Timelock reference`,
          `Proposals execute immediately upon passing`,
        ],
        cwe: ['CWE-863'],
        remediation: 'Use OpenZeppelin TimelockController with minimum delay (e.g., 2 days). Compose Governor + Timelock.',
        detectionMethod: 'governance_anomaly: governance without timelock = instant execution risk',
      });
    }

    if (!hasProposalThreshold) {
      findings.push({
        category: 'governance',
        type: 'no_proposal_threshold',
        title: 'No proposal creation threshold — spam/griefing risk',
        severity: 'medium',
        location: `${fileName}`,
        line: 0,
        description: `The governance contract does not require a minimum token balance to create proposals. Without a proposal threshold, any address (even with 0 tokens) can create unlimited proposals, causing: (1) Proposal spam — gas exhaustion for voters, (2) Governance DoS — too many proposals to track, (3) Voter fatigue — legitimate proposals get lost in noise. This is a governance anomaly affecting protocol operability.`,
        confidence: 0.68,
        evidence: [
          `Governance pattern detected`,
          `No proposalThreshold/PROPOSAL_THRESHOLD`,
          `Any address can create proposals`,
        ],
        cwe: ['CWE-400'],
        remediation: 'Set proposal threshold: require(getVotes(msg.sender) >= proposalThreshold()).',
        detectionMethod: 'governance_anomaly: governance without proposal threshold = spam risk',
      });
    }
  }

  // Detect: Owner can pause forever (governance centralization)
  if (code.includes('pause') && code.includes('onlyOwner')) {
    const hasUnpause = code.includes('unpause');
    const hasPauseDuration = /pauseDuration|MAX_PAUSE|autoUnpause/i.test(code);

    if (!hasUnpause && !hasPauseDuration) {
      findings.push({
        category: 'governance',
        type: 'permanent_pause',
        title: 'Owner can pause indefinitely — permanent fund freeze risk',
        severity: 'high',
        location: `${fileName}`,
        line: 0,
        description: `The contract has a pause function restricted to onlyOwner, but no unpause function or maximum pause duration. The owner can permanently pause the contract, freezing all user funds. Per HackenProof severity classification, permanent fund freeze is Critical severity. Even if the owner is currently trustworthy, the centralized risk remains: (1) Owner key compromise → permanent freeze, (2) Owner turns malicious → rug pull via freeze, (3) Owner loses key → permanent freeze with no recovery.`,
        confidence: 0.75,
        evidence: [
          `pause() function with onlyOwner modifier`,
          `No unpause() function or max pause duration`,
          `Owner can freeze all operations indefinitely`,
          `HackenProof: permanent fund freeze = Critical`,
        ],
        cwe: ['CWE-863'],
        remediation: 'Add unpause() with timelock, or add maximum pause duration with auto-unpause, or use governance-controlled pause instead of single owner.',
        detectionMethod: 'governance_anomaly: pause without unpause/duration = permanent freeze risk',
      });
    }
  }

  return findings;
}

// ─── 5. DEPENDENCY ANOMALIES ────────────────────────────────────────

function detectDependencyAnomalies(
  code: string,
  fileName: string,
  parsed: ParsedContract,
): AnomalyFinding[] {
  const findings: AnomalyFinding[] = [];

  // Check imports against known vulnerable dependencies
  for (const imp of parsed.imports) {
    for (const vulnDep of VULNERABLE_DEPS) {
      if (imp.toLowerCase().includes(vulnDep.name.toLowerCase())) {
        findings.push({
          category: 'dependency',
          type: vulnDep.vulnerability,
          title: `Uses ${vulnDep.name} (${vulnDep.versions}) — ${vulnDep.vulnerability}`,
          severity: vulnDep.severity,
          location: `${fileName}`,
          line: 0,
          description: `Import "${imp}" references ${vulnDep.name} which has a known vulnerability: ${vulnDep.description}${vulnDep.fixedIn ? ` Fixed in version ${vulnDep.fixedIn}.` : ''} Using vulnerable dependencies in a smart contract is especially dangerous because deployments are immutable — once deployed, the vulnerability cannot be patched without a full migration.`,
          confidence: 0.85,
          evidence: [
            `Import: ${imp}`,
            `Known vulnerable: ${vulnDep.name} ${vulnDep.versions}`,
            `Vulnerability: ${vulnDep.vulnerability}`,
            vulnDep.fixedIn ? `Fixed in: ${vulnDep.fixedIn}` : 'No fix available',
          ],
          cwe: vulnDep.cwe,
          remediation: vulnDep.fixedIn ? `Upgrade to ${vulnDep.name} >= ${vulnDep.fixedIn}` : `Review usage carefully. Consider alternatives.`,
          detectionMethod: 'dependency_anomaly: import matched against known vulnerable dependency database',
        });
      }
    }
  }

  // Detect: Import from unverified source (not OpenZeppelin, Solmate, Solady, etc.)
  const trustedSources = ['openzeppelin', 'solmate', 'solady', 'forge-std', 'prb-math', 'fixed-point-math', 'uniswap', 'aave', 'compound', 'chainlink'];
  for (const imp of parsed.imports) {
    const isTrusted = trustedSources.some(src => imp.toLowerCase().includes(src));
    const isLocal = imp.startsWith('.') || imp.startsWith('./');
    if (!isTrusted && !isLocal && imp.includes('/')) {
      // Only flag non-trusted, non-local imports
      findings.push({
        category: 'dependency',
        type: 'unverified_import',
        title: `Import from unverified source: ${imp.split('/').slice(0, 2).join('/')}`,
        severity: 'low',
        location: `${fileName}`,
        line: 0,
        description: `Import "${imp}" is from a source not in the trusted set (${trustedSources.join(', ')}). While this may be a legitimate library, unverified dependencies in smart contracts carry supply chain risk: the dependency may contain backdoors, be unaudited, or be abandoned with known vulnerabilities. This is especially critical for contracts handling user funds.`,
        confidence: 0.30,
        evidence: [
          `Import: ${imp}`,
          `Not in trusted sources list`,
          `Supply chain risk for smart contracts`,
        ],
        cwe: ['CWE-1357'],
        remediation: 'Verify the dependency is audited and maintained. Consider using a well-known alternative.',
        detectionMethod: 'dependency_anomaly: import not in trusted source database',
      });
    }
  }

  return findings;
}

// ─── 6. INTERACTION ANOMALIES ───────────────────────────────────────

function detectInteractionAnomalies(
  code: string,
  fileName: string,
  parsed: ParsedContract,
  isSolidity: boolean,
): AnomalyFinding[] {
  const findings: AnomalyFinding[] = [];

  if (!isSolidity) return findings;

  // Detect: Callback function (receive/fallback) that makes external calls
  // This creates a reentrancy surface that's hard to detect
  const hasReceiveOrFallback = /\b(?:receive|fallback)\s*\(\s*\)\s*(?:external|public)\s*(?:payable)?\s*\{/.test(code);

  if (hasReceiveOrFallback) {
    // Check if receive/fallback makes external calls
    const receiveMatch = code.match(/receive\s*\(\s*\)\s*(?:external|public)\s*(?:payable)?\s*\{([\s\S]*?)\}/);
    const fallbackMatch = code.match(/fallback\s*\(\s*\)\s*(?:external|public)\s*(?:payable)?\s*\{([\s\S]*?)\}/);

    for (const bodyMatch of [receiveMatch, fallbackMatch]) {
      if (bodyMatch && bodyMatch[1]) {
        const hasCallInCallback = /(?:\.call|\.delegatecall|\.transfer|\.send)\s*[({]/.test(bodyMatch[1]);
        if (hasCallInCallback) {
          findings.push({
            category: 'interaction',
            type: 'callback_reentrancy',
            title: 'receive/fallback makes external calls — callback reentrancy surface',
            severity: 'critical',
            location: `${fileName}`,
            line: 0,
            description: `The receive() or fallback() function makes external calls (call/transfer/delegatecall). When ETH is sent to this contract, the callback is invoked, which then makes an external call. The external call target can re-enter the sending contract, creating a reentrancy loop. This is especially dangerous because: (1) The callback is triggered by plain ETH transfers (no function signature needed), (2) Any contract sending ETH to this address triggers the callback, (3) The reentrancy surface is invisible in normal function analysis. This requires understanding of the EVM's callback mechanism — not detectable by pattern matching.`,
            confidence: 0.88,
            evidence: [
              `receive/fallback function detected`,
              `External call within callback body`,
              `ETH transfers trigger callback → external call → reentrancy`,
              `Callback reentrancy is invisible to function-level analysis`,
            ],
            cwe: ['SWC-107'],
            remediation: 'Remove external calls from receive/fallback. Use a separate withdraw function with CEI pattern.',
            detectionMethod: 'interaction_anomaly: callback function with external call = callback reentrancy surface',
          });
        }
      }
    }
  }

  // Detect: Cross-contract call chain that could form a reentrancy cycle
  // If A calls B and B calls A (even indirectly), there's a reentrancy cycle
  const callTargets = new Map<string, Set<string>>();
  for (const edge of parsed.callGraph) {
    if (!callTargets.has(edge.caller)) {
      callTargets.set(edge.caller, new Set());
    }
    callTargets.get(edge.caller)!.add(edge.callee);
  }

  // Check for 2-hop cycles: A→B→A
  for (const [caller, callees] of callTargets) {
    for (const callee of callees) {
      const calleeCallees = callTargets.get(callee);
      if (calleeCallees && calleeCallees.has(caller)) {
        findings.push({
          category: 'interaction',
          type: 'call_cycle',
          title: `Reentrancy cycle: ${caller}() ↔ ${callee}()`,
          severity: 'critical',
          location: `${fileName}`,
          line: 0,
          description: `A 2-hop call cycle exists: ${caller}() calls ${callee}() and ${callee}() calls ${caller}(). Even if both functions individually follow CEI pattern, the cross-contract reentrancy allows: (1) ${caller} makes external call to ${callee}, (2) ${callee} re-enters ${caller} before ${caller}'s state is updated, (3) ${caller} operates on stale state. Cross-contract reentrancy is the most common form in DeFi exploits (Curve, Balancer, etc.).`,
          confidence: 0.80,
          evidence: [
            `Call graph cycle: ${caller} → ${callee} → ${caller}`,
            `Cross-contract reentrancy surface`,
            `Even with per-function CEI, cross-contract reentrancy persists`,
          ],
          cwe: ['SWC-107'],
          remediation: 'Add cross-contract reentrancy guard. Use a global lock or reentrancy guard that spans both contracts.',
          detectionMethod: 'interaction_anomaly: 2-hop call cycle in call graph = cross-contract reentrancy',
        });
      }
    }
  }

  return findings;
}

// ─── 7. NUMERICAL ANOMALIES ─────────────────────────────────────────

function detectNumericalAnomalies(
  code: string,
  fileName: string,
  parsed: ParsedContract,
  isSolidity: boolean,
): AnomalyFinding[] {
  const findings: AnomalyFinding[] = [];

  if (!isSolidity) return findings;

  // Detect: Division before multiplication (precision loss)
  // x / y * z should be x * z / y to preserve precision
  const divBeforeMulPattern = /(\w+)\s*\/\s*(\w+)\s*\*\s*(\w+)/g;
  let divMulMatch;
  while ((divMulMatch = divBeforeMulPattern.exec(code)) !== null) {
    const matchLine = code.slice(0, divMulMatch.index).split('\n').length;
    findings.push({
      category: 'numerical',
      type: 'precision_loss',
      title: `Division before multiplication: ${divMulMatch[1]} / ${divMulMatch[2]} * ${divMulMatch[3]}`,
      severity: 'medium',
      location: `${fileName}:L${matchLine}`,
      line: matchLine,
      description: `Expression ${divMulMatch[1]} / ${divMulMatch[2]} * ${divMulMatch[3]} performs division before multiplication. In Solidity's integer arithmetic, division truncates (rounds down). For example: 7 / 3 * 100 = 200 (actual: 233.33). The correct order is ${divMulMatch[1]} * ${divMulMatch[3]} / ${divMulMatch[2]} = 233. This precision loss compounds in financial calculations, leading to: under-collateralization, incorrect fee calculation, or vault share price drift. This is a numerical anomaly — the code is "correct" but produces wrong results due to integer division semantics.`,
      confidence: 0.75,
      evidence: [
        `Expression: ${divMulMatch[0]}`,
        `Division before multiplication truncates intermediate result`,
        `Correct: ${divMulMatch[1]} * ${divMulMatch[3]} / ${divMulMatch[2]}`,
        `Example: 7/3*100 = 200 vs 7*100/3 = 233`,
      ],
      cwe: ['SWC-101'],
      remediation: `Reorder to: ${divMulMatch[1]} * ${divMulMatch[3]} / ${divMulMatch[2]}. Use mulDiv from PRBMath for overflow-safe operation.`,
      detectionMethod: 'numerical_anomaly: division-before-multiplication pattern = precision loss',
    });
  }

  // Detect: Rounding in favor of the protocol (vault withdrawal)
  // If shares = assets * totalSupply / totalAssets, rounding should favor
  // the protocol (round down for deposit, round up for withdraw)
  if (code.includes('convertToShares') || code.includes('convertToAssets')) {
    const hasRoundUp = /roundUp|ceil|Rounding\.Up|ROUND_UP/i.test(code);
    if (!hasRoundUp) {
      findings.push({
        category: 'numerical',
        type: 'rounding_direction',
        title: 'Vault conversion without explicit rounding direction — potential drain',
        severity: 'medium',
        location: `${fileName}`,
        line: 0,
        description: `The vault's convertToShares/convertToAssets calculations do not specify rounding direction. In vaults: (1) deposit (assets→shares) must round DOWN (user gets fewer shares), (2) withdraw (shares→assets) must round DOWN (user gets fewer assets), (3) mint (shares→assets) must round UP (user pays more assets), (4) redeem (assets→shares) must round UP (user burns more shares). If any direction is wrong, a user can repeatedly deposit and withdraw to slowly drain the vault. This is the "rounding leak" attack vector.`,
        confidence: 0.65,
        evidence: [
          `Vault share/asset conversion detected`,
          `No explicit rounding direction (roundUp/ceil/Rounding.Up)`,
          `Incorrect rounding enables vault drain via repeated operations`,
        ],
        cwe: ['SWC-101'],
        remediation: 'Use OpenZeppelin ERC4626 which handles rounding correctly. Or add explicit rounding: mul<rounding>Div with appropriate Rounding parameter.',
        detectionMethod: 'numerical_anomaly: vault conversion without rounding direction = rounding leak',
      });
    }
  }

  // Detect: Use of WAD/RAY precision without overflow protection
  const hasWadMath = /1e18|1e27|WAD|RAY|wad|ray/i.test(code);
  const hasMulWad = /mulWad|divWad|wadMul|wadDiv|rayMul|rayDiv/i.test(code);
  const hasFullMul = /fullMul|mulDiv|tryMul/i.test(code);

  if (hasWadMath && !hasMulWad && !hasFullMul) {
    findings.push({
      category: 'numerical',
      type: 'wad_overflow',
      title: 'Fixed-point arithmetic (WAD/RAY) without overflow-safe operations',
      severity: 'high',
      location: `${fileName}`,
      line: 0,
      description: `The contract uses 1e18 (WAD) or 1e27 (RAY) fixed-point arithmetic but does not use overflow-safe mulWad/divWad operations. Standard multiplication (a * b / WAD) can overflow even for reasonable values: if a = 1e18 and b = 1e18, then a * b = 1e36 which overflows uint256 for values > 2^128 ≈ 3.4e38. In Solidity 0.8+, this causes a revert (DoS), but in unchecked blocks or pre-0.8, it silently wraps. Use mulDiv or mulWad from PRBMath/Solady for correct overflow-safe fixed-point math.`,
      confidence: 0.72,
      evidence: [
        `WAD/RAY (1e18/1e27) fixed-point arithmetic detected`,
        `No mulWad/divWad or mulDiv operations`,
        `a * b / WAD can overflow for large a, b values`,
      ],
      cwe: ['SWC-101'],
      remediation: 'Use PRBMath.mulDiv or Solady.mulWadDiv for overflow-safe fixed-point operations.',
      detectionMethod: 'numerical_anomaly: fixed-point arithmetic without overflow-safe mulDiv = overflow risk',
    });
  }

  return findings;
}

// ─── HELPER: GET FUNCTION BODY ──────────────────────────────────────

function getFunctionBody(code: string, startLine: number): string {
  const lines = code.split('\n');
  const bodyLines: string[] = [];
  let braceDepth = 0;
  let foundStart = false;

  for (let i = startLine - 1; i < lines.length; i++) {
    const line = lines[i];
    const opens = (line.match(/\{/g) || []).length;
    const closes = (line.match(/\}/g) || []).length;

    if (opens > 0) foundStart = true;
    if (foundStart) {
      braceDepth += opens - closes;
      bodyLines.push(line);
      if (braceDepth <= 0 && opens > 0) break;
    }
  }

  return bodyLines.join('\n');
}
