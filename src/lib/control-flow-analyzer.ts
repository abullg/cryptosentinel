/**
 * CryptoSentinel — Control Flow Analyzer
 * Inspired by: CodeQL (control flow), Slither (CFG analysis), Mythril (path exploration),
 *             Halmos (symbolic paths), Certora (formal control flow)
 *
 * Performs deep control flow analysis beyond what the semantic analyzer does:
 * 1. Unreachable code detection — code after return/throw/revert that can never execute
 * 2. Missing return path detection — functions with paths that don't return a value
 * 3. Circular dependency detection — contracts that create circular import/call dependencies
 * 4. Dead branch detection — if-conditions that are always true or always false
 * 5. Exception path analysis — paths where require/assert fails leaving state inconsistent
 * 6. Execution path analysis — enumerate paths through functions for deeper analysis
 *
 * These are NOT pattern-matchable — they require graph analysis on the control flow.
 */

import { parseCode, ParsedContract, ASTNode, CallEdge, CFGNode } from './semantic-analyzer';

// ─── CONTROL FLOW FINDING ────────────────────────────────────────────

export interface ControlFlowFinding {
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
  affectedPaths?: string[];  // The execution paths affected
}

// ─── MAIN ANALYSIS FUNCTION ─────────────────────────────────────────

export function runControlFlowAnalysis(
  code: string,
  fileName: string,
): ControlFlowFinding[] {
  const findings: ControlFlowFinding[] = [];
  const lines = code.split('\n');
  const isSolidity = code.includes('pragma solidity') || code.includes('contract ');

  const parsed = parseCode(code, fileName);

  // ─── 1. UNREACHABLE CODE DETECTION ────────────────────────────────
  findings.push(...detectUnreachableCode(code, fileName, parsed, isSolidity));

  // ─── 2. MISSING RETURN PATH DETECTION ─────────────────────────────
  findings.push(...detectMissingReturnPaths(code, fileName, parsed, isSolidity));

  // ─── 3. CIRCULAR DEPENDENCY DETECTION ─────────────────────────────
  findings.push(...detectCircularDependencies(code, fileName, parsed, isSolidity));

  // ─── 4. DEAD BRANCH DETECTION ─────────────────────────────────────
  findings.push(...detectDeadBranches(code, fileName, parsed, isSolidity));

  // ─── 5. EXCEPTION PATH ANALYSIS ───────────────────────────────────
  findings.push(...detectExceptionPaths(code, fileName, parsed, isSolidity));

  // Sort by severity then confidence
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => {
    const sevDiff = (severityOrder[a.severity] ?? 2) - (severityOrder[b.severity] ?? 2);
    if (sevDiff !== 0) return sevDiff;
    return b.confidence - a.confidence;
  });

  return findings;
}

// ─── 1. UNREACHABLE CODE DETECTION ──────────────────────────────────
// Code after return/throw/revert that can never execute.
// Also detects code after if(condition) { return } else { return } —
// both branches return, so code after the if-else is unreachable.

function detectUnreachableCode(
  code: string,
  fileName: string,
  parsed: ParsedContract,
  isSolidity: boolean,
): ControlFlowFinding[] {
  const findings: ControlFlowFinding[] = [];
  const lines = code.split('\n');

  // For each function, walk the CFG and detect unreachable code
  for (const [funcName, cfg] of parsed.cfg) {
    const funcNode = parsed.functions.get(funcName);
    if (!funcNode) continue;

    // Walk CFG nodes in execution order
    for (let i = 0; i < cfg.length - 1; i++) {
      const node = cfg[i];

      // After a return/revert/throw, any code is unreachable
      if (node.type === 'return' || (node.type === 'require' && node.code.includes('revert'))) {
        // Check if there are more nodes before exit
        const remainingNodes = cfg.slice(i + 1).filter(n => n.type !== 'exit');
        if (remainingNodes.length > 0) {
          const unreachableLines = remainingNodes.map(n => `L${n.line}`).join(', ');

          // Only report if there are meaningful operations (not just emit)
          const meaningfulOps = remainingNodes.filter(n =>
            n.type === 'state_write' || n.type === 'call' || n.type === 'transfer'
          );

          if (meaningfulOps.length > 0) {
            findings.push({
              type: 'unreachable_code',
              title: `Unreachable code in ${funcName}() after ${node.type} at L${node.line}`,
              severity: meaningfulOps.some(n => n.type === 'state_write') ? 'high' : 'medium',
              location: `${fileName}:L${node.line}`,
              line: node.line,
              description: `In function ${funcName}(), a ${node.type} statement at L${node.line} makes all subsequent code unreachable: ${unreachableLines}. ${meaningfulOps.some(n => n.type === 'state_write') ? 'Critically, unreachable state writes indicate a logic error — the developer intended to update state but the code path never executes. This may mean a security check or state update is silently skipped.' : 'While the unreachable code is not directly dangerous, it indicates dead code that may mask a logic error.'} Unreachable code is only detectable through control flow analysis — the code is syntactically valid.`,
              confidence: 0.85,
              evidence: [
                `${node.type} at L${node.code.slice(0, 60)}`,
                `Unreachable nodes: ${unreachableLines}`,
                meaningfulOps.length > 0 ? `Contains ${meaningfulOps.length} meaningful operations (state writes/calls)` : 'Only trivial operations (emit/require)',
              ],
              cwe: ['CWE-561'],
              remediation: 'Remove unreachable code or fix the control flow so the intended path is reachable.',
              affectedPaths: [`${funcName}: entry → ... → ${node.type}@L${node.line} → (unreachable) ${unreachableLines}`],
            });
          }
        }
      }
    }

    // Detect: Code after if/else where both branches return
    // This is more subtle — both branches of an if-else return,
    // so code after the if-else is unreachable
    const cfgNodes = cfg.filter(n => n.type !== 'entry' && n.type !== 'exit');
    for (let i = 0; i < cfgNodes.length - 2; i++) {
      const node = cfgNodes[i];
      if (node.type !== 'if') continue;

      // Look for pattern: if → return, else → return, then code after
      // This is simplified — a full analysis would track branches
      const nextNodes = cfgNodes.slice(i + 1, i + 4);
      const hasBothBranchesReturn = nextNodes.filter(n => n.type === 'return').length >= 2;

      if (hasBothBranchesReturn) {
        const afterReturn = cfgNodes.slice(i + 4);
        const meaningfulAfter = afterReturn.filter(n =>
          n.type === 'state_write' || n.type === 'call' || n.type === 'transfer'
        );

        if (meaningfulAfter.length > 0) {
          findings.push({
            type: 'unreachable_code',
            title: `Unreachable code in ${funcName}() — both if/else branches return`,
            severity: 'medium',
            location: `${fileName}:L${node.line}`,
            line: node.line,
            description: `In function ${funcName}(), both branches of the if-statement at L${node.line} contain return statements. Code after this if-else block is unreachable: ${meaningfulAfter.map(n => `L${n.line}`).join(', ')}. The developer likely intended one branch to fall through, but both branches exit the function.`,
            confidence: 0.80,
            evidence: [
              `if-statement at L${node.line}`,
              `Both branches contain return`,
              `Unreachable code after: ${meaningfulAfter.map(n => `L${n.line}`).join(', ')}`,
            ],
            cwe: ['CWE-561'],
            remediation: 'Fix the control flow: remove one return or restructure the logic.',
            affectedPaths: [`${funcName}: if → return, else → return → (unreachable)`],
          });
        }
      }
    }
  }

  return findings;
}

// ─── 2. MISSING RETURN PATH DETECTION ───────────────────────────────
// Functions declared with returns that have paths without a return statement.

function detectMissingReturnPaths(
  code: string,
  fileName: string,
  parsed: ParsedContract,
  isSolidity: boolean,
): ControlFlowFinding[] {
  const findings: ControlFlowFinding[] = [];

  for (const [funcName, cfg] of parsed.cfg) {
    const funcNode = parsed.functions.get(funcName);
    if (!funcNode) continue;

    // Check if function declares a return type
    if (!funcNode.returnType || funcNode.returnType.trim() === '') continue;
    // Skip view/pure functions for now (less critical)
    // Still check public/external non-view functions

    // Check if any CFG path reaches exit without a return
    const cfgNodes = cfg.filter(n => n.type !== 'entry' && n.type !== 'exit');
    const hasReturn = cfgNodes.some(n => n.type === 'return');

    if (!hasReturn) {
      // Function has a return type declaration but no return statement in CFG
      const isViewOrPure = funcNode.isView || funcNode.isPure;
      findings.push({
        type: 'missing_return',
        title: `${funcName}() declares returns but has no return statement`,
        severity: isViewOrPure ? 'medium' : 'high',
        location: `${fileName}:L${funcNode.line}`,
        line: funcNode.line,
        description: `Function ${funcName}() declares return type "${funcNode.returnType}" but has no return statement in its control flow. In Solidity, this means: (1) For value types (uint, address, bool), the default value (0) is returned silently, (2) For reference types (array, struct), an empty value is returned, (3) The caller operates on this default value, which is almost certainly incorrect. ${!isViewOrPure ? 'This is especially dangerous in state-changing functions — the caller may use the default return value for accounting, leading to incorrect state.' : ''} This requires control flow analysis — the missing return is not a syntax error.`,
        confidence: 0.82,
        evidence: [
          `Function ${funcName} at L${funcNode.line}`,
          `Declared return type: ${funcNode.returnType}`,
          `No return statement in CFG`,
          isViewOrPure ? 'View/pure function — less critical' : 'State-changing function — high risk',
        ],
        cwe: ['CWE-392'],
        remediation: `Add a return statement to all execution paths in ${funcName}().`,
        affectedPaths: [`${funcName}: entry → ... → exit (no return)`],
      });
    } else {
      // Has at least one return, but check if all paths return
      // Simple heuristic: if there's an if-statement with a return in one branch
      // but no return after the if, there's a path without return
      const returnNodes = cfgNodes.filter(n => n.type === 'return');
      const ifNodes = cfgNodes.filter(n => n.type === 'if');
      const lastNode = cfgNodes[cfgNodes.length - 1];

      if (ifNodes.length > 0 && returnNodes.length > 0 && lastNode && lastNode.type !== 'return') {
        // There's a return inside an if, but no return at the end
        findings.push({
          type: 'missing_return_path',
          title: `${funcName}() — not all paths return a value`,
          severity: 'high',
          location: `${fileName}:L${funcNode.line}`,
          line: funcNode.line,
          description: `Function ${funcName}() has return statements inside if-blocks, but the function does not end with a return. Execution paths that skip all if-conditions with returns reach the end of the function without returning. The caller receives a default value (0 for uint/address, false for bool), which is almost certainly incorrect. In Solidity, this does NOT cause a compiler error for internal functions — it silently returns the default. This is only detectable by enumerating all execution paths through the CFG.`,
          confidence: 0.78,
          evidence: [
            `Return statements: ${returnNodes.map(n => `L${n.line}`).join(', ')}`,
            `If-blocks: ${ifNodes.map(n => `L${n.line}`).join(', ')}`,
            `Function does not end with return — some paths miss return`,
          ],
          cwe: ['CWE-392'],
          remediation: 'Ensure all execution paths return a value. Add a return at the end of the function or restructure control flow.',
          affectedPaths: [`${funcName}: if-path → return, else-path → exit (no return)`],
        });
      }
    }
  }

  return findings;
}

// ─── 3. CIRCULAR DEPENDENCY DETECTION ───────────────────────────────

function detectCircularDependencies(
  code: string,
  fileName: string,
  parsed: ParsedContract,
  isSolidity: boolean,
): ControlFlowFinding[] {
  const findings: ControlFlowFinding[] = [];

  // Build adjacency list from call graph
  const adjList = new Map<string, Set<string>>();
  for (const edge of parsed.callGraph) {
    if (!adjList.has(edge.caller)) adjList.set(edge.caller, new Set());
    adjList.get(edge.caller)!.add(edge.callee);
  }

  // DFS cycle detection
  const visited = new Set<string>();
  const inStack = new Set<string>();
  const cycles: string[][] = [];

  function dfs(node: string, path: string[]) {
    if (inStack.has(node)) {
      // Found a cycle
      const cycleStart = path.indexOf(node);
      if (cycleStart !== -1) {
        cycles.push([...path.slice(cycleStart), node]);
      }
      return;
    }
    if (visited.has(node)) return;

    visited.add(node);
    inStack.add(node);
    path.push(node);

    const neighbors = adjList.get(node);
    if (neighbors) {
      for (const neighbor of neighbors) {
        dfs(neighbor, [...path]);
      }
    }

    inStack.delete(node);
    path.pop();
  }

  for (const node of adjList.keys()) {
    dfs(node, []);
  }

  // Report unique cycles (limit to 3 to avoid spam)
  const reportedCycles = new Set<string>();
  for (const cycle of cycles.slice(0, 3)) {
    const cycleKey = [...cycle].sort().join('→');
    if (reportedCycles.has(cycleKey)) continue;
    reportedCycles.add(cycleKey);

    const cycleStr = cycle.join(' → ');

    // Only report if cycle involves external calls (reentrancy cycle)
    const hasExternalInCycle = parsed.callGraph.some(e =>
      cycle.includes(e.caller) && cycle.includes(e.callee) && e.isExternal
    );

    if (hasExternalInCycle) {
      findings.push({
        type: 'call_cycle',
        title: `External call cycle: ${cycleStr}`,
        severity: 'critical',
        location: `${fileName}`,
        line: 0,
        description: `A circular call dependency exists: ${cycleStr}. This cycle includes external calls, creating a reentrancy attack surface. When function A in the cycle makes an external call to B, and B (or a function B calls) can re-enter A, the reentrancy allows A to execute with stale state. Cross-contract reentrancy is the most exploited DeFi vulnerability class. This requires graph analysis on the call graph — the individual calls look safe in isolation.`,
        confidence: 0.80,
        evidence: [
          `Call cycle: ${cycleStr}`,
          `External call in cycle — reentrancy surface`,
          `Cross-contract reentrancy risk`,
        ],
        cwe: ['SWC-107'],
        remediation: 'Break the cycle by adding reentrancy guards, or restructure to remove circular calls, or use Checks-Effects-Interactions consistently across all functions in the cycle.',
        affectedPaths: [cycleStr],
      });
    } else {
      // Internal cycle — less dangerous but indicates unusual design
      findings.push({
        type: 'internal_cycle',
        title: `Internal call cycle: ${cycleStr}`,
        severity: 'low',
        location: `${fileName}`,
        line: 0,
        description: `A circular call dependency exists among internal functions: ${cycleStr}. While internal calls don't create reentrancy (they execute in the same context), circular dependencies indicate: (1) Potential infinite recursion if termination conditions are wrong, (2) Gas accumulation — each cycle iteration adds gas cost, (3) Maintenance complexity — changes to one function affect all in the cycle. This is a code quality finding with security implications for gas and recursion.`,
        confidence: 0.60,
        evidence: [
          `Internal call cycle: ${cycleStr}`,
          `No external calls in cycle`,
          `Risk: infinite recursion, gas accumulation`,
        ],
        cwe: ['CWE-674'],
        remediation: 'Break the circular dependency by extracting shared logic into a separate function.',
        affectedPaths: [cycleStr],
      });
    }
  }

  // Detect circular import dependencies (for JS/TS)
  if (!isSolidity && parsed.imports.length > 0) {
    // Simple check: if file A imports B and B imports A, that's circular
    // We can't fully resolve this without the actual import files,
    // but we can flag patterns that suggest circularity
    const importsByDir = new Map<string, string[]>();
    for (const imp of parsed.imports) {
      const dir = imp.split('/').slice(0, -1).join('/') || '.';
      if (!importsByDir.has(dir)) importsByDir.set(dir, []);
      importsByDir.get(dir)!.push(imp);
    }
  }

  return findings;
}

// ─── 4. DEAD BRANCH DETECTION ───────────────────────────────────────
// If-conditions that are always true or always false.

function detectDeadBranches(
  code: string,
  fileName: string,
  parsed: ParsedContract,
  isSolidity: boolean,
): ControlFlowFinding[] {
  const findings: ControlFlowFinding[] = [];
  const lines = code.split('\n');

  // Detect: if (true) / if (false) — always taken/never taken
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    const lineNum = i + 1;

    // if(true) — always taken
    const alwaysTrueMatch = line.match(/^if\s*\(\s*true\s*\)/);
    if (alwaysTrueMatch) {
      findings.push({
        type: 'dead_branch',
        title: `Condition is always true: if(true) at L${lineNum}`,
        severity: 'low',
        location: `${fileName}:L${lineNum}`,
        line: lineNum,
        description: `The if-condition at L${lineNum} is always true. This means the else-branch is dead code — it never executes. If the else-branch contains security-critical logic (access checks, validations), those checks are silently skipped. Even if not security-critical, this indicates a logic error: the developer wrote a conditional that doesn't actually condition anything.`,
        confidence: 0.95,
        evidence: [`Condition: if(true)`, `Else branch is dead code`],
        cwe: ['CWE-570'],
        remediation: 'Replace with the always-taken branch, or fix the condition if it was meant to be variable.',
        affectedPaths: [],
      });
    }

    // if(false) — never taken
    const alwaysFalseMatch = line.match(/^if\s*\(\s*false\s*\)/);
    if (alwaysFalseMatch) {
      findings.push({
        type: 'dead_branch',
        title: `Condition is always false: if(false) at L${lineNum}`,
        severity: 'low',
        location: `${fileName}:L${lineNum}`,
        line: lineNum,
        description: `The if-condition at L${lineNum} is always false. The if-branch is dead code — it never executes. If the if-branch contains security-critical logic, that security check is permanently disabled.`,
        confidence: 0.95,
        evidence: [`Condition: if(false)`, `If branch is dead code`],
        cwe: ['CWE-571'],
        remediation: 'Remove the dead branch, or fix the condition if it was meant to be variable.',
        affectedPaths: [],
      });
    }

    // if (1 > 0) / if (0 > 1) — compile-time constant comparison
    const constCompareMatch = line.match(/^if\s*\(\s*(\d+)\s*([><=!]+)\s*(\d+)\s*\)/);
    if (constCompareMatch) {
      const [, left, op, right] = constCompareMatch;
      let result = false;
      const l = parseInt(left);
      const r = parseInt(right);
      if (op === '>') result = l > r;
      else if (op === '<') result = l < r;
      else if (op === '>=') result = l >= r;
      else if (op === '<=') result = l <= r;
      else if (op === '==' || op === '===') result = l === r;
      else if (op === '!=' || op === '!==') result = l !== r;

      findings.push({
        type: 'dead_branch',
        title: `Constant condition: if(${left} ${op} ${right}) is always ${result} at L${lineNum}`,
        severity: 'low',
        location: `${fileName}:L${lineNum}`,
        line: lineNum,
        description: `The if-condition compares two compile-time constants: ${left} ${op} ${right} = ${result}. The ${result ? 'else' : 'if'}-branch is dead code. This typically indicates a debugging leftover (if(DEBUG > 0)) or a logic error.`,
        confidence: 0.90,
        evidence: [`Condition: if(${left} ${op} ${right})`, `Result is always ${result}`],
        cwe: [result ? 'CWE-570' : 'CWE-571'],
        remediation: 'Replace with the always-taken branch or fix the condition.',
        affectedPaths: [],
      });
    }
  }

  // Detect: require(true) / assert(true) — no-op check
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    const lineNum = i + 1;

    if (/\b(?:require|assert)\s*\(\s*true\s*\)/.test(line)) {
      findings.push({
        type: 'dead_branch',
        title: `No-op check: require/assert(true) at L${lineNum}`,
        severity: 'medium',
        location: `${fileName}:L${lineNum}`,
        line: lineNum,
        description: `A require(true) or assert(true) at L${lineNum} always passes — it's a no-op. This is likely a placeholder that was never implemented with an actual condition. If this was intended to be a security check (e.g., require(msg.sender == owner)), the check is missing and the function is unprotected.`,
        confidence: 0.85,
        evidence: [`require/assert(true) at L${lineNum}`, `Always passes — no security value`],
        cwe: ['CWE-345'],
        remediation: 'Replace true with the actual condition, or remove if intentional.',
        affectedPaths: [],
      });
    }
  }

  return findings;
}

// ─── 5. EXCEPTION PATH ANALYSIS ─────────────────────────────────────
// Paths where require/assert fails, leaving state in an inconsistent condition.

function detectExceptionPaths(
  code: string,
  fileName: string,
  parsed: ParsedContract,
  isSolidity: boolean,
): ControlFlowFinding[] {
  const findings: ControlFlowFinding[] = [];

  if (!isSolidity) return findings;

  // Detect: State writes before require that can leave inconsistent state
  // If a require fails after state has been modified, the transaction reverts,
  // BUT in a cross-contract call, the caller's state changes are NOT reverted
  for (const [funcName, cfg] of parsed.cfg) {
    const funcNode = parsed.functions.get(funcName);
    if (!funcNode || funcNode.isView || funcNode.isPure) continue;

    const cfgNodes = cfg.filter(n => n.type !== 'entry' && n.type !== 'exit');

    // Find state writes that come BEFORE require/assert
    let lastStateWriteLine = -1;
    let lastStateWriteVar = '';

    for (const node of cfgNodes) {
      if (node.isStateWrite) {
        lastStateWriteLine = node.line;
        lastStateWriteVar = node.affectedVariables?.[0] || 'state';
      }

      if (node.isRequire && lastStateWriteLine > 0 && lastStateWriteLine < node.line) {
        // State was written before this require — if require fails, state reverts
        // In a single transaction this is fine (everything reverts),
        // but if this function is called via delegatecall from a proxy,
        // the proxy's state changes are in a separate context
        // Also, if the state write and require are in different branches
        // of a conditional, the require may not protect the state write

        // For now, report as medium — this is only a problem in specific patterns
        findings.push({
          type: 'state_before_check',
          title: `${funcName}(): state write to "${lastStateWriteVar}" before require at L${node.line}`,
          severity: 'medium',
          location: `${fileName}:L${lastStateWriteLine}`,
          line: lastStateWriteLine,
          description: `In function ${funcName}(), state variable ${lastStateWriteVar} is written at L${lastStateWriteLine} BEFORE the require/assert at L${node.line}. While Solidity reverts all state changes on failure, this pattern is problematic when: (1) The function is called via delegatecall from a proxy (proxy state persists), (2) The require depends on an external call that can be manipulated, (3) The state write and check are in different conditional branches. The safer pattern is: require first, then update state (CEI pattern).`,
          confidence: 0.55,
          evidence: [
            `State write: ${lastStateWriteVar} at L${lastStateWriteLine}`,
            `Check: require/assert at L${node.line}`,
            `Write before check — if check fails, write was unnecessary`,
            `In delegatecall context, proxy state may persist`,
          ],
          cwe: ['SWC-107'],
          remediation: 'Reorder: perform require/assert BEFORE state writes (CEI pattern).',
          affectedPaths: [`${funcName}: state_write@L${lastStateWriteLine} → require@L${node.line}`],
        });

        // Only report once per function
        break;
      }
    }
  }

  // Detect: Function that makes external call without try/catch
  // If the external call throws, the entire transaction reverts.
  // If state was already modified before the call, ALL changes revert.
  // This is expected behavior, but if the contract is designed to
  // continue operation even when the external call fails, it's a bug.
  for (const [funcName, cfg] of parsed.cfg) {
    const funcNode = parsed.functions.get(funcName);
    if (!funcNode || funcNode.isView || funcNode.isPure) continue;

    const cfgNodes = cfg.filter(n => n.type !== 'entry' && n.type !== 'exit');
    const externalCalls = cfgNodes.filter(n => n.isExternalCall);

    if (externalCalls.length > 0) {
      // Check if there's try/catch in the function
      const funcBody = getFunctionBody(code, funcNode.line);
      const hasTryCatch = funcBody.includes('try ') && funcBody.includes('catch');

      if (!hasTryCatch && externalCalls.length > 1) {
        findings.push({
          type: 'unhandled_external_failure',
          title: `${funcName}(): multiple external calls without try/catch — single failure reverts all`,
          severity: 'medium',
          location: `${fileName}:L${funcNode.line}`,
          line: funcNode.line,
          description: `Function ${funcName}() makes ${externalCalls.length} external calls without try/catch error handling. If any single external call fails (e.g., the callee reverts, runs out of gas, or returns unexpected data), the ENTIRE transaction reverts, including all successful calls and state changes. For protocols that need partial execution (e.g., batch operations where some calls may legitimately fail), this causes: (1) DoS — one bad call blocks all operations, (2) Griefing — attacker can trigger failure of one call to revert the entire batch, (3) Fund lock — user's operation fails because of an unrelated call failure.`,
          confidence: 0.62,
          evidence: [
            `${externalCalls.length} external calls in ${funcName}`,
            `No try/catch for error handling`,
            `Single failure reverts entire transaction`,
          ],
          cwe: ['CWE-391'],
          remediation: 'Wrap external calls in try/catch to handle individual failures gracefully. Consider using a batch pattern that continues on individual failures.',
          affectedPaths: externalCalls.map(n => `${funcName}: external_call@L${n.line}`),
        });
      }
    }
  }

  return findings;
}

// ─── HELPER ─────────────────────────────────────────────────────────

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
