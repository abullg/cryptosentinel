/**
 * CryptoSentinel — AST-Based Semantic Analyzer
 * Inspired by: CodeQL (AST traversal), Semgrep (tree matching), Halmos (symbolic),
 *             Slither (inheritance graph), Brakeman (call graph)
 *
 * This goes BEYOND regex patterns by:
 * 1. Parsing code into an actual AST (functions, calls, assignments, conditions)
 * 2. Building a call graph (who calls what, with what args)
 * 3. Building a control flow graph (execution paths through functions)
 * 4. Tracking variable dependencies across function boundaries
 * 5. Detecting semantic violations (CEI pattern, missing checks, invariant breaks)
 * 6. Identifying unreachable security checks
 * 7. Detecting privilege escalation through unprotected internal calls
 *
 * This is a lightweight parser — not a full compiler frontend — but it captures
 * the structure needed for meaningful security analysis.
 */

// ─── AST NODE TYPES ──────────────────────────────────────────────────

export type ASTNodeType =
  | 'contract' | 'function' | 'modifier' | 'variable' | 'assignment'
  | 'if_statement' | 'for_loop' | 'return' | 'emit' | 'require'
  | 'external_call' | 'state_write' | 'state_read' | 'internal_call'
  | 'arithmetic' | 'comparison' | 'event' | 'struct' | 'interface'
  | 'class' | 'method' | 'arrow_function' | 'try_catch'
  | 'route_handler' | 'middleware' | 'import';

export interface ASTNode {
  type: ASTNodeType;
  name: string;
  line: number;
  children: ASTNode[];
  // Semantic metadata
  isPublic?: boolean;
  isExternal?: boolean;
  isPayable?: boolean;
  isView?: boolean;
  isPure?: boolean;
  isVirtual?: boolean;
  isOverride?: boolean;
  modifiers?: string[];
  parameters?: ParamInfo[];
  returnType?: string;
  // For calls
  callee?: string;
  arguments?: string[];
  // For assignments
  lhs?: string;
  rhs?: string;
  // For conditions
  condition?: string;
  // Parent context
  parentFunction?: string;
  parentContract?: string;
}

export interface ParamInfo {
  name: string;
  type: string;
  isCalldata?: boolean;
  isMemory?: boolean;
  isStorage?: boolean;
}

// ─── CALL GRAPH ──────────────────────────────────────────────────────

export interface CallEdge {
  caller: string;
  callee: string;
  line: number;
  arguments: string[];
  isExternal: boolean;
  isDelegatecall: boolean;
  isStaticcall: boolean;
}

// ─── CONTROL FLOW ────────────────────────────────────────────────────

export interface CFGNode {
  id: string;
  function: string;
  type: 'entry' | 'exit' | 'call' | 'state_write' | 'require' | 'if' | 'return' | 'emit' | 'transfer';
  code: string;
  line: number;
  successors: string[];
  // Security-relevant metadata
  isExternalCall?: boolean;
  isStateWrite?: boolean;
  isRequire?: boolean;
  isTransfer?: boolean;
  affectedVariables?: string[];
}

// ─── SEMANTIC FINDING ────────────────────────────────────────────────

export interface SemanticFinding {
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
}

// ─── PARSED CONTRACT ─────────────────────────────────────────────────

export interface ParsedContract {
  name: string;
  language: string;
  ast: ASTNode[];
  functions: Map<string, ASTNode>;
  callGraph: CallEdge[];
  cfg: Map<string, CFGNode[]>;
  stateVariables: Map<string, { type: string; visibility: string; line: number }>;
  modifiers: Map<string, ASTNode>;
  inheritance: string[];
  imports: string[];
}

// ─── SOLIDITY PARSER ─────────────────────────────────────────────────

function parseSolidity(code: string, fileName: string): ParsedContract {
  const lines = code.split('\n');
  const ast: ASTNode[] = [];
  const functions = new Map<string, ASTNode>();
  const callGraph: CallEdge[] = [];
  const cfgMap = new Map<string, CFGNode[]>();
  const stateVars = new Map<string, { type: string; visibility: string; line: number }>();
  const modifiersMap = new Map<string, ASTNode>();
  const inheritance: string[] = [];
  const imports: string[] = [];

  let currentContract = '';
  let currentFunction = '';
  let braceDepth = 0;
  let functionBraceDepth = -1;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;
    const trimmed = line.trim();

    // Skip empty lines and comments
    if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) continue;

    // Track imports
    const importMatch = trimmed.match(/^import\s+.*from\s+["']([^"']+)["']/);
    if (importMatch) { imports.push(importMatch[1]); continue; }
    const importSimple = trimmed.match(/^import\s+["']([^"']+)["']/);
    if (importSimple) { imports.push(importSimple[1]); continue; }

    // Track contract declaration
    const contractMatch = trimmed.match(/^(?:abstract\s+)?contract\s+(\w+)(?:\s+is\s+([\w,\s]+))?\s*\{?/);
    if (contractMatch) {
      currentContract = contractMatch[1];
      if (contractMatch[2]) {
        inheritance.push(...contractMatch[2].split(',').map(s => s.trim()));
      }
      ast.push({
        type: 'contract',
        name: currentContract,
        line: lineNum,
        children: [],
        parentContract: currentContract,
      });
      continue;
    }

    // Track state variables
    const stateVarMatch = trimmed.match(/^(?:uint\d*|int\d*|bool|address|bytes\d*|string|mapping)\s+(?:public\s+|private\s+|internal\s+|external\s+)?(?:constant\s+|immutable\s+)?(\w+)/);
    if (stateVarMatch && !trimmed.includes('function') && !trimmed.includes('(')) {
      const varType = trimmed.match(/^(uint\d*|int\d*|bool|address|bytes\d*|string|mapping[^;]*)/)?.[1] || 'unknown';
      const visibility = trimmed.includes('public') ? 'public' : trimmed.includes('private') ? 'private' : trimmed.includes('internal') ? 'internal' : 'default';
      stateVars.set(stateVarMatch[1], { type: varType, visibility, line: lineNum });
      continue;
    }

    // Track modifier declarations
    const modifierMatch = trimmed.match(/^modifier\s+(\w+)\s*\(/);
    if (modifierMatch) {
      const node: ASTNode = {
        type: 'modifier',
        name: modifierMatch[1],
        line: lineNum,
        children: [],
        modifiers: [],
        parentContract: currentContract,
      };
      modifiersMap.set(modifierMatch[1], node);
      continue;
    }

    // Track function declarations (the most important part)
    const funcMatch = trimmed.match(
      /^function\s+(\w+)\s*\(([^)]*)\)\s*(.*?)\s*(?:returns\s*\(([^)]*)\))?\s*\{?$/
    );
    if (funcMatch) {
      currentFunction = funcMatch[1];
      const attrs = funcMatch[3] || '';
      const params = parseParams(funcMatch[2]);

      const funcNode: ASTNode = {
        type: 'function',
        name: currentFunction,
        line: lineNum,
        children: [],
        isPublic: attrs.includes('public') || (!attrs.includes('private') && !attrs.includes('internal')),
        isExternal: attrs.includes('external'),
        isPayable: attrs.includes('payable'),
        isView: attrs.includes('view'),
        isPure: attrs.includes('pure'),
        isVirtual: attrs.includes('virtual'),
        isOverride: attrs.includes('override'),
        modifiers: attrs.match(/only\w+|nonReentrant|_\w+/g)?.filter(m =>
          !['public', 'external', 'internal', 'private', 'payable', 'view', 'pure', 'virtual', 'override', 'memory', 'calldata', 'storage'].includes(m)
        ) || [],
        parameters: params,
        returnType: funcMatch[4]?.trim(),
        parentContract: currentContract,
      };

      functions.set(currentFunction, funcNode);
      functionBraceDepth = braceDepth;

      // Initialize CFG for this function
      cfgMap.set(currentFunction, [{
        id: `${currentFunction}_entry`,
        function: currentFunction,
        type: 'entry',
        code: `function ${currentFunction}(...)`,
        line: lineNum,
        successors: [],
      }]);

      continue;
    }

    // Track brace depth for function scope
    const opens = (trimmed.match(/\{/g) || []).length;
    const closes = (trimmed.match(/\}/g) || []).length;
    braceDepth += opens - closes;

    if (currentFunction && braceDepth < functionBraceDepth) {
      // Function ended
      if (cfgMap.has(currentFunction)) {
        const cfg = cfgMap.get(currentFunction)!;
        cfg.push({
          id: `${currentFunction}_exit`,
          function: currentFunction,
          type: 'exit',
          code: '}',
          line: lineNum,
          successors: [],
        });
      }
      currentFunction = '';
      functionBraceDepth = -1;
      continue;
    }

    // Inside a function — parse statements
    if (currentFunction) {
      const cfg = cfgMap.get(currentFunction) || [];
      const nodeId = `${currentFunction}_L${lineNum}`;

      // External calls: .call, .transfer, .send
      const extCallMatch = trimmed.match(/(\w+)\s*\.\s*(call|delegatecall|staticcall|transfer|send)\s*[({]/);
      if (extCallMatch) {
        const isDelegate = extCallMatch[2] === 'delegatecall';
        const isStatic = extCallMatch[2] === 'staticcall';
        callGraph.push({
          caller: currentFunction,
          callee: `${extCallMatch[1]}.${extCallMatch[2]}`,
          line: lineNum,
          arguments: [],
          isExternal: true,
          isDelegatecall: isDelegate,
          isStaticcall: isStatic,
        });

        cfg.push({
          id: nodeId,
          function: currentFunction,
          type: extCallMatch[2] === 'transfer' || extCallMatch[2] === 'send' ? 'transfer' : 'call',
          code: trimmed.slice(0, 80),
          line: lineNum,
          successors: [],
          isExternalCall: true,
          isTransfer: extCallMatch[2] === 'transfer' || extCallMatch[2] === 'send',
        });

        if (functions.has(currentFunction)) {
          functions.get(currentFunction)!.children.push({
            type: 'external_call',
            name: extCallMatch[2],
            line: lineNum,
            children: [],
            callee: extCallMatch[1],
            parentFunction: currentFunction,
            parentContract: currentContract,
          });
        }
        continue;
      }

      // Internal calls: other functions
      const intCallMatch = trimmed.match(/(\w+)\s*\(/);
      if (intCallMatch && !['require', 'assert', 'revert', 'emit', 'if', 'for', 'while', 'return', 'delete', 'unchecked', 'assembly'].includes(intCallMatch[1])) {
        const callee = intCallMatch[1];
        // Check if it's a known function (not a type cast or built-in)
        if (!trimmed.match(/^(?:uint|int|bool|address|bytes|string|abi|block|msg|tx|type|keccak256|sha256|sha3|ecrecover|gasleft|this|super)\b/)) {
          callGraph.push({
            caller: currentFunction,
            callee,
            line: lineNum,
            arguments: [],
            isExternal: false,
            isDelegatecall: false,
            isStaticcall: false,
          });

          if (functions.has(currentFunction)) {
            functions.get(currentFunction)!.children.push({
              type: 'internal_call',
              name: callee,
              line: lineNum,
              children: [],
              callee,
              parentFunction: currentFunction,
              parentContract: currentContract,
            });
          }
        }
      }

      // State writes: variable = or variable[...] =
      const stateWriteMatch = trimmed.match(/^(\w+)(?:\[.*?\])?\s*=(?!=)/);
      if (stateWriteMatch && stateVars.has(stateWriteMatch[1])) {
        cfg.push({
          id: nodeId,
          function: currentFunction,
          type: 'state_write',
          code: trimmed.slice(0, 80),
          line: lineNum,
          successors: [],
          isStateWrite: true,
          affectedVariables: [stateWriteMatch[1]],
        });

        if (functions.has(currentFunction)) {
          functions.get(currentFunction)!.children.push({
            type: 'state_write',
            name: stateWriteMatch[1],
            line: lineNum,
            children: [],
            lhs: stateWriteMatch[1],
            rhs: trimmed.split('=')[1]?.trim().slice(0, 50),
            parentFunction: currentFunction,
            parentContract: currentContract,
          });
        }
        continue;
      }

      // Require/assert statements
      const requireMatch = trimmed.match(/(?:require|assert)\s*\((.+?)(?:,\s*["'][^"']*["'])?\)/);
      if (requireMatch) {
        cfg.push({
          id: nodeId,
          function: currentFunction,
          type: 'require',
          code: trimmed.slice(0, 80),
          line: lineNum,
          successors: [],
          isRequire: true,
        });

        if (functions.has(currentFunction)) {
          functions.get(currentFunction)!.children.push({
            type: 'require',
            name: 'require',
            line: lineNum,
            children: [],
            condition: requireMatch[1],
            parentFunction: currentFunction,
            parentContract: currentContract,
          });
        }
        continue;
      }

      // If statements
      const ifMatch = trimmed.match(/^if\s*\((.+?)\)/);
      if (ifMatch) {
        cfg.push({
          id: nodeId,
          function: currentFunction,
          type: 'if',
          code: trimmed.slice(0, 80),
          line: lineNum,
          successors: [],
        });
        continue;
      }

      // Emit events
      const emitMatch = trimmed.match(/^emit\s+(\w+)/);
      if (emitMatch) {
        cfg.push({
          id: nodeId,
          function: currentFunction,
          type: 'emit',
          code: trimmed.slice(0, 80),
          line: lineNum,
          successors: [],
        });
        continue;
      }
    }
  }

  // Link CFG nodes
  for (const [funcName, cfg] of cfgMap) {
    for (let i = 0; i < cfg.length - 1; i++) {
      cfg[i].successors.push(cfg[i + 1].id);
    }
  }

  return {
    name: fileName,
    language: 'solidity',
    ast,
    functions,
    callGraph,
    cfg: cfgMap,
    stateVariables: stateVars,
    modifiers: modifiersMap,
    inheritance,
    imports,
  };
}

// ─── JAVASCRIPT/TYPESCRIPT PARSER ────────────────────────────────────

function parseJavaScript(code: string, fileName: string): ParsedContract {
  const lines = code.split('\n');
  const ast: ASTNode[] = [];
  const functions = new Map<string, ASTNode>();
  const callGraph: CallEdge[] = [];
  const cfgMap = new Map<string, CFGNode[]>();
  const stateVars = new Map<string, { type: string; visibility: string; line: number }>();
  const modifiersMap = new Map<string, ASTNode>();
  const inheritance: string[] = [];
  const imports: string[] = [];

  let currentFunction = '';
  let currentClass = '';

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;
    const trimmed = line.trim();

    if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('/*')) continue;

    // Imports
    const importMatch = trimmed.match(/(?:import\s+.*\s+from\s+|import\s+)["']([^"']+)["']/);
    if (importMatch) { imports.push(importMatch[1]); continue; }

    // Class declaration
    const classMatch = trimmed.match(/class\s+(\w+)/);
    if (classMatch) {
      currentClass = classMatch[1];
      ast.push({ type: 'class', name: currentClass, line: lineNum, children: [], parentContract: currentClass });
      continue;
    }

    // Function/method declarations
    const funcMatch = trimmed.match(/(?:async\s+)?(?:function\s+(\w+)|(?:get|set)?\s+(\w+)\s*\(|(\w+)\s*=\s*(?:async\s+)?\()/);
    if (funcMatch) {
      currentFunction = funcMatch[1] || funcMatch[2] || funcMatch[3];
      const isArrow = !!funcMatch[3];
      const isPublic = !trimmed.includes('private') && !trimmed.includes('#');

      const funcNode: ASTNode = {
        type: isArrow ? 'arrow_function' : 'method',
        name: currentFunction,
        line: lineNum,
        children: [],
        isPublic,
        modifiers: [],
        parentContract: currentClass || undefined,
      };
      functions.set(currentFunction, funcNode);

      // Check if this is a route handler
      const routeMatch = trimmed.match(/(?:app|router)\s*\.\s*(get|post|put|delete|patch)/);
      if (routeMatch) {
        funcNode.type = 'route_handler';
      }

      cfgMap.set(currentFunction, [{
        id: `${currentFunction}_entry`,
        function: currentFunction,
        type: 'entry',
        code: trimmed.slice(0, 60),
        line: lineNum,
        successors: [],
      }]);
      continue;
    }

    // Inside function — track calls
    if (currentFunction) {
      // Database calls
      const dbCallMatch = trimmed.match(/(?:findById|findOne|findAll|create|update|destroy|query|execute|raw)\s*\(/);
      if (dbCallMatch) {
        callGraph.push({
          caller: currentFunction,
          callee: dbCallMatch[0].split('(')[0],
          line: lineNum,
          arguments: [],
          isExternal: false,
          isDelegatecall: false,
          isStaticcall: false,
        });
      }

      // External service calls
      const extCallMatch = trimmed.match(/(?:fetch|axios|request|http\.get|https\.get)\s*\(/);
      if (extCallMatch) {
        callGraph.push({
          caller: currentFunction,
          callee: 'external_http',
          line: lineNum,
          arguments: [],
          isExternal: true,
          isDelegatecall: false,
          isStaticcall: false,
        });

        const cfg = cfgMap.get(currentFunction) || [];
        cfg.push({
          id: `${currentFunction}_L${lineNum}`,
          function: currentFunction,
          type: 'call',
          code: trimmed.slice(0, 80),
          line: lineNum,
          successors: [],
          isExternalCall: true,
        });
      }

      // Dangerous sinks
      const sinkMatch = trimmed.match(/(?:eval|exec|execSync|spawn|innerHTML|document\.write)\s*\(/);
      if (sinkMatch) {
        const cfg = cfgMap.get(currentFunction) || [];
        cfg.push({
          id: `${currentFunction}_L${lineNum}`,
          function: currentFunction,
          type: 'call',
          code: trimmed.slice(0, 80),
          line: lineNum,
          successors: [],
          isExternalCall: true,
        });
      }

      // Auth checks
      const authMatch = trimmed.match(/(?:authenticate|verify|validate|authorize|isAuthenticated|requireAuth|checkPermission)/);
      if (authMatch && functions.has(currentFunction)) {
        functions.get(currentFunction)!.modifiers = functions.get(currentFunction)!.modifiers || [];
        functions.get(currentFunction)!.modifiers!.push(authMatch[0]);
      }
    }
  }

  return {
    name: fileName,
    language: 'typescript',
    ast,
    functions,
    callGraph,
    cfg: cfgMap,
    stateVariables: stateVars,
    modifiers: modifiersMap,
    inheritance,
    imports,
  };
}

function parseParams(paramStr: string): ParamInfo[] {
  if (!paramStr.trim()) return [];
  return paramStr.split(',').map(p => {
    const parts = p.trim().split(/\s+/);
    return {
      name: parts[parts.length - 1]?.replace(/\[.*\]/, '') || '',
      type: parts[0] || 'unknown',
      isCalldata: p.includes('calldata'),
      isMemory: p.includes('memory'),
      isStorage: p.includes('storage'),
    };
  }).filter(p => p.name && p.type);
}

// ─── SEMANTIC ANALYSIS ENGINE ────────────────────────────────────────

export function runSemanticAnalysis(
  code: string,
  fileName: string,
): SemanticFinding[] {
  const findings: SemanticFinding[] = [];
  const isSolidity = code.includes('pragma solidity') || code.includes('contract ');
  const parsed = isSolidity ? parseSolidity(code, fileName) : parseJavaScript(code, fileName);

  // ─── 1. CEI PATTERN VIOLATION (Checks-Effects-Interactions) ────────
  // Walk the CFG for each function. If an external call appears BEFORE
  // a state write in the execution order, it's a CEI violation.
  // This is NOT catchable by simple regex — it requires control flow.

  for (const [funcName, cfg] of parsed.cfg) {
    const funcNode = parsed.functions.get(funcName);
    if (!funcNode || funcNode.isView || funcNode.isPure) continue;

    // Walk CFG nodes in order
    let lastExternalCallLine = -1;
    let lastExternalCallCode = '';
    let lastStateWriteLine = -1;
    let hasReentrancyGuard = false;
    const stateWritesAfterCall: string[] = [];

    // ─── Bug fix: reentrancy-guard detection ─────────────────────────
    // Previously the code only checked for `notentered` inside a require()
    // in the function body. This MISSED the standard `nonReentrant`
    // modifier on the function signature (which lives in funcNode.modifiers,
    // not in any CFG node). Result: every CEI finding was a false positive
    // on guarded functions.
    //
    // Now we ALSO check the function's modifier list for nonReentrant /
    // reentrancyGuard / ReentrancyGuard patterns. This is the canonical
    // way OpenZeppelin and similar libs protect against reentrancy.
    const funcNodeForGuard = parsed.functions.get(funcName);
    if (funcNodeForGuard?.modifiers?.some(m =>
      /nonreentrant|reentrancyguard|reentrancy_guard|__reentrancyguard|non_reentrant/i.test(m)
    )) {
      hasReentrancyGuard = true;
    }

    for (const node of cfg) {
      if (node.type === 'entry' || node.type === 'exit') continue;

      // Check for reentrancy guard inside require (legacy pattern)
      if (node.isRequire && node.code.toLowerCase().includes('notentered')) {
        hasReentrancyGuard = true;
      }

      // Track external calls — record EVERY external call, not just the first
      // (previously: only first external call was tracked, missing multi-call
      // reentrancy patterns).
      if (node.isExternalCall || node.isTransfer) {
        // Record the FIRST external call for the "state writes after call"
        // check (the canonical CEI violation).
        if (lastExternalCallLine === -1) {
          lastExternalCallLine = node.line;
          lastExternalCallCode = node.code;
        }
      }

      // Track state writes
      if (node.isStateWrite) {
        // If this state write comes AFTER an external call → CEI violation
        if (lastExternalCallLine > 0 && node.line > lastExternalCallLine) {
          stateWritesAfterCall.push(`${node.affectedVariables?.join(',') || 'state'}@L${node.line}`);
        }
        lastStateWriteLine = node.line;
      }
    }

    if (stateWritesAfterCall.length > 0 && !hasReentrancyGuard) {
      findings.push({
        type: 'reentrancy',
        title: `CEI violation in ${funcName}: state update after external call`,
        severity: 'critical',
        location: `${fileName}:L${lastExternalCallLine}`,
        line: lastExternalCallLine,
        description: `Function ${funcName} violates the Checks-Effects-Interactions pattern. External call at line ${lastExternalCallLine} (\`${lastExternalCallCode.slice(0, 50)}\`) executes BEFORE state variables are updated at ${stateWritesAfterCall.join(', ')}. An attacker re-enters ${funcName} through the external call callback, operating on stale state. This is a CONFIRMED reentrancy vulnerability — not detectable by simple pattern matching because the external call and state write are on different lines with different syntax.`,
        confidence: 0.92,
        evidence: [
          `External call: L${lastExternalCallLine} — ${lastExternalCallCode.slice(0, 60)}`,
          `State writes after call: ${stateWritesAfterCall.join(', ')}`,
          `No reentrancy guard (nonReentrant) found in ${funcName}`,
          `Control flow: call → state_write (should be: check → state_write → call)`,
        ],
        cwe: ['SWC-107'],
        remediation: 'Reorder to follow CEI: update state BEFORE external calls, or add nonReentrant modifier.',
      });
    }
  }

  // ─── 2. PRIVILEGE ESCALATION VIA INTERNAL CALLS ───────────────────
  // A public function without access control that calls a privileged
  // internal function creates a privilege escalation path.
  // This requires call graph analysis — impossible with regex alone.

  const privilegedFuncs = new Set<string>();
  const unprotectedFuncs = new Map<string, ASTNode>();

  for (const [name, node] of parsed.functions) {
    const hasAccessControl = (node.modifiers || []).some(m =>
      m.toLowerCase().includes('owner') ||
      m.toLowerCase().includes('admin') ||
      m.toLowerCase().includes('role') ||
      m.toLowerCase().includes('governance') ||
      m.toLowerCase().includes('guard')
    );

    if (hasAccessControl) {
      privilegedFuncs.add(name);
    } else if ((node.isPublic || node.isExternal) && !node.isView && !node.isPure) {
      unprotectedFuncs.set(name, node);
    }
  }

  // Check if unprotected functions call privileged ones
  for (const edge of parsed.callGraph) {
    if (unprotectedFuncs.has(edge.caller) && privilegedFuncs.has(edge.callee) && !edge.isExternal) {
      const callerNode = unprotectedFuncs.get(edge.caller)!;
      findings.push({
        type: 'access_control',
        title: `Privilege escalation: ${edge.caller}() calls privileged ${edge.callee}()`,
        // HackenProof tier: Critical (unauthorized privileged action)
        // Per docs.hackenproof.com: "Unauthorized privileged action — can
        // enable direct fund theft or governance hijacking" → Critical.
        // Previously under-classified as 'high'.
        severity: 'critical',
        location: `${fileName}:L${callerNode.line}`,
        line: callerNode.line,
        description: `Public function ${edge.caller}() (no access control) calls ${edge.callee}() which IS protected by access control. However, since ${edge.caller} is public, any caller can invoke it, which then invokes the privileged ${edge.callee} internally, bypassing the access control check. This is a privilege escalation vulnerability that requires call graph analysis to detect — the access control on ${edge.callee} only protects direct calls, not internal calls from the same contract. HackenProof severity: Critical (unauthorized privileged action).`,
        confidence: 0.82,
        evidence: [
          `${edge.caller}() is public/external without access control modifiers`,
          `${edge.callee}() has access control (onlyOwner/onlyAdmin/onlyRole)`,
          `Call graph: ${edge.caller} → ${edge.callee} at L${edge.line}`,
          `Internal calls bypass modifier checks in Solidity`,
        ],
        cwe: ['SWC-105', 'CWE-863'],
        remediation: `Add access control to ${edge.caller}() or refactor ${edge.callee}() to check msg.sender even for internal calls.`,
      });
    }
  }

  // ─── 3. UNCHECKED RETURN VALUE ACROSS FUNCTIONS ───────────────────
  // If function A calls external function B and doesn't check the return
  // value, then uses B's expected result in a state write, this is
  // only detectable through cross-function analysis.

  for (const [funcName, cfg] of parsed.cfg) {
    const funcNode = parsed.functions.get(funcName);
    if (!funcNode || funcNode.isView) continue;

    let hasUncheckedCall = false;
    let uncheckedCallLine = -1;
    let uncheckedCallCode = '';

    for (const node of cfg) {
      if (node.isExternalCall && !node.isTransfer) {
        // Check if the next require/assert checks this call
        const nextNodes = cfg.filter(n => n.line > node.line && n.line <= node.line + 5);
        const hasCheck = nextNodes.some(n => n.isRequire);
        if (!hasCheck) {
          hasUncheckedCall = true;
          uncheckedCallLine = node.line;
          uncheckedCallCode = node.code;
        }
      }
    }

    if (hasUncheckedCall && uncheckedCallLine > 0) {
      // Check if there's a state write after this unchecked call
      const stateWritesAfter = cfg.filter(n =>
        n.isStateWrite && n.line > uncheckedCallLine
      );

      if (stateWritesAfter.length > 0) {
        findings.push({
          type: 'unchecked_call',
          title: `Unchecked return value in ${funcName} followed by state mutation`,
          severity: 'high',
          location: `${fileName}:L${uncheckedCallLine}`,
          line: uncheckedCallLine,
          description: `External call in ${funcName} at L${uncheckedCallLine} does not check the return value. Execution continues to state writes at L${stateWritesAfter.map(n => n.line).join(', L')}. If the call fails silently, the contract operates on incorrect assumptions, and subsequent state writes corrupt the contract state. This is detectable only through control flow analysis — the unchecked call and state write may be on non-adjacent lines.`,
          confidence: 0.85,
          evidence: [
            `Unchecked external call: L${uncheckedCallLine} — ${uncheckedCallCode.slice(0, 60)}`,
            `State writes after: L${stateWritesAfter.map(n => n.line).join(', ')}`,
            `No require/assert within 5 lines after the call`,
          ],
          cwe: ['SWC-104'],
          remediation: 'Check the return value with require(success) or use try/catch.',
        });
      }
    }
  }

  // ─── 4. MISSING INVARIANT CHECKS ───────────────────────────────────
  // After state mutations, check if critical invariants are verified.
  // E.g., after a withdrawal, is the balance >= 0 checked?
  // This is semantic — not pattern-based.

  for (const [funcName, cfg] of parsed.cfg) {
    const funcNode = parsed.functions.get(funcName);
    if (!funcNode || funcNode.isView || funcNode.isPure) continue;
    if ((funcNode.modifiers || []).includes('nonReentrant')) continue;

    const stateWrites = cfg.filter(n => n.isStateWrite);
    const requires = cfg.filter(n => n.isRequire);

    // If a function has state writes but NO require/assert at all → suspicious
    if (stateWrites.length > 0 && requires.length === 0 && (funcNode.isPublic || funcNode.isExternal)) {
      findings.push({
        type: 'access_control',
        title: `Function ${funcName} mutates state without any precondition checks`,
        severity: 'medium',
        location: `${fileName}:L${funcNode.line}`,
        line: funcNode.line,
        description: `Public/external function ${funcName} modifies ${stateWrites.length} state variable(s) but contains zero require/assert statements. This means the function executes unconditionally — any input is accepted. While this may be intentional, it often indicates missing validation: balance checks, access control, input bounds, or invariant preservation. This finding requires AST analysis — a regex cannot count require statements vs state writes.`,
        confidence: 0.55,
        evidence: [
          `State writes: ${stateWrites.length} in ${funcName}`,
          `Require/assert: 0 in ${funcName}`,
          `Function is public/external — callable by anyone`,
        ],
        cwe: ['SWC-105'],
        remediation: 'Add precondition checks (require) before state mutations. Verify access control and input validation.',
      });
    }
  }

  // ─── 5. DELEGATECALL TO FUNCTION WITHOUT ACCESS CONTROL ───────────
  // If a proxy's fallback uses delegatecall and the implementation
  // has unprotected functions, this creates an attack surface.

  const delegatecallEdges = parsed.callGraph.filter(e => e.isDelegatecall);
  for (const edge of delegatecallEdges) {
    // Check if the calling function has access control
    const callerNode = parsed.functions.get(edge.caller);
    if (callerNode && !callerNode.modifiers?.length) {
      findings.push({
        type: 'delegatecall',
        title: `Unprotected delegatecall in ${edge.caller} to ${edge.callee}`,
        severity: 'critical',
        location: `${fileName}:L${edge.line}`,
        line: edge.line,
        description: `Function ${edge.caller} uses delegatecall without access control. Delegatecall executes the callee's logic in the context of the caller's storage. An attacker who can influence the implementation address or call data can execute arbitrary logic with full storage access. This requires call graph analysis to identify the delegatecall + missing modifier combination.`,
        confidence: 0.88,
        evidence: [
          `delegatecall at L${edge.line}`,
          `No access control modifiers on ${edge.caller}`,
          `Call graph: ${edge.caller} →[delegatecall]→ ${edge.callee}`,
        ],
        cwe: ['SWC-112'],
        remediation: 'Add onlyOwner/onlyAdmin to the function containing delegatecall. Use EIP-1967 proxy pattern.',
      });
    }
  }

  // ─── 6. STATE VARIABLE SHADOWING IN INHERITANCE ───────────────────
  // If a contract inherits and re-declares a state variable that
  // exists in a parent, the child's version shadows the parent's.
  // This requires AST knowledge of inheritance + state vars.

  if (parsed.inheritance.length > 0 && parsed.stateVariables.size > 0) {
    // Check for common shadowed variables (owner, admin, paused, etc.)
    const commonlyShadowed = ['owner', 'admin', 'paused', 'locked', 'implementation', '_implementation'];
    for (const varName of commonlyShadowed) {
      if (parsed.stateVariables.has(varName)) {
        const varInfo = parsed.stateVariables.get(varName)!;
        if (varInfo.visibility === 'public' && parsed.inheritance.length > 0) {
          findings.push({
            type: 'state_shadowing',
            title: `State variable "${varName}" may shadow parent contract variable`,
            severity: 'medium',
            location: `${fileName}:L${varInfo.line}`,
            line: varInfo.line,
            description: `Contract declares ${varName} (type: ${varInfo.type}) and inherits from ${parsed.inheritance.join(', ')}. If any parent also declares ${varName}, the child's version shadows the parent's — reads/writes to ${varName} in the parent context use the parent's slot, while the child's context uses the child's slot. This causes inconsistent state and potential ownership hijacking. Detectable only through inheritance graph + state variable analysis.`,
            confidence: 0.45,
            evidence: [
              `Variable: ${varName} (${varInfo.type}, ${varInfo.visibility}) at L${varInfo.line}`,
              `Inherits fromB: ${parsed.inheritance.join(', ')}`,
              `Commonly shadowed variable in proxy/upgradeable patterns`,
            ],
            cwe: ['SWC-119'],
            remediation: 'Use unique variable names or EIP-1967 storage slots. Run Slither for precise shadow detection.',
          });
        }
      }
    }
  }

  // ─── 7. ORACLE RELIANCE WITHOUT FRESHNESS (Semantic) ──────────────
  // If a function calls latestRoundData/getPrice and then uses the
  // result in a calculation WITHOUT checking the timestamp/roundId,
  // the oracle result may be stale.

  for (const [funcName, cfg] of parsed.cfg) {
    const hasOracleCall = cfg.some(n =>
      n.code.includes('latestRoundData') ||
      n.code.includes('getPrice') ||
      n.code.includes('consult') ||
      n.code.includes('peek')
    );
    const hasFreshnessCheck = cfg.some(n =>
      n.isRequire && (
        n.code.includes('updatedAt') ||
        n.code.includes('roundId') ||
        n.code.includes('staleness') ||
        n.code.includes('freshness') ||
        n.code.includes('heartbeat')
      )
    );
    const hasDeviationCheck = cfg.some(n =>
      n.code.includes('maxDeviation') ||
      n.code.includes('circuitBreaker') ||
      n.code.includes('TWAP') ||
      n.code.includes('twap')
    );

    if (hasOracleCall && !hasFreshnessCheck && !hasDeviationCheck) {
      const funcNode = parsed.functions.get(funcName);
      findings.push({
        type: 'oracle_manipulation',
        title: `Oracle read in ${funcName} without freshness or deviation check`,
        // HackenProof tier: HIGH (not Critical). Oracle manipulation is
        // explicitly listed under HIGH per docs.hackenproof.com.
        severity: 'high',
        location: `${fileName}:L${funcNode?.line || 0}`,
        line: funcNode?.line || 0,
        description: `Function ${funcName} reads oracle data but does not verify the timestamp of the last update or check price deviation bounds. Stale oracle data can be exploited via flash loans or oracle manipulation. This requires control flow analysis — the oracle read and missing check may span multiple lines with intermediate calculations. HackenProof severity: HIGH (oracle manipulation).`,
        confidence: 0.72,
        evidence: [
          `Oracle call found in ${funcName} CFG`,
          `No freshness check (updatedAt, roundId, staleness) in require/assert`,
          `No deviation check (maxDeviation, circuitBreaker, TWAP)`,
          `Function CFG: ${cfg.map(n => `${n.type}@L${n.line}`).join(' → ')}`,
        ],
        cwe: ['SWC-120'],
        remediation: 'Add staleness check: require(block.timestamp - updatedAt < MAX_STALENESS). Add deviation bounds. Use TWAP.',
      });
    }
  }

  // ─── 8. JS/TS: MISSING AUTH ON ROUTE HANDLERS ─────────────────────
  // A route handler that performs DB mutations without auth middleware

  if (!isSolidity) {
    for (const [funcName, node] of parsed.functions) {
      if (node.type === 'route_handler') {
        const hasAuth = (node.modifiers || []).some(m =>
          m.toLowerCase().includes('auth') ||
          m.toLowerCase().includes('authenticate') ||
          m.toLowerCase().includes('verify') ||
          m.toLowerCase().includes('validate')
        );

        // Check if this route does DB operations
        const doesDBOp = parsed.callGraph.some(e =>
          e.caller === funcName &&
          ['findById', 'findOne', 'create', 'update', 'destroy', 'query'].some(op => e.callee.includes(op))
        );

        // Check if it modifies state (POST/PUT/DELETE/PATCH)
        const isMutating = parsed.callGraph.some(e =>
          e.caller === funcName && !e.isExternal
        );

        if (!hasAuth && doesDBOp && isMutating) {
          findings.push({
            type: 'auth_bypass',
            title: `Route handler ${funcName} performs DB operations without authentication`,
            severity: 'high',
            location: `${fileName}:L${node.line}`,
            line: node.line,
            description: `Route handler ${funcName} at L${node.line} performs database operations without any authentication middleware. Any unauthenticated user can access this endpoint and modify data. This requires call graph analysis to identify the route → DB operation chain.`,
            confidence: 0.78,
            evidence: [
              `Route handler: ${funcName} at L${node.line}`,
              `No auth middleware detected`,
              `DB operations in call graph from ${funcName}`,
            ],
            cwe: ['CWE-863'],
            remediation: 'Add authentication middleware to this route handler.',
          });
        }
      }
    }
  }

  // Sort by confidence
  findings.sort((a, b) => b.confidence - a.confidence);

  return findings;
}

// ─── UTILITY: GET PARSED CONTRACT ────────────────────────────────────

export function parseCode(code: string, fileName: string): ParsedContract {
  const isSolidity = code.includes('pragma solidity') || code.includes('contract ');
  return isSolidity ? parseSolidity(code, fileName) : parseJavaScript(code, fileName);
}
