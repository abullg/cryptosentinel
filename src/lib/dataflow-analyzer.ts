/**
 * CryptoSentinel — Dataflow / Taint Analyzer
 * Inspired by: CodeQL (dataflow analysis), Brakeman (call tracking), Snyk Code (taint tracking)
 *
 * Tracks tainted data from sources (user input) through assignments and function calls
 * to sinks (dangerous operations). If tainted data reaches a sink without sanitization,
 * a vulnerability is reported.
 *
 * This is a lightweight static approximation — not full abstract interpretation.
 * It performs:
 * 1. Source identification — where does user input enter?
 * 2. Taint propagation — how does tainted data flow through assignments?
 * 3. Sink detection — where does tainted data reach dangerous operations?
 * 4. Sanitizer recognition — where is tainted data cleaned?
 */

export interface TaintSource {
  type: string;
  pattern: RegExp;
  description: string;
  language: string[];
}

export interface TaintSink {
  type: string;
  vulnerabilityType: string;
  pattern: RegExp;
  description: string;
  cwe: string[];
  severity: string;
  language: string[];
}

export interface Sanitizer {
  type: string;
  pattern: RegExp;
  description: string;
  language: string[];
}

export interface TaintFinding {
  type: string;
  title: string;
  severity: string;
  cwe: string[];
  source: { location: string; code: string; line: number };
  sink: { location: string; code: string; line: number };
  path: string[];     // Variable names in the taint chain
  sanitized: boolean;
  sanitizerFound?: string;
  confidence: number;
  description: string;
}

// ─── SOURCES — where tainted data enters ─────────────────────────────

const SOURCES: TaintSource[] = [
  // Solidity sources
  { type: 'msg.sender', pattern: /msg\.sender/g, description: 'External caller address', language: ['solidity'] },
  { type: 'msg.value', pattern: /msg\.value/g, description: 'Sent ETH amount', language: ['solidity'] },
  { type: 'msg.data', pattern: /msg\.data/g, description: 'Raw calldata', language: ['solidity'] },
  { type: 'tx.origin', pattern: /tx\.origin/g, description: 'Transaction origin (phishing risk)', language: ['solidity'] },
  { type: 'block.timestamp', pattern: /block\.timestamp|now\b/g, description: 'Manipulatable timestamp', language: ['solidity'] },
  { type: 'block.number', pattern: /block\.number/g, description: 'Manipulatable block number', language: ['solidity'] },
  { type: 'function_param', pattern: /function\s+\w+\s*\(([^)]+)\)/g, description: 'External function parameter', language: ['solidity'] },
  
  // Web/JS sources
  { type: 'req.query', pattern: /req\.query\.(\w+)/g, description: 'URL query parameter', language: ['typescript', 'javascript'] },
  { type: 'req.body', pattern: /req\.body\.(\w+)/g, description: 'Request body field', language: ['typescript', 'javascript'] },
  { type: 'req.params', pattern: /req\.params\.(\w+)/g, description: 'URL path parameter', language: ['typescript', 'javascript'] },
  { type: 'request.query', pattern: /request\.query\.(\w+)/g, description: 'URL query parameter', language: ['typescript', 'javascript', 'python'] },
  { type: 'request.form', pattern: /request\.form\.(\w+)/g, description: 'Form field', language: ['python'] },
  { type: 'localStorage', pattern: /localStorage\.getItem\s*\(/g, description: 'Browser storage value', language: ['typescript', 'javascript', 'web'] },
  { type: 'window.location', pattern: /window\.location/g, description: 'Browser URL', language: ['typescript', 'javascript', 'web'] },
  { type: 'postMessage', pattern: /(?:window|event)\.data/g, description: 'PostMessage data', language: ['typescript', 'javascript', 'web'] },
];

// ─── SINKS — where tainted data is consumed dangerously ──────────────

const SINKS: TaintSink[] = [
  // Solidity sinks
  { type: 'external_call', vulnerabilityType: 'reentrancy', pattern: /(\w+)\s*\.\s*(?:call|delegatecall|staticcall)\s*\{/g, description: 'External call with tainted data', cwe: ['SWC-107'], severity: 'critical', language: ['solidity'] },
  { type: 'transfer', vulnerabilityType: 'reentrancy', pattern: /(\w+)\s*\.\s*transfer\s*\(/g, description: 'ETH transfer with tainted amount', cwe: ['SWC-107'], severity: 'critical', language: ['solidity'] },
  { type: 'selfdestruct', vulnerabilityType: 'denial_of_service', pattern: /selfdestruct\s*\(\s*(\w+)\s*\)/g, description: 'Self-destruct with tainted address', cwe: ['CWE-400'], severity: 'critical', language: ['solidity'] },
  { type: 'delegatecall', vulnerabilityType: 'delegatecall', pattern: /delegatecall\s*\{[^}]*\}\s*\(\s*(\w+)/g, description: 'Delegatecall to tainted address', cwe: ['SWC-112'], severity: 'critical', language: ['solidity'] },
  { type: 'storage_write', vulnerabilityType: 'storage_collision', pattern: /(\w+)\s*\[\s*(\w+)\s*\]\s*=/g, description: 'Storage write with tainted index', cwe: ['SWC-118'], severity: 'high', language: ['solidity'] },
  
  // Web/JS sinks
  { type: 'innerHTML', vulnerabilityType: 'xss', pattern: /innerHTML\s*=\s*(\w+)/g, description: 'DOM injection via innerHTML', cwe: ['CWE-79'], severity: 'high', language: ['typescript', 'javascript', 'web'] },
  { type: 'document.write', vulnerabilityType: 'xss', pattern: /document\.write\s*\(\s*(\w+)/g, description: 'DOM injection via document.write', cwe: ['CWE-79'], severity: 'high', language: ['typescript', 'javascript', 'web'] },
  { type: 'eval', vulnerabilityType: 'code_injection', pattern: /eval\s*\(\s*(\w+)/g, description: 'Code execution via eval', cwe: ['CWE-94'], severity: 'critical', language: ['typescript', 'javascript'] },
  { type: 'exec', vulnerabilityType: 'command_injection', pattern: /(?:exec|execSync|spawn)\s*\(\s*(\w+)/g, description: 'Command execution with tainted input', cwe: ['CWE-78'], severity: 'critical', language: ['typescript', 'javascript'] },
  { type: 'sql_query', vulnerabilityType: 'sql_injection', pattern: /(?:query|execute|raw)\s*\(\s*(\w+)/g, description: 'SQL query with tainted input', cwe: ['CWE-89'], severity: 'critical', language: ['typescript', 'javascript', 'python'] },
  { type: 'fetch', vulnerabilityType: 'ssrf', pattern: /(?:fetch|axios\.get|http\.get)\s*\(\s*(\w+)/g, description: 'HTTP request with tainted URL', cwe: ['CWE-918'], severity: 'critical', language: ['typescript', 'javascript'] },
  { type: 'readFile', vulnerabilityType: 'path_traversal', pattern: /(?:readFile|readFileSync|createReadStream)\s*\(\s*(\w+)/g, description: 'File read with tainted path', cwe: ['CWE-22'], severity: 'high', language: ['typescript', 'javascript'] },
  { type: 'redirect', vulnerabilityType: 'open_redirect', pattern: /(?:redirect|res\.location)\s*\(\s*(\w+)/g, description: 'Redirect with tainted URL', cwe: ['CWE-601'], severity: 'medium', language: ['typescript', 'javascript'] },
  { type: 'deserialize', vulnerabilityType: 'deserialization', pattern: /(?:pickle\.loads|yaml\.load|unserialize)\s*\(\s*(\w+)/g, description: 'Deserialization of tainted data', cwe: ['CWE-502'], severity: 'critical', language: ['typescript', 'javascript', 'python'] },
];

// ─── SANITIZERS — where tainted data is cleaned ──────────────────────

const SANITIZERS: Sanitizer[] = [
  { type: 'DOMPurify', pattern: /DOMPurify\.sanitize\s*\(/g, description: 'HTML sanitization', language: ['typescript', 'javascript', 'web'] },
  { type: 'escapeHtml', pattern: /escapeHtml\s*\(/g, description: 'HTML escaping', language: ['typescript', 'javascript'] },
  { type: 'encodeURIComponent', pattern: /encodeURIComponent\s*\(/g, description: 'URL encoding', language: ['typescript', 'javascript'] },
  { type: 'path.resolve', pattern: /path\.resolve\s*\(/g, description: 'Path normalization', language: ['typescript', 'javascript'] },
  { type: 'basename', pattern: /(?:path\.)?basename\s*\(/g, description: 'Filename extraction', language: ['typescript', 'javascript'] },
  { type: 'JSON.parse', pattern: /JSON\.parse\s*\(/g, description: 'Safe JSON parsing', language: ['typescript', 'javascript'] },
  { type: 'parseInt', pattern: /parseInt\s*\(/g, description: 'Integer parsing', language: ['typescript', 'javascript'] },
  { type: 'Number', pattern: /Number\s*\(\s*(\w+)\s*\)/g, description: 'Number coercion', language: ['typescript', 'javascript'] },
  { type: 'require', pattern: /require\s*\(/g, description: 'Solidity require check', language: ['solidity'] },
  { type: 'nonReentrant', pattern: /nonReentrant/g, description: 'Reentrancy guard', language: ['solidity'] },
  { type: 'SafeMath', pattern: /SafeMath\.\w+\s*\(/g, description: 'Safe arithmetic', language: ['solidity'] },
  { type: 'validator', pattern: /(?:validator|validate|joi|zod)\.\w+\s*\(/g, description: 'Input validation', language: ['typescript', 'javascript'] },
  { type: 'sanitize', pattern: /sanitize\w*\s*\(/g, description: 'General sanitization', language: ['typescript', 'javascript', 'python'] },
  { type: 'parameterized', pattern: /(?:\$1|\$2|:param|PreparedStatement)/g, description: 'Parameterized query', language: ['typescript', 'javascript', 'python'] },
];

// ─── TAINT TRACKING ENGINE ───────────────────────────────────────────

interface TaintVar {
  name: string;
  source: string;
  line: number;
  sanitized: boolean;
  sanitizer?: string;
}

/**
 * Perform lightweight taint analysis on source code.
 * Tracks: source → variable assignment → sink
 */
export function runTaintAnalysis(
  sourceCode: string,
  fileName: string,
): TaintFinding[] {
  const findings: TaintFinding[] = [];
  const lines = sourceCode.split('\n');
  const taintedVars: Map<string, TaintVar> = new Map();
  
  // Detect language
  const isSolidity = sourceCode.includes('pragma solidity') || sourceCode.includes('contract ');
  const isWeb = !isSolidity;
  const lang = isSolidity ? 'solidity' : 'typescript';
  
  // Phase 1: Identify sources and track taint through assignments
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;
    
    // Check for direct source usage
    for (const source of SOURCES) {
      if (!source.language.includes(lang) && !source.language.includes('web')) continue;
      source.pattern.lastIndex = 0;
      const match = source.pattern.exec(line);
      if (match) {
        // Track variable assignments from this source
        // Pattern: var = source; or let/const var = source;
        const assignMatch = line.match(/(?:let|const|var|type\s+\w+)?\s*(\w+)\s*(?::\s*\w+)?\s*=\s*.*(?:req\.|request\.|msg\.|tx\.|block\.|localStorage|window\.)/);
        if (assignMatch) {
          taintedVars.set(assignMatch[1], {
            name: assignMatch[1],
            source: source.type,
            line: lineNum,
            sanitized: false,
          });
        }
        
        // Also track direct parameter usage in Solidity
        if (isSolidity) {
          const funcMatch = line.match(/function\s+\w+\s*\(([^)]+)\)/);
          if (funcMatch) {
            const params = funcMatch[1].split(',').map(p => p.trim().split(' ').pop()?.trim()).filter(Boolean);
            for (const param of params) {
              if (param) {
                taintedVars.set(param, {
                  name: param,
                  source: 'function_parameter',
                  line: lineNum,
                  sanitized: false,
                });
              }
            }
          }
        }
      }
    }
    
    // Track taint propagation through assignments
    // Pattern: newVar = taintedVar.something or newVar = f(taintedVar)
    for (const [varName, taint] of taintedVars) {
      if (taint.sanitized) continue;
      
      // Check if this line assigns from a tainted variable
      const propMatch = line.match(new RegExp(`(?:let|const|var)?\\s*(\\w+)\\s*(?::\\s*\\w+)?\\s*=\\s*${varName}(?:\\.|\\[|\\()`));
      if (propMatch) {
        taintedVars.set(propMatch[1], {
          name: propMatch[1],
          source: taint.source,
          line: lineNum,
          sanitized: false,
        });
      }
      
      // Check function call propagation: newVar = func(taintedVar, ...)
      const callMatch = line.match(new RegExp(`(?:let|const|var)?\\s*(\\w+)\\s*(?::\\s*\\w+)?\\s*=\\s*\\w+\\s*\\(.*${varName}.*\\)`));
      if (callMatch) {
        // Check if the function is a sanitizer
        let isSanitizer = false;
        for (const san of SANITIZERS) {
          san.pattern.lastIndex = 0;
          if (san.pattern.test(line)) {
            isSanitizer = true;
            taintedVars.set(callMatch[1], {
              name: callMatch[1],
              source: taint.source,
              line: lineNum,
              sanitized: true,
              sanitizer: san.type,
            });
            break;
          }
        }
        if (!isSanitizer) {
          taintedVars.set(callMatch[1], {
            name: callMatch[1],
            source: taint.source,
            line: lineNum,
            sanitized: false,
          });
        }
      }
      
      // Direct sanitization check on this line
      for (const san of SANITIZERS) {
        if (!san.language.includes(lang) && !san.language.includes('web')) continue;
        san.pattern.lastIndex = 0;
        if (san.pattern.test(line)) {
          // Mark all tainted vars on this line as sanitized
          // Bug fix: use word-boundary matching (was line.includes(varName))
          if (new RegExp(`\\b${varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`).test(line)) {
            taint.sanitized = true;
            taint.sanitizer = san.type;
          }
        }
      }
    }
  }
  
  // Phase 2: Check if tainted data reaches sinks
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;
    
    for (const sink of SINKS) {
      if (!sink.language.includes(lang) && !sink.language.includes('web')) continue;
      sink.pattern.lastIndex = 0;
      const sinkMatch = sink.pattern.exec(line);
      if (!sinkMatch) continue;
      
      // Check if any tainted variable reaches this sink
      for (const [varName, taint] of taintedVars) {
        // Bug fix: previously used `line.includes(varName)` which matches
        // substrings (e.g., varName='user' would match 'userBalance',
        // 'userAddress', etc.). This produced spurious taint flows.
        // Now we use word-boundary matching for both direct and indirect use.
        const varBoundaryRegex = new RegExp(`\\b${varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`);
        const directUse = (sinkMatch[1] === varName) || varBoundaryRegex.test(line);
        const indirectUse = directUse; // same check — kept for backwards-compat semantics

        if (directUse || indirectUse) {
          // Check if sanitized before this sink
          let isSanitized = taint.sanitized;
          let sanitizerName = taint.sanitizer;
          
          // Check for inline sanitization (require, if-check) before sink
          const beforeLines = lines.slice(Math.max(0, i - 5), i);
          for (const beforeLine of beforeLines) {
            for (const san of SANITIZERS) {
              if (!san.language.includes(lang)) continue;
              san.pattern.lastIndex = 0;
              if (san.pattern.test(beforeLine)) {
                isSanitized = true;
                sanitizerName = san.type;
              }
            }
          }
          
          if (!isSanitized) {
            const path = [taint.source, varName, sink.type];
            const dedupKey = `${sink.vulnerabilityType}:${taint.source}:${sink.type}`;
            
            // Avoid duplicates
            if (findings.some(f => f.type === sink.vulnerabilityType && f.source.code === taint.source)) continue;
            
            findings.push({
              type: sink.vulnerabilityType,
              title: `Taint flow: ${taint.source} → ${varName} → ${sink.type}`,
              severity: sink.severity,
              cwe: sink.cwe,
              source: {
                location: `${fileName}:L${taint.line}`,
                code: taint.source,
                line: taint.line,
              },
              sink: {
                location: `${fileName}:L${lineNum}`,
                code: line.trim().slice(0, 80),
                line: lineNum,
              },
              path,
              sanitized: false,
              confidence: 0.82,
              description: `Tainted data from ${taint.source} (line ${taint.line}) flows through variable "${varName}" to ${sink.type} sink (line ${lineNum}) without sanitization. This enables ${sink.vulnerabilityType} attacks. ${sink.description}.`,
            });
          } else if (sanitizerName) {
            // Sanitized flow — report as informational (low confidence)
            findings.push({
              type: sink.vulnerabilityType,
              title: `Sanitized taint flow: ${taint.source} → ${varName} → ${sink.type} (via ${sanitizerName})`,
              severity: 'low',
              cwe: sink.cwe,
              source: {
                location: `${fileName}:L${taint.line}`,
                code: taint.source,
                line: taint.line,
              },
              sink: {
                location: `${fileName}:L${lineNum}`,
                code: line.trim().slice(0, 80),
                line: lineNum,
              },
              path: [taint.source, varName, sanitizerName, sink.type],
              sanitized: true,
              sanitizerFound: sanitizerName,
              confidence: 0.25,
              description: `Tainted data from ${taint.source} flows to ${sink.type} but is sanitized via ${sanitizerName}. Verify the sanitizer is correctly applied and sufficient for this context.`,
            });
          }
        }
      }
    }
  }
  
  // Sort by severity then confidence
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => {
    const sevDiff = (severityOrder[a.severity as keyof typeof severityOrder] ?? 2) - 
                    (severityOrder[b.severity as keyof typeof severityOrder] ?? 2);
    if (sevDiff !== 0) return sevDiff;
    return b.confidence - a.confidence;
  });
  
  return findings;
}
