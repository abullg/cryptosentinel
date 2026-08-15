/**
 * Blockchain Verification Module
 * Provides on-chain data for vulnerability confirmation
 *
 * Capabilities:
 * - Etherscan API: contract verification, bytecode, transactions
 * - Check if contract is deployed and verified on-chain
 * - Analyze transaction patterns for exploit evidence
 * - Check known exploit databases
 * - Verify access control patterns from on-chain data
 */

const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY || '';

// Etherscan V2 API endpoints — chainid parameter added for V2 migration
const CHAIN_APIS: Record<string, { url: string; chainId: number; name: string }> = {
  ethereum:  { url: 'https://api.etherscan.io/v2/api', chainId: 1,     name: 'Ethereum Mainnet' },
  goerli:    { url: 'https://api.etherscan.io/v2/api', chainId: 5,     name: 'Goerli Testnet' },
  sepolia:   { url: 'https://api.etherscan.io/v2/api', chainId: 11155111, name: 'Sepolia Testnet' },
  bsc:       { url: 'https://api.bscscan.com/v2/api', chainId: 56,    name: 'BSC Mainnet' },
  polygon:   { url: 'https://api.polygonscan.com/v2/api', chainId: 137, name: 'Polygon Mainnet' },
  arbitrum:  { url: 'https://api.arbiscan.io/v2/api', chainId: 42161,  name: 'Arbitrum One' },
  optimism:  { url: 'https://api-optimistic.etherscan.io/v2/api', chainId: 10, name: 'Optimism' },
  base:      { url: 'https://api.basescan.org/v2/api', chainId: 8453,  name: 'Base' },
  avalanche: { url: 'https://api.snowtrace.io/api', chainId: 43114,   name: 'Avalanche C-Chain' },
  fantom:    { url: 'https://api.ftmscan.com/api', chainId: 250,      name: 'Fantom Opera' },
};

export interface BlockchainVerificationResult {
  address: string;
  chain: string;
  isDeployed: boolean;
  isVerified: boolean;
  contractName?: string;
  compilerVersion?: string;
  balance?: string;
  txCount?: number;
  creationTx?: string;
  creator?: string;
  timestamp?: string;
  // Analysis data
  hasRecentActivity: boolean;
  suspiciousPatterns: string[];
  knownExploits: string[];
  // Raw data for AI analysis
  rawData: string;
}

export interface ContractAddressInfo {
  address: string;
  chain: string;
}

/**
 * Extract potential contract addresses from source code or context
 * Looks for Ethereum addresses (0x...) that might be deployed contracts
 */
export function extractContractAddresses(sourceCode: string, projectName?: string): ContractAddressInfo[] {
  const addresses: ContractAddressInfo[] = [];
  // Match Ethereum addresses (42 chars: 0x + 40 hex digits)
  const addressPattern = /0x[0-9a-fA-F]{40}/g;
  const matches = sourceCode.match(addressPattern) || [];

  // Filter out obvious non-contract addresses
  const skipPatterns = [
    /^0x0{40}$/i,          // Zero address
    /^0xdEaD$/i,           // DEAD address
    /^0x0{8}1{32}$/i,     // Precompile addresses
    /^0x0{38}01$/i,       // Precompile 1
    /^0x0{38}02$/i,       // Precompile 2
    /^0x0{38}03$/i,       // Precompile 3
    /^0x0{38}04$/i,       // Precompile 4
  ];

  const uniqueAddresses = [...new Set(matches)];
  for (const addr of uniqueAddresses) {
    if (skipPatterns.some(p => p.test(addr))) continue;
    if (addr === '0x0000000000000000000000000000000000000000') continue;
    addresses.push({ address: addr, chain: 'ethereum' });
  }

  return addresses.slice(0, 10); // Cap at 10 addresses
}

/**
 * Query Etherscan-like API for contract information
 */
async function queryBlockExplorer(
  chain: string,
  address: string,
  action: string,
  module: string
): Promise<unknown> {
  const chainApi = CHAIN_APIS[chain] || CHAIN_APIS.ethereum;
  // V2 API requires chainid parameter
  const url = `${chainApi.url}?chainid=${chainApi.chainId}&module=${module}&action=${action}&address=${address}${ETHERSCAN_API_KEY ? `&apikey=${ETHERSCAN_API_KEY}` : ''}`;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);

  try {
    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timeout);
    if (!response.ok) return null;
    const data = await response.json();
    return data;
  } catch {
    clearTimeout(timeout);
    return null;
  }
}

/**
 * Verify a contract on blockchain — get deployment info, verification status, etc.
 */
export async function verifyContractOnChain(
  addressInfo: ContractAddressInfo
): Promise<BlockchainVerificationResult> {
  const { address, chain } = addressInfo;
  const chainApi = CHAIN_APIS[chain] || CHAIN_APIS.ethereum;

  const result: BlockchainVerificationResult = {
    address,
    chain,
    isDeployed: false,
    isVerified: false,
    hasRecentActivity: false,
    suspiciousPatterns: [],
    knownExploits: [],
    rawData: '',
  };

  // Query 1: Check if contract is verified (get contract ABI/source)
  const verifyData = await queryBlockExplorer(chain, address, 'getsourcecode', 'contract');
  if (verifyData && typeof verifyData === 'object' && 'result' in (verifyData as Record<string, unknown>)) {
    const verifyResult = (verifyData as { result: Record<string, unknown>[] }).result;
    if (Array.isArray(verifyResult) && verifyResult.length > 0) {
      const info = verifyResult[0];
      result.isVerified = info.CompilerVersion !== '' && info.CompilerVersion !== undefined;
      result.contractName = info.ContractName as string || undefined;
      result.compilerVersion = info.CompilerVersion as string || undefined;
      result.isDeployed = true; // If Etherscan returns data, contract exists
    }
  }

  // Query 2: Get contract balance
  const balanceData = await queryBlockExplorer(chain, address, 'balance', 'account');
  if (balanceData && typeof balanceData === 'object' && 'result' in (balanceData as Record<string, unknown>)) {
    const bal = (balanceData as { result: string }).result;
    if (bal && bal !== '0') {
      result.balance = bal;
      result.isDeployed = true;
    }
  }

  // Query 3: Get normal transaction count
  const txData = await queryBlockExplorer(chain, address, 'txlist', 'account');
  if (txData && typeof txData === 'object' && 'result' in (txData as Record<string, unknown>)) {
    const txs = (txData as { result: Record<string, unknown>[] }).result;
    if (Array.isArray(txs)) {
      result.txCount = txs.length;
      result.isDeployed = txs.length > 0;

      // Check for recent activity (last 30 days)
      const thirtyDaysAgo = Date.now() / 1000 - 30 * 24 * 60 * 60;
      const recentTxs = txs.filter((tx: Record<string, unknown>) => {
        const ts = Number(tx.timeStamp);
        return ts > thirtyDaysAgo;
      });
      result.hasRecentActivity = recentTxs.length > 0;

      // Analyze transaction patterns for suspicious activity
      analyzeTransactionPatterns(txs, result);

      // Get creation transaction info
      if (txs.length > 0) {
        const firstTx = txs[0] as Record<string, string>;
        result.creationTx = firstTx.hash;
        result.creator = firstTx.from;
        result.timestamp = firstTx.timeStamp;
      }
    }
  }

  // Build raw data string for AI analysis
  result.rawData = buildRawDataString(result, chainApi.name);

  return result;
}

/**
 * Analyze transaction patterns for suspicious activity
 */
function analyzeTransactionPatterns(
  txs: Record<string, unknown>[],
  result: BlockchainVerificationResult
): void {
  if (txs.length === 0) return;

  // Pattern 1: Many failed transactions (possible attack attempts)
  const failedTxs = txs.filter((tx: Record<string, unknown>) => {
    const status = Number(tx.isError || tx.status || 1);
    return status === 0 || status === 2; // isError=1 means error on Etherscan
  });
  if (failedTxs.length > txs.length * 0.3) {
    result.suspiciousPatterns.push(`High failure rate: ${failedTxs.length}/${txs.length} transactions failed — may indicate attack attempts or buggy interactions`);
  }

  // Pattern 2: Large value transfers out (potential drain)
  const largeOutTxs = txs.filter((tx: Record<string, unknown>) => {
    const value = BigInt(String(tx.value || '0'));
    return value > BigInt('1000000000000000000000'); // > 1000 ETH
  });
  if (largeOutTxs.length > 0) {
    result.suspiciousPatterns.push(`${largeOutTxs.length} transactions with >1000 ETH value — possible fund drainage`);
  }

  // Pattern 3: Same address calling repeatedly (possible reentrancy attack)
  const callerCounts: Record<string, number> = {};
  for (const tx of txs) {
    const from = String(tx.from || '');
    callerCounts[from] = (callerCounts[from] || 0) + 1;
  }
  const topCallers = Object.entries(callerCounts)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 3);
  if (topCallers[0] && topCallers[0][1] > 10) {
    result.suspiciousPatterns.push(`Address ${topCallers[0][0]} called contract ${topCallers[0][1]} times — possible repeated interaction attack`);
  }

  // Pattern 4: Internal transactions (possible delegatecall/proxy patterns)
  const internalTxs = txs.filter((tx: Record<string, unknown>) => {
    return String(tx.type || '') === '2' || String(tx.input || '').length > 10;
  });
  if (internalTxs.length > txs.length * 0.5) {
    result.suspiciousPatterns.push(`${internalTxs.length} complex transactions with function calls — verify access control on all called functions`);
  }
}

/**
 * Build raw data string for AI consumption
 */
function buildRawDataString(result: BlockchainVerificationResult, chainName: string): string {
  const lines: string[] = [];
  lines.push(`Chain: ${chainName}`);
  lines.push(`Address: ${result.address}`);
  lines.push(`Deployed: ${result.isDeployed}`);
  lines.push(`Source Verified: ${result.isVerified}`);
  if (result.contractName) lines.push(`Contract Name: ${result.contractName}`);
  if (result.compilerVersion) lines.push(`Compiler: ${result.compilerVersion}`);
  if (result.balance) lines.push(`Balance (wei): ${result.balance}`);
  if (result.txCount !== undefined) lines.push(`Transaction Count: ${result.txCount}`);
  if (result.creator) lines.push(`Creator: ${result.creator}`);
  if (result.creationTx) lines.push(`Creation TX: ${result.creationTx}`);
  lines.push(`Recent Activity (30d): ${result.hasRecentActivity}`);
  if (result.suspiciousPatterns.length > 0) {
    lines.push(`Suspicious Patterns:`);
    for (const p of result.suspiciousPatterns) {
      lines.push(`  - ${p}`);
    }
  }
  return lines.join('\n');
}

/**
 * Check for known exploits in public databases
 * Uses a local database of known exploit patterns
 */
export function checkKnownExploits(
  contractName: string,
  sourceCode: string
): string[] {
  const exploits: string[] = [];

  // Known exploit signatures in source code
  const signatures: Array<{ pattern: RegExp; exploit: string }> = [
    {
      pattern: /function\s+withdraw\s*\([^)]*\)\s*(?:public|external)(?:(?!nonReentrant)[\s\S])*?\{/i,
      exploit: 'Similar to DAO hack pattern — withdraw without reentrancy guard',
    },
    {
      pattern: /delegatecall\s*\(/i,
      exploit: 'Delegatecall usage — similar to Parity Wallet hack vector',
    },
    {
      pattern: /tx\.origin/i,
      exploit: 'tx.origin usage — phishing attack vector (similar to known ERC-20 phishing)',
    },
    {
      pattern: /assembly\s*\{/i,
      exploit: 'Inline assembly — similar to exploits in multiple DeFi protocols',
    },
    {
      pattern: /selfdestruct\s*\(/i,
      exploit: 'Self-destruct pattern — similar to Parity Wallet kill vulnerability',
    },
    {
      pattern: /call\.value/i,
      exploit: 'Low-level call.value — similar to multiple reentrancy exploits',
    },
  ];

  for (const { pattern, exploit } of signatures) {
    if (pattern.test(sourceCode)) {
      exploits.push(exploit);
    }
  }

  return exploits;
}

/**
 * Run full blockchain verification pipeline
 * Returns formatted context string for AI analysis
 */
export async function runBlockchainVerification(
  sourceCode: string,
  contractName?: string,
  providedAddress?: string
): Promise<string> {
  const contextLines: string[] = [];
  contextLines.push('=== BLOCKCHAIN VERIFICATION DATA ===');

  // Step 1: Check known exploits (always available, no API needed)
  const knownExploits = checkKnownExploits(contractName || '', sourceCode);
  if (knownExploits.length > 0) {
    contextLines.push('\nKNOWN EXPLOIT PATTERNS DETECTED:');
    for (const exploit of knownExploits) {
      contextLines.push(`  - ${exploit}`);
    }
  }

  // Step 2: If a contract address is provided, verify on-chain
  if (providedAddress && /^0x[0-9a-fA-F]{40}$/.test(providedAddress)) {
    contextLines.push('\nON-CHAIN VERIFICATION:');
    const chains = ['ethereum', 'bsc', 'polygon', 'arbitrum', 'optimism', 'base'];

    // Try to verify on each chain (in parallel, take first success)
    const verifyPromises = chains.map(async (chain) => {
      try {
        return await verifyContractOnChain({ address: providedAddress, chain });
      } catch {
        return null;
      }
    });

    const results = await Promise.allSettled(verifyPromises);
    let foundOnChain = false;

    for (const r of results) {
      if (r.status === 'fulfilled' && r.value && r.value.isDeployed) {
        foundOnChain = true;
        contextLines.push(`\nChain: ${r.value.chain}`);
        contextLines.push(r.value.rawData);
        if (r.value.suspiciousPatterns.length > 0) {
          contextLines.push('\nSUSPICIOUS ON-CHAIN PATTERNS:');
          for (const p of r.value.suspiciousPatterns) {
            contextLines.push(`  - ${p}`);
          }
        }
      }
    }

    if (!foundOnChain) {
      contextLines.push(`Address ${providedAddress} not found on any checked chain. Contract may be on an unsupported chain or address may be incorrect.`);
    }
  } else {
    // Step 3: Extract addresses from source code
    const addresses = extractContractAddresses(sourceCode, contractName);
    if (addresses.length > 0) {
      contextLines.push(`\nEXTRACTED ADDRESSES FROM SOURCE: ${addresses.length} found`);
      for (const addr of addresses.slice(0, 5)) {
        contextLines.push(`  - ${addr.address} (chain: ${addr.chain})`);
      }
      contextLines.push('Note: Provide a contract address for full on-chain verification.');
    } else {
      contextLines.push('\nNo contract addresses found in source code. Provide an address for on-chain verification.');
    }
  }

  // Step 4: Source code static patterns (always available)
  contextLines.push('\nSOURCE CODE ANALYSIS (for blockchain context):');
  const codePatterns: string[] = [];

  if (/pragma solidity[^;]*0\.[0-7]\./.test(sourceCode)) {
    codePatterns.push('Solidity version <0.8.0 — integer overflow/underflow possible without SafeMath');
  }
  if (/payable\s*\(/.test(sourceCode) && !/nonReentrant/.test(sourceCode)) {
    codePatterns.push('Payable functions without reentrancy guard — potential reentrancy vector');
  }
  if (/onlyOwner|onlyAdmin|onlyRole/.test(sourceCode) && /owner\s*=\s*msg\.sender/.test(sourceCode)) {
    codePatterns.push('Owner-privileged pattern — check for centralization risk and governance');
  }
  if (/import.*proxy|import.*upgradeable|Initializable/.test(sourceCode)) {
    codePatterns.push('Upgradeable/proxy pattern — verify implementation slot and admin access');
  }

  if (codePatterns.length > 0) {
    for (const p of codePatterns) {
      contextLines.push(`  - ${p}`);
    }
  } else {
    contextLines.push('  No critical blockchain-relevant patterns detected in static analysis.');
  }

  contextLines.push('\n=== END BLOCKCHAIN VERIFICATION DATA ===');
  return contextLines.join('\n');
}
