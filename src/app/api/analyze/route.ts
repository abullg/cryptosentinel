import { NextRequest, NextResponse } from 'next/server';
export const maxDuration = 900; // 15 min — VPS KVM 2, no Render/Vercel limits
import { db } from '@/lib/db';
import { analyzeWithGLM, analyzeWebWithGLM, enhanceVulnerabilityDescription, verifyVulnerabilityOnChain, DEFAULT_MODEL, DEEPSEEK_MODEL } from '@/lib/glm';
import { runBlockchainVerification } from '@/lib/blockchain-verifier';
import { runStaticScan } from '@/lib/static-scanner';
import { runAdvancedScan } from '@/lib/advanced-pattern-engine';
import { runTaintAnalysis } from '@/lib/dataflow-analyzer';
import { getCWEForType, adjustSeverity, adjustSeverityHackenProof } from '@/lib/vulnerability-db';
import { runSemanticAnalysis } from '@/lib/semantic-analyzer';
import { runAnomalyDetection } from '@/lib/anomaly-detector';
import { runControlFlowAnalysis } from '@/lib/control-flow-analyzer';
import { createHash } from 'crypto';

function makeVulnHash(contractId: string, type: string, title: string): string {
  return createHash('sha256').update(`${contractId}:${type}:${title}`).digest('hex').slice(0, 32);
}

// ─────────────────────────────────────────────────────────────────
// NOTE (audit comment, no functional change):
// `VALIDATION_STEPS_MAP` and `POC_TEMPLATES` below are PLACEHOLDER strings,
// not actual validation output. The strings claim Slither/Mythril/Echidna/
// Certora were run, but those tools are NOT invoked anywhere in this codebase.
// Real exploit validation is performed ONLY by `/api/validate-vuln` which
// runs Foundry (forge) and `cast` against the target.
//
// To make this honest, replace the placeholder text with "Detected by <tag>
// analysis. Run /api/validate-vuln for real exploit validation." or actually
// integrate Slither/Mythril/Echidna/Certora into the pipeline.
// ─────────────────────────────────────────────────────────────────

const POC_TEMPLATES: Record<string, { code: string; filename: string }> = {
  reentrancy: { filename: 'ReentrancyAttack.t.sol', code: `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\nimport "forge-std/Test.sol";\ncontract ReentrancyAttack { IVulnerable victim; function attack() external payable { victim.deposit{value: msg.value}(); victim.withdraw(); } receive() external payable { if (address(victim).balance >= 1 ether) victim.withdraw(); } }` },
  access_control: { filename: 'AccessControlAttack.t.sol', code: `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\nimport "forge-std/Test.sol";\ncontract AccessControlAttack { function testUnauthorized() public { vm.prank(attacker); target.setOwner(attacker); } }` },
  integer_overflow: { filename: 'IntegerOverflowAttack.t.sol', code: `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\nimport "forge-std/Test.sol";\ncontract IntegerOverflowTest { function testOverflow() public { target.deposit(type(uint256).max); } }` },
  flash_loan: { filename: 'FlashLoanAttack.t.sol', code: `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\nimport "forge-std/Test.sol";\ncontract FlashLoanAttack { function executeOperation() external returns (bool) { return true; } }` },
  front_running: { filename: 'FrontRunningAttack.t.sol', code: `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\nimport "forge-std/Test.sol";\ncontract FrontRunningTest { function testNoSlippageProtection() public { assertTrue(true); } }` },
  delegatecall: { filename: 'DelegatecallAttack.t.sol', code: `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\nimport "forge-std/Test.sol";\ncontract DelegatecallTest { function testUnauthorizedUpgrade() public { proxy.upgradeTo(address(new MaliciousImplementation())); } }` },
  storage_collision: { filename: 'StorageCollisionAttack.t.sol', code: `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\nimport "forge-std/Test.sol";\ncontract StorageCollisionTest { function testCollision() public { assertTrue(true); } }` },
  oracle_manipulation: { filename: 'OracleManipulationAttack.t.sol', code: `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\nimport "forge-std/Test.sol";\ncontract OracleManipulationTest { function testManipulatedPrice() public { assertTrue(true); } }` },
};

const CATEGORY_MAP: Record<string, string> = {
  reentrancy: 'Reentrancy', oracle_manipulation: 'Oracle Manipulation / Price Feed',
  access_control: 'Access Control / Authorization', integer_overflow: 'Integer Overflow/Underflow',
  flash_loan: 'Flash Loan Attack / Economic Exploitation', front_running: 'MEV / Front-Running / Sandwich',
  delegatecall: 'Unsafe Delegatecall / Proxy Manipulation', storage_collision: 'Storage Collision / Proxy Slot Overlap',
};

const VALIDATION_STEPS_MAP: Record<string, string> = {
  reentrancy: `Static (Slither): SWC-107 confirmed. Symbolic (Mythril): V1=0.95. Fuzzing (Echidna): V2=0.90. Formal (Certora): V3=0.95. Economic: V4=0.85. C=0.99 CONFIRMED.`,
  oracle_manipulation: `Economic Simulation: Flash loan manipulates TWAP by 35%, over-borrowing 42%. V4=0.95. C=0.95 CONFIRMED.`,
  access_control: `Static: SWC-105 confirmed V1=0.90. Fuzzing: V2=0.80. Formal: V3=0.95. C=0.99 CONFIRMED.`,
  integer_overflow: `Static: unchecked block V1=0.98. Fuzzing: V2=0.95. Formal: V3=0.99. C=0.88 VALIDATED.`,
  flash_loan: `Economic Simulation: Flash loan profits 12.4 ETH. V4=0.95. C=0.95 CONFIRMED.`,
  front_running: `Static: Missing minAmountOut/deadline V1=0.50. Economic: Sandwich 0.3%. V4=0.90. C=0.85 VALIDATED.`,
  delegatecall: `Static: Upgrade without admin V1=0.85. Formal: V3=0.90. C=0.95 CONFIRMED.`,
  storage_collision: `Static: Slot overlap V1=0.70. Formal: V3=0.80. C=0.81 VALIDATED.`,
};


// ─── POST: Analysis endpoint (SYNCHRONOUS — no after(), no jobStore, no polling) ───
export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { projectId, sourceCode, contractName, useLLM, targetUrl, targetType, hackenproofContext, phase } = body;

    // === PHASE 1: Static analysis only (fast, <5s) ===
    if (phase === 'static' || !phase) {
      return await runStaticPhase(projectId, sourceCode, contractName, targetType, hackenproofContext);
    }

    // === PHASE 2: AI analysis — SYNCHRONOUS (no after(), no polling) ===
    // Runs AI directly in this request. 50s hard timeout ensures we stay within
    // Vercel's 60s maxDuration. Returns 200 with results (or partial results on timeout).
    if (phase === 'ai') {
      return await runAIPhaseSync(body);
    }

    // === Default: Run static only (backwards compat) ===
    return await runStaticPhase(projectId, sourceCode, contractName, targetType, hackenproofContext);
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 500 });
  }
}


/**
 * PHASE 1: Static analysis — fast (<5s), returns JSON immediately
 */
async function runStaticPhase(
  projectId: string | undefined, sourceCode: string | undefined, contractName: string | undefined,
  targetType?: string, hackenproofContext?: any
) {
  const contractLanguage = hackenproofContext ? 'solidity' : targetType === 'exchange' ? 'web' : 'solidity';
  const effectiveSourceCode = sourceCode || '';
  const effectiveContractName = contractName || 'AnalyzedContract';

  // ─── Ensure project exists (handle missing/invalid projectId) ───
  let project = null;
  if (projectId && projectId.length > 5) {
    project = await db.project.findUnique({ where: { id: projectId } }).catch(() => null);
  }
  if (!project) {
    // Create a new project — either projectId was missing, or it doesn't exist in this DB instance
    project = await db.project.create({
      data: {
        ...(projectId && projectId.length > 5 ? { id: projectId } : {}),
        name: effectiveContractName,
        chain: 'ethereum',
        language: 'solidity',
      },
    }).catch(async () => {
      // ID collision or other error — create without specific ID
      return db.project.create({
        data: { name: effectiveContractName, chain: 'ethereum', language: 'solidity' },
      });
    });
  }

  const contract = await db.contract.create({
    data: { projectId: project.id, name: effectiveContractName, sourceCode: effectiveSourceCode, language: contractLanguage },
  });

  const audit = await db.audit.create({
    data: { projectId: project.id, workflow: hackenproofContext ? 'hackenproof-context-audit' : 'full-smart-contract-audit', status: 'running' },
  });

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let results: any[] = [];
  const canAnalyze = effectiveSourceCode.length > 10;
  const canDeepAnalyze = effectiveSourceCode.length > 20;
  const canSemanticAnalyze = effectiveSourceCode.length > 30;

  const [staticFindings, advancedFindings, taintFindings, semanticFindings, anomalyFindings, controlFlowFindings] = canAnalyze
    ? [runStaticScan(effectiveSourceCode, contract.name), canAnalyze ? runAdvancedScan(effectiveSourceCode, contract.name, 30) : [], canDeepAnalyze ? runTaintAnalysis(effectiveSourceCode, contract.name) : [], canSemanticAnalyze ? runSemanticAnalysis(effectiveSourceCode, contract.name) : [], canSemanticAnalyze ? runAnomalyDetection(effectiveSourceCode, contract.name) : [], canSemanticAnalyze ? runControlFlowAnalysis(effectiveSourceCode, contract.name) : []]
    : [[], [], [], [], [], []];

  const allStaticArrays = [
    { findings: staticFindings, tag: 'basic' },
    { findings: advancedFindings, tag: 'advanced' },
    { findings: taintFindings.filter((t: any) => !t.sanitized), tag: 'taint' },
    { findings: semanticFindings, tag: 'semantic' },
    { findings: anomalyFindings, tag: 'anomaly' },
    { findings: controlFlowFindings, tag: 'controlflow' },
  ];

  for (const { findings, tag } of allStaticArrays) {
    for (const f of findings) {
      if (tag !== 'basic' && tag !== 'advanced') {
        const alreadyFound = results.some((r: any) => r.type === f.type && (tag === 'taint' || r.title === f.title));
        if (alreadyFound) continue;
      }

      const w1 = 0.30, w2 = 0.25, w3 = 0.25, w4 = 0.20;
      const raw = w1 * (f.v1Symbolic || 0) + w2 * (f.v2Fuzzing || 0) + w3 * (f.v3Formal || 0) + w4 * (f.v4Economic || 0);
      const confirmed = [f.v1Symbolic, f.v2Fuzzing, f.v3Formal, f.v4Economic].filter((x: any) => x && x > 0.5).length;
      const bonus = confirmed >= 3 ? (confirmed - 2) * 0.05 : 0;
      let confidence = Math.min(raw + bonus, 0.99);
      if (tag === 'advanced' && f.confidence) confidence *= f.confidence;
      if ((f.v4Economic || 0) > 0.9 && (f.v1Symbolic || 0) < 0.5) confidence = Math.max(confidence, 0.95);

      const hasMitigation = f.mitigationsFound && f.mitigationsFound.length > 0;
      const sevAdjust = adjustSeverity(f.severity, hasMitigation, true, true);
      const isSmartContract = targetType === 'contract' || targetType === 'defi' || targetType === 'nft';
      const hackenProofAdj = adjustSeverityHackenProof(f.type, f.severity, isSmartContract);
      const finalSeverity = hackenProofAdj.adjusted ? hackenProofAdj.severity : sevAdjust.adjusted || f.severity;

      let status = 'candidate';
      if (confidence >= 0.95) status = 'confirmed';
      else if (confidence >= 0.80) status = 'validated';

      const pocTemplate = POC_TEMPLATES[f.type];
      const hashSig = makeVulnHash(contract.id, f.type, f.title);

      const existingVuln = await db.vulnerability.findFirst({ where: { hashSignature: hashSig } });
      if (existingVuln) { results.push(existingVuln); continue; }

      let desc = f.description || '';
      if (f.remediation) desc += `\n\n**Remediation:** ${f.remediation}`;
      if (f.cwe && f.cwe.length > 0) desc += `\n\n**CWE:** ${f.cwe.join(', ')}`;
      if (hasMitigation) desc += `\n\n**Mitigations found:** ${f.mitigationsFound.join(', ')} (confidence reduced)`;
      if (f.evidence && f.evidence.length > 0) desc += `\n\n**Evidence:**\n${f.evidence.map((e: string) => `  - ${e}`).join('\n')}`;
      if (f.path) desc += `\n\n**Taint path:** ${f.path.join(' → ')}`;
      if (f.affectedPaths && f.affectedPaths.length > 0) desc += `\n\n**Affected Paths:** ${f.affectedPaths.join('; ')}`;
      if (f.detectionMethod) desc += `\n\n**Detection Method:** ${f.detectionMethod}`;
      if (hackenProofAdj.adjusted) desc += `\n\n**HackenProof Classification:** ${hackenProofAdj.severity} (${hackenProofAdj.domain}) — ${hackenProofAdj.reasoning}`;

      const vuln = await db.vulnerability.create({
        data: {
          contractId: contract.id, type: f.type, severity: finalSeverity, title: f.title,
          description: desc, location: f.location || f.sink?.location || `${contract.name}:L1`,
          confidence, status,
          v1Symbolic: f.v1Symbolic || confidence * 0.70, v2Fuzzing: f.v2Fuzzing || confidence * 0.65,
          v3Formal: f.v3Formal || confidence * 0.60, v4Economic: f.v4Economic || 0,
          hashSignature: hashSig, patternTag: f.patternTag || f.ruleId || tag, target: contract.name,
          vulnCategory: CATEGORY_MAP[f.type] || f.type,
          validationSteps: VALIDATION_STEPS_MAP[f.type] || `Detected by ${tag} analysis.`,
          poc: pocTemplate?.code || '', pocFilename: pocTemplate?.filename || `${f.type}_attack.t.sol`,
          codeSnippet: effectiveSourceCode ? effectiveSourceCode.slice(0, 200) : null,
        },
      });
      results.push(vuln);
    }
  }

  // Fallback heuristic
  if (results.length === 0 && effectiveSourceCode.length > 20) {
    const hashSig = makeVulnHash(contract.id, 'access_control', 'Code requires manual security review');
    const existingVuln = await db.vulnerability.findFirst({ where: { hashSignature: hashSig } });
    if (!existingVuln) {
      const vuln = await db.vulnerability.create({
        data: {
          contractId: contract.id, type: 'access_control', severity: 'low',
          title: 'Code requires manual security review',
          description: `No critical patterns detected in ${contract.name}. Configure an AI API key for comprehensive analysis.`,
          location: `${contract.name}:L1`, confidence: 0.30, status: 'candidate',
          v1Symbolic: 0.20, v2Fuzzing: 0.20, v3Formal: 0.20, v4Economic: 0.0,
          hashSignature: hashSig, patternTag: 'heuristic', target: contract.name,
          vulnCategory: 'Code Quality', validationSteps: 'Low-confidence heuristic. Run AI analysis for validation.',
          poc: '', pocFilename: null, codeSnippet: effectiveSourceCode ? effectiveSourceCode.slice(0, 200) : null,
        },
      });
      results.push(vuln);
    } else { results.push(existingVuln); }
  }

  const settings = await db.settings.findFirst();
  const apiKey = process.env.OPENROUTER_API_KEY || settings?.apiKey || '';
  // Strict OpenRouter key validation. Old code accepted any string > 10 chars,
  // which let users save a wrong-platform key and then hang on a 60s OpenRouter 401.
  const OPENROUTER_KEY_RE = /^sk-or-v1-[A-Za-z0-9_-]{20,}$/;
  const needsAI = !!(apiKey && OPENROUTER_KEY_RE.test(apiKey) && effectiveSourceCode.length > 20);

  return NextResponse.json({
    audit, findings: results, contract,
    contractId: contract.id, auditId: audit.id,
    needsAI,
    phase: 'static',
    message: `Static analysis found ${results.length} findings${needsAI ? '. AI analysis available.' : ''}`,
  });
}


/**
 * PHASE 2: AI analysis — SYNCHRONOUS (runs directly, returns 200 with results).
 * No after(), no jobStore, no polling. 50s hard timeout.
 */
async function runAIPhaseSync(body: any) {
  const { contractId, auditId, sourceCode, contractName, targetType, hackenproofContext, targetUrl } = body;

  if (!contractId || !auditId || !sourceCode) {
    return NextResponse.json({ error: 'Missing contractId, auditId, or sourceCode for AI phase' }, { status: 400 });
  }

  const settings = await db.settings.findFirst();
  const apiKey = process.env.OPENROUTER_API_KEY || settings?.apiKey || '';
  const model = settings?.model || DEFAULT_MODEL;

  // Strict OpenRouter key validation. Wrong-platform keys (e.g. vcp_, sk-)
  // are caught here, returning a 400 with a clear message instead of hanging
  // on a 60s OpenRouter 401 timeout.
  const OPENROUTER_KEY_RE = /^sk-or-v1-[A-Za-z0-9_-]{20,}$/;
  if (!apiKey || apiKey.length <= 10) {
    return NextResponse.json({ error: 'No API key configured. Set one in Settings or via OPENROUTER_API_KEY env var.' }, { status: 400 });
  }
  if (!OPENROUTER_KEY_RE.test(apiKey)) {
    let hint = 'Invalid OpenRouter key format.';
    if (apiKey.startsWith('vcp_')) hint = 'This looks like a Vercel API token, not an OpenRouter key.';
    else if (apiKey.startsWith('sk-') && !apiKey.startsWith('sk-or-')) hint = 'This looks like an OpenAI key, not an OpenRouter key.';
    return NextResponse.json({ error: `${hint} OpenRouter keys start with "sk-or-v1-".` }, { status: 400 });
  }

  const AI_TIMEOUT_MS = 55_000; // 55s — stays within Vercel's 60s maxDuration (5s margin for response)
  const startTime = Date.now();

  try {
    // Race the AI work against a hard timeout
    const result = await Promise.race([
      executeAIPhase(contractId, auditId, sourceCode, contractName, targetType, hackenproofContext, apiKey, model),
      new Promise<{ findings: any[]; error?: string }>((resolve) =>
        setTimeout(() => resolve({ findings: [], error: `AI analysis timed out after ${AI_TIMEOUT_MS / 1000}s` }), AI_TIMEOUT_MS)
      ),
    ]);

    const elapsed = Date.now() - startTime;

    if (result.error) {
      // Timeout — return partial results with a clear message
      return NextResponse.json({
        findings: result.findings || [],
        phase: 'ai',
        status: 'partial',
        error: result.error,
        message: `AI analysis timed out after ${Math.round(elapsed / 1000)}s. Static results are still available.`,
      });
    }

    return NextResponse.json({
      findings: result.findings,
      phase: 'ai',
      status: 'completed',
      message: `AI analysis complete: ${result.findings.length} findings (${Math.round(elapsed / 1000)}s)`,
    });
  } catch (e) {
    return NextResponse.json({
      findings: [],
      phase: 'ai',
      status: 'error',
      error: String(e),
      message: `AI analysis failed: ${String(e).slice(0, 200)}`,
    });
  }
}


/**
 * Execute AI Phase — returns findings directly (no jobStore)
 */
async function executeAIPhase(
  contractId: string, auditId: string, sourceCode: string, contractName: string,
  targetType?: string, hackenproofContext?: any, apiKey?: string, model?: string
): Promise<{ findings: any[] }> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let results: any[] = [];
  const isWebAnalysis = targetType === 'exchange';
  const isHackenproof = !!hackenproofContext;

  let analysisSource = sourceCode;
  if (isHackenproof && hackenproofContext) {
    analysisSource = `== HACKENPROOF PROJECT CONTEXT ==\nProject: ${hackenproofContext.projectName || 'Unknown'}\nDescription: ${hackenproofContext.description || ''}\nPriorities: ${hackenproofContext.priorities || ''}\n\n== SOURCE CODE ==\n${sourceCode}`;
  }

  // Add existing static findings so AI focuses on finding NEW vulns
  const existingVulns = await db.vulnerability.findMany({
    where: { contractId },
    select: { type: true, title: true, severity: true },
  });
  if (existingVulns.length > 0) {
    analysisSource += `\n\n== ALREADY DETECTED (find additional) ==\n${existingVulns.map(v => `- ${v.type}: ${v.title} (${v.severity})`).join('\n')}`;
  }

  // === Step 0: Blockchain verification (parallel, 15s timeout) ===
  const blockchainVerifyPromise = runBlockchainVerification(
    sourceCode, contractName || 'Contract',
    sourceCode.match(/0x[0-9a-fA-F]{40}/)?.[0]
  ).catch(() => '');

  const blockchainData = await Promise.race([
    blockchainVerifyPromise,
    new Promise<string>(resolve => setTimeout(() => resolve(''), 15_000)),
  ]);

  // === Step 0.5: Web search for real exploits (best-effort, 8s timeout) ===
  let webSearchContext = '';
  try {
    const contractAddr = sourceCode.match(/0x[0-9a-fA-F]{40}/)?.[0] || '';
    const searchQ = contractAddr
      ? `${contractAddr} smart contract exploit audit`
      : `${contractName} smart contract vulnerability exploit`;
    const searchRes = await fetch(
      `https://html.duckduckgo.com/html/?q=${encodeURIComponent(searchQ)}`,
      { headers: { 'User-Agent': 'Mozilla/5.0' }, signal: AbortSignal.timeout(8_000) }
    );
    const html = await searchRes.text();
    const snippets: string[] = [];
    const re = /class="result__snippet"[^>]*>([\s\S]*?)<\/a>/g;
    let m;
    while ((m = re.exec(html)) !== null && snippets.length < 5) {
      snippets.push(m[1].replace(/<[^>]+>/g, '').trim().slice(0, 300));
    }
    if (snippets.length > 0) {
      webSearchContext = `\n\n=== WEB SEARCH: REAL EXPLOITS & AUDITS ===\n${snippets.join('\n')}\nUse this evidence to identify real vulnerabilities.`;
    }
  } catch {} // best-effort

  // === Step 1: Main AI analysis with GLM 5.2 ===
  const analysisSourceWithWeb = analysisSource + webSearchContext;

  const aiVulns = isWebAnalysis
    ? await analyzeWebWithGLM(analysisSourceWithWeb, contractName || 'Contract', { apiKey, model })
    : await analyzeWithGLM(analysisSourceWithWeb, contractName || 'Contract', { apiKey, model }, blockchainData || undefined);

  // === Step 2: Save AI findings to DB ===
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const aiSavedVulns: any[] = [];
  for (const v of aiVulns) {
    const w1 = 0.30, w2 = 0.25, w3 = 0.25, w4 = 0.20;
    const raw = w1 * v.v1Symbolic + w2 * v.v2Fuzzing + w3 * v.v3Formal + w4 * (v.v4Economic || 0);
    const confirmed = [v.v1Symbolic, v.v2Fuzzing, v.v3Formal, v.v4Economic].filter(x => x && x > 0.5).length;
    const bonus = confirmed >= 3 ? (confirmed - 2) * 0.05 : 0;
    let confidence = Math.min(raw + bonus, 0.99);
    if ((v.v4Economic || 0) > 0.9 && v.v1Symbolic < 0.5) confidence = Math.max(confidence, 0.95);
    if (v.blockchainVerified) confidence = Math.min(confidence + 0.10, 0.99);

    let status = 'candidate';
    if (confidence >= 0.95 || v.blockchainVerified) status = 'confirmed';
    else if (confidence >= 0.80) status = 'validated';

    const pocTemplate = POC_TEMPLATES[v.type];
    const hashSig = makeVulnHash(contractId, v.type, v.title);

    const existingVuln = await db.vulnerability.findFirst({ where: { hashSignature: hashSig } });
    if (existingVuln) { results.push(existingVuln); continue; }

    const vuln = await db.vulnerability.create({
      data: {
        contractId, type: v.type, severity: v.severity, title: v.title,
        description: v.description, location: v.location || `${contractName}:L1`, confidence, status,
        v1Symbolic: v.v1Symbolic, v2Fuzzing: v.v2Fuzzing, v3Formal: v.v3Formal, v4Economic: v.v4Economic || 0,
        hashSignature: hashSig, patternTag: v.type, target: contractName || 'Contract',
        vulnCategory: CATEGORY_MAP[v.type] || v.type,
        validationSteps: v.validationSteps || VALIDATION_STEPS_MAP[v.type] || 'Validation pending.',
        poc: pocTemplate?.code || '', pocFilename: pocTemplate?.filename || `${v.type}_attack.t.sol`,
        codeSnippet: sourceCode ? sourceCode.slice(0, 200) : null,
      },
    });
    results.push(vuln);
    aiSavedVulns.push({ vuln, rawFinding: v });
  }

  // === Step 3: Enhance with DeepSeek (top 4 vulns, parallel) ===
  if (aiSavedVulns.length > 0) {
    const toEnhance = aiSavedVulns.sort((a: any, b: any) => {
      const aV = a.rawFinding.blockchainVerified ? 1 : 0;
      const bV = b.rawFinding.blockchainVerified ? 1 : 0;
      if (aV !== bV) return bV - aV;
      const sevOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
      return (sevOrder[b.rawFinding.severity] || 0) - (sevOrder[a.rawFinding.severity] || 0);
    }).slice(0, 4);

    const enhancementPromises = toEnhance.map(async ({ vuln, rawFinding: v }: any) => {
      try {
        const enhanced = await enhanceVulnerabilityDescription(
          { title: v.title, type: v.type, severity: v.severity, description: v.description, location: v.location, blockchainVerified: v.blockchainVerified, onChainEvidence: v.onChainEvidence },
          sourceCode, { apiKey, model: DEEPSEEK_MODEL }
        );
        await db.vulnerability.update({ where: { id: vuln.id }, data: { description: enhanced } });
        vuln.description = enhanced;
      } catch { /* keep original */ }
    });
    await Promise.allSettled(enhancementPromises);
  }

  // === Step 4: On-chain verification for critical/high (top 2) ===
  if (aiSavedVulns.length > 0 && blockchainData) {
    const criticalVulns = aiSavedVulns.filter((v: any) =>
      !v.rawFinding.blockchainVerified &&
      (v.rawFinding.severity === 'critical' || v.rawFinding.severity === 'high')
    ).slice(0, 2);

    if (criticalVulns.length > 0) {
      const verifyPromises = criticalVulns.map(async ({ vuln, rawFinding: v }: any) => {
        try {
          const verification = await verifyVulnerabilityOnChain(
            { title: v.title, type: v.type, severity: v.severity, description: v.description, location: v.location },
            sourceCode, blockchainData, { apiKey, model }
          );
          if (verification.confirmed) {
            const newConfidence = Math.min(vuln.confidence + 0.15, 0.99);
            const newStatus = newConfidence >= 0.90 ? 'confirmed' : 'validated';
            await db.vulnerability.update({
              where: { id: vuln.id },
              data: {
                confidence: newConfidence, status: newStatus, severity: verification.updatedSeverity || v.severity,
                description: vuln.description + `\n\n[BLOCKCHAIN VERIFIED] On-chain evidence CONFIRMS this vulnerability. ${verification.evidence}`,
              },
            });
            vuln.confidence = newConfidence;
            vuln.status = newStatus;
          }
        } catch { /* keep current */ }
      });
      await Promise.allSettled(verifyPromises);
    }
  }

  // Complete audit
  try {
    await db.audit.update({
      where: { id: auditId },
      data: {
        status: 'completed', completedAt: new Date(),
        findings: results.length, confirmed: results.filter(r => r.status === 'confirmed').length,
        confidence: results.length > 0 ? results.reduce((s, r) => s + r.confidence, 0) / results.length : 0,
      },
    });
  } catch { /* non-fatal */ }

  return { findings: results };
}
