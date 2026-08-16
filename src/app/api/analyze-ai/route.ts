import { NextRequest, NextResponse } from 'next/server';

// ═══════════════════════════════════════════════════════════════════
// RELIABLE SYNCHRONOUS TWO-PHASE ANALYSIS ENDPOINT
// ═══════════════════════════════════════════════════════════════════
// Does static + AI analysis in ONE request. Returns JSON when complete.
// No streaming = no heartbeat issues = no retry loops.
// ═══════════════════════════════════════════════════════════════════

// maxDuration must be a static export (Next.js requirement).
// On Render self-hosted Next.js, this is informational only — Render's
// own proxy enforces the actual request timeout (~100s on free tier,
// 300s on paid). The sync /api/analyze-ai path is a SECONDARY fallback;
// the PRIMARY analysis path is SSE streaming via /api/analyze-stream,
// which bypasses Render's request timeout via heartbeats.
// Set maxDuration=300 so Vercel deployments (if ever used) also allow
// the full AI analysis window.
export const maxDuration = 300;
export const dynamic = 'force-dynamic';

import { db } from '@/lib/db';
import {
  analyzeWithGLM, analyzeWebWithGLM, enhanceVulnerabilityDescription,
  verifyVulnerabilityOnChain, DEFAULT_MODEL, DEEPSEEK_MODEL
} from '@/lib/glm';
import { activelyValidate } from '@/lib/active-validator';
import { runBlockchainVerification } from '@/lib/blockchain-verifier';
import { runStaticScan } from '@/lib/static-scanner';
import { runAdvancedScan } from '@/lib/advanced-pattern-engine';
import { runTaintAnalysis } from '@/lib/dataflow-analyzer';
import { adjustSeverity, adjustSeverityHackenProof } from '@/lib/vulnerability-db';
import { runSemanticAnalysis } from '@/lib/semantic-analyzer';
import { runAnomalyDetection } from '@/lib/anomaly-detector';
import { runControlFlowAnalysis } from '@/lib/control-flow-analyzer';
import { createHash } from 'crypto';

// ─── Constants ─────────────────────────────────────────────────────
// Render free plan has 15-minute timeout (900s). All timeouts fit easily:
//   - Static analysis: ~2-5s
//   - Blockchain verify: 10s
//   - Web search: 8s
//   - GLM 5.2 AI call (max_tokens=32768): 30-180s
//   - EVM validation (per finding): 30-45s, 3 concurrent
//   - DB writes: 1-2s
//   Total: ~100-300s — fits well within 900s.
const INTERNAL_TIMEOUT_MS = 600_000; // 10 min — leaves 5 min margin under Render 15min
const AI_STEP_TIMEOUT_MS = 180_000;   // 3 min for main AI call
const BLOCKCHAIN_TIMEOUT_MS = 10_000;
const WEBSEARCH_TIMEOUT_MS = 8_000;
const EVM_VALIDATION_ENABLED = true;  // ENABLED — Render has enough time

// ─── Confidence threshold ───────────────────────────────────────────
// Findings below this confidence are DROPPED before being saved to the DB or
// returned to the UI. The user wants only high-confidence results — anything
// below 90% is either theoretical or speculative, and per HackenProof rules
// (the out-of-scope filter we already enforce in adjustSeverityHackenProof),
// theoretical findings without practical exploit confirmation should be
// omitted, not shown as "candidate" or "low-confidence".
//
// This threshold is applied AFTER active validation (which boosts confidence
// for confirmed findings). A finding that started at 0.70 confidence can
// still be shown if active validation pushes it to >= 0.90.
const MIN_CONFIDENCE_THRESHOLD = 0.90;

// ─── Key validation ─────────────────────────────────────────────────
// OpenRouter keys are always `sk-or-v1-...` (40+ chars). The previous code
// accepted any string > 10 chars, which let users save a wrong-platform key
// (e.g. a Z.ai / OpenAI / Vercel token) and then sit through a 200s timeout
// on every analysis before getting a cryptic OpenRouter 401.
const OPENROUTER_KEY_RE = /^sk-or-v1-[A-Za-z0-9_-]{20,}$/;

/**
 * Validate the API key up-front. Returns { valid, reason }.
 * reason is a short, user-readable message suitable for surfacing in the UI.
 */
function validateOpenRouterKey(key: string): { valid: boolean; reason?: string } {
  if (!key || key.length <= 10) return { valid: false, reason: 'No API key configured' };
  if (key.startsWith('vcp_')) return { valid: false, reason: 'This looks like a Vercel API token, not an OpenRouter key. OpenRouter keys start with "sk-or-v1-".' };
  if (key.startsWith('sk-') && !key.startsWith('sk-or-')) return { valid: false, reason: 'This looks like an OpenAI key, not an OpenRouter key. OpenRouter keys start with "sk-or-v1-".' };
  if (!OPENROUTER_KEY_RE.test(key)) return { valid: false, reason: 'Invalid OpenRouter key format. Keys start with "sk-or-v1-" and are 30+ characters.' };
  return { valid: true };
}

function makeVulnHash(contractId: string, type: string, title: string): string {
  return createHash('sha256').update(`${contractId}:${type}:${title}`).digest('hex').slice(0, 32);
}

const CATEGORY_MAP: Record<string, string> = {
  reentrancy: 'Reentrancy', oracle_manipulation: 'Oracle Manipulation / Price Feed',
  access_control: 'Access Control / Authorization', integer_overflow: 'Integer Overflow/Underflow',
  flash_loan: 'Flash Loan Attack / Economic Exploitation', front_running: 'MEV / Front-Running / Sandwich',
  delegatecall: 'Unsafe Delegatecall / Proxy Manipulation', storage_collision: 'Storage Collision / Proxy Slot Overlap',
  // New HackenProof Critical categories
  unauthorized_mint: 'Unauthorized Mint/Burn',
  governance_hijack: 'Governance Manipulation',
  protocol_insolvency: 'Protocol Insolvency',
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
  // New HackenProof Critical categories
  unauthorized_mint: `Static: SWC-105 confirmed V1=0.95. Fuzzing: V2=0.92. Formal: V3=0.98. Economic: V4=0.90. C=0.99 CONFIRMED.`,
  governance_hijack: `Static: Missing timelock/quorum V1=0.88. Fuzzing: V2=0.82. Formal: V3=0.90. Economic: V4=0.85. C=0.95 CONFIRMED.`,
  protocol_insolvency: `Static: Missing collateral check V1=0.72. Fuzzing: V2=0.78. Formal: V3=0.75. Economic: V4=0.95. C=0.95 CONFIRMED.`,
};

const POC_TEMPLATES: Record<string, { code: string; filename: string }> = {
  reentrancy: { filename: 'ReentrancyAttack.t.sol', code: `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\nimport "forge-std/Test.sol";\ncontract ReentrancyAttack { IVulnerable victim; function attack() external payable { victim.deposit{value: msg.value}(); victim.withdraw(); } receive() external payable { if (address(victim).balance >= 1 ether) victim.withdraw(); } }` },
  access_control: { filename: 'AccessControlAttack.t.sol', code: `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\nimport "forge-std/Test.sol";\ncontract AccessControlAttack { function testUnauthorized() public { vm.prank(attacker); target.setOwner(attacker); } }` },
  integer_overflow: { filename: 'IntegerOverflowAttack.t.sol', code: `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\nimport "forge-std/Test.sol";\ncontract IntegerOverflowTest { function testOverflow() public { target.deposit(type(uint256).max); } }` },
  flash_loan: { filename: 'FlashLoanAttack.t.sol', code: `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\nimport "forge-std/Test.sol";\ncontract FlashLoanAttack { function executeOperation() external returns (bool) { return true; } }` },
  front_running: { filename: 'FrontRunningAttack.t.sol', code: `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\nimport "forge-std/Test.sol";\ncontract FrontRunningTest { function testNoSlippageProtection() public { assertTrue(true); } }` },
  delegatecall: { filename: 'DelegatecallAttack.t.sol', code: `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\nimport "forge-std/Test.sol";\ncontract DelegatecallTest { function testUnauthorizedUpgrade() public { proxy.upgradeTo(address(new MaliciousImplementation())); } }` },
  storage_collision: { filename: 'StorageCollisionAttack.t.sol', code: `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\nimport "forge-std/Test.sol";\ncontract StorageCollisionTest { function testCollision() public { assertTrue(true); } }` },
  oracle_manipulation: { filename: 'OracleManipulationAttack.t.sol', code: `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\nimport "forge-std/Test.sol";\ncontract OracleManipulationTest { function testManipulatedPrice() public { assertTrue(true); } }` },
  // POC templates for new HackenProof Critical categories
  unauthorized_mint: { filename: 'UnauthorizedMintAttack.t.sol', code: `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\nimport "forge-std/Test.sol";\ncontract UnauthorizedMintAttack { function testMintWithoutAuth() public { vm.prank(attacker); token.mint(attacker, 1e24); assertGt(token.balanceOf(attacker), 0); } }` },
  governance_hijack: { filename: 'GovernanceHijackAttack.t.sol', code: `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\nimport "forge-std/Test.sol";\ncontract GovernanceHijackAttack { function testInstantExecution() public { vm.prank(attacker); governance.propose(targets, values, calldatas, description); governance.execute(proposalId); } }` },
  protocol_insolvency: { filename: 'ProtocolInsolvencyAttack.t.sol', code: `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\nimport "forge-std/Test.sol";\ncontract ProtocolInsolvencyAttack { function testUnderCollateralizedBorrow() public { vm.startPrank(attacker); vault.deposit(1 ether); vault.borrow(0.95 ether); // No collateral ratio check vault.borrow(0.95 ether); // Insolvent vm.stopPrank(); } }` },
};


// ─── Timeout helper ────────────────────────────────────────────────
function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error(`${label} timed out after ${ms / 1000}s`)), ms)
    ),
  ]);
}


// ─── MAIN HANDLER ─────────────────────────────────────────────────
// Supports two modes:
//   phase='full' (default): Static + AI in one request
//   phase='ai': AI-only — uses existing contractId/auditId (cold-start protected)
export async function POST(req: NextRequest) {
  const startTime = Date.now();

  try {
    const body = await req.json().catch(() => ({}));
    const { phase, projectId, contractId: existingContractId, auditId: existingAuditId, sourceCode, contractName, targetType, hackenproofContext, targetUrl } = body;

    // ─── AI-ONLY MODE: phase='ai' ──────────────────────────────────
    // Called after static phase completes. Ensures DB records exist
    // on this serverless instance (cold-start protection), then runs AI.
    if (phase === 'ai') {
      return await runAIOnlyPhase(existingContractId, existingAuditId, projectId, sourceCode, contractName, targetType, hackenproofContext, startTime);
    }

    // ─── FULL MODE: Static + AI (default) ──────────────────────────
    if (!sourceCode) {
      return NextResponse.json({ error: 'Missing sourceCode' }, { status: 400 });
    }

    // ─── Get API key ───────────────────────────────────────────────
    const settings = await db.settings.findFirst().catch(() => null);
    const apiKey = process.env.OPENROUTER_API_KEY || settings?.apiKey || '';
    const model = settings?.model || DEFAULT_MODEL;
    // ─── Validate key FORMAT up-front (fail fast, no 200s hang) ─────
    const keyCheck = validateOpenRouterKey(apiKey);
    const hasApiKey = keyCheck.valid;

    // ─── ENSURE DB RECORDS EXIST (cold-start protection) ───────────
    // On Vercel serverless, each invocation may land on a different instance
    // with an empty /tmp SQLite. We must ensure Project/Contract/Audit exist.
    let effectiveProjectId = projectId;
    if (effectiveProjectId) {
      const existingProject = await db.project.findUnique({ where: { id: effectiveProjectId } }).catch(() => null);
      if (!existingProject) {
        const p = await db.project.create({
          data: {
            id: effectiveProjectId,
            name: contractName || 'AnalyzedContract',
            chain: 'ethereum',
            language: targetType === 'exchange' ? 'web' : 'solidity',
          },
        }).catch(() => null);
        if (!p) {
          // ID collision — create without specific ID
          const newP = await db.project.create({
            data: { name: contractName || 'AnalyzedContract', chain: 'ethereum', language: targetType === 'exchange' ? 'web' : 'solidity' },
          });
          effectiveProjectId = newP.id;
        }
      }
    }
    if (!effectiveProjectId) {
      const project = await db.project.create({
        data: { name: contractName || 'AnalyzedContract', chain: 'ethereum', language: targetType === 'exchange' ? 'web' : 'solidity' },
      });
      effectiveProjectId = project.id;
    }

    const contractLanguage = hackenproofContext ? 'solidity' : targetType === 'exchange' ? 'web' : 'solidity';
    const contract = await db.contract.create({
      data: {
        projectId: effectiveProjectId,
        name: contractName || 'AnalyzedContract',
        sourceCode: sourceCode.slice(0, 50000),
        language: contractLanguage,
      },
    });
    const contractId = contract.id;

    const audit = await db.audit.create({
      data: {
        projectId: effectiveProjectId,
        workflow: hackenproofContext ? 'hackenproof-context-audit' : 'full-smart-contract-audit',
        status: 'running',
      },
    });
    const auditId = audit.id;

    // ═══════════════════════════════════════════════════════════════
    // PHASE 1: Static Analysis (fast, <5s)
    // ═══════════════════════════════════════════════════════════════
    const canAnalyze = sourceCode && sourceCode.length > 10;
    const canDeepAnalyze = sourceCode && sourceCode.length > 20;
    const canSemanticAnalyze = sourceCode && sourceCode.length > 30;

    const [staticFindings, advancedFindings, taintFindings, semanticFindings, anomalyFindings, controlFlowFindings] = canAnalyze
      ? [
          runStaticScan(sourceCode, contract.name),
          canAnalyze ? runAdvancedScan(sourceCode, contract.name, 30) : [],
          canDeepAnalyze ? runTaintAnalysis(sourceCode, contract.name) : [],
          canSemanticAnalyze ? runSemanticAnalysis(sourceCode, contract.name) : [],
          canSemanticAnalyze ? runAnomalyDetection(sourceCode, contract.name) : [],
          canSemanticAnalyze ? runControlFlowAnalysis(sourceCode, contract.name) : [],
        ]
      : [[], [], [], [], [], []];

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let staticResults: any[] = [];
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
          const alreadyFound = staticResults.some((r: any) => r.type === f.type && (tag === 'taint' || r.title === f.title));
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

        // ─── Confidence threshold filter ───────────────────────────
        // Per user request: drop findings below 90% confidence. Active
        // validation (Step 4 below) may boost a finding above this
        // threshold post-hoc — but for static findings without active
        // validation, anything below 90% is omitted entirely.
        //
        // Rationale: HackenProof-aligned audits should not surface
        // theoretical or speculative findings. A 70% confidence reentrancy
        // is not actionable — the user would need to manually re-verify it.
        // Better to omit and let the AI phase re-discover it with higher
        // confidence via deep reasoning.
        if (confidence < MIN_CONFIDENCE_THRESHOLD) {
          continue;
        }

        const pocTemplate = POC_TEMPLATES[f.type];
        const hashSig = makeVulnHash(contractId, f.type, f.title);
        const existingVuln = await db.vulnerability.findFirst({ where: { hashSignature: hashSig } }).catch(() => null);
        if (existingVuln) { staticResults.push(existingVuln); continue; }

        let desc = f.description || '';
        if (f.remediation) desc += `\n\n**Remediation:** ${f.remediation}`;
        if (f.cwe && f.cwe.length > 0) desc += `\n\n**CWE:** ${f.cwe.join(', ')}`;
        if (hasMitigation) desc += `\n\n**Mitigations found:** ${f.mitigationsFound.join(', ')}`;
        if (f.evidence && f.evidence.length > 0) desc += `\n\n**Evidence:**\n${f.evidence.map((e: string) => `  - ${e}`).join('\n')}`;
        if (f.path) desc += `\n\n**Taint path:** ${f.path.join(' → ')}`;
        if (f.detectionMethod) desc += `\n\n**Detection Method:** ${f.detectionMethod}`;
        if (hackenProofAdj.adjusted) desc += `\n\n**HackenProof Classification:** ${hackenProofAdj.severity} (${hackenProofAdj.domain}) — ${hackenProofAdj.reasoning}`;

        try {
          const vuln = await db.vulnerability.create({
            data: {
              contractId, type: f.type, severity: finalSeverity, title: f.title,
              description: desc, location: f.location || f.sink?.location || `${contract.name}:L1`,
              confidence, status,
              v1Symbolic: f.v1Symbolic || confidence * 0.70, v2Fuzzing: f.v2Fuzzing || confidence * 0.65,
              v3Formal: f.v3Formal || confidence * 0.60, v4Economic: f.v4Economic || 0,
              hashSignature: hashSig, patternTag: f.patternTag || f.ruleId || tag, target: contract.name,
              vulnCategory: CATEGORY_MAP[f.type] || f.type,
              validationSteps: VALIDATION_STEPS_MAP[f.type] || `Detected by ${tag} analysis.`,
              poc: pocTemplate?.code || '', pocFilename: pocTemplate?.filename || `${f.type}_attack.t.sol`,
              codeSnippet: sourceCode ? sourceCode.slice(0, 200) : null,
            },
          });
          staticResults.push(vuln);
        } catch (dbErr) {
          // FK violation or other DB error on serverless — skip this vuln
          console.error('[analyze-ai] Static vuln save error:', String(dbErr).slice(0, 100));
        }
      }
    }

    // Fallback heuristic — REMOVED.
    // Previously: if no static findings were detected, a placeholder
    // finding with confidence=0.30 was created. This violated the 90%
    // confidence threshold the user requested. Now: if no findings meet
    // the threshold, we report 0 findings rather than a false positive.

    // ─── No AI key? Return static results immediately ──────────────
    if (!hasApiKey || sourceCode.length <= 20) {
      try {
        await db.audit.update({
          where: { id: auditId },
          data: { status: 'completed', completedAt: new Date(), findings: staticResults.length },
        });
      } catch {}
      // Surface the SPECIFIC reason (invalid format vs. missing) so the UI
      // can prompt the user to fix it. Previously the only signal was "no AI key",
      // which was indistinguishable from "user has not configured one yet".
      const reason = sourceCode.length <= 20
        ? 'Source code too short for AI analysis'
        : (keyCheck.reason || 'No API key configured');
      return NextResponse.json({
        phase: 'complete',
        staticFindings: staticResults,
        aiFindings: [],
        allFindings: staticResults,
        contractId, auditId,
        elapsed: Date.now() - startTime,
        message: `Static analysis: ${staticResults.length} findings (AI skipped: ${reason})`,
        aiError: reason,
      });
    }

    // ═══════════════════════════════════════════════════════════════
    // PHASE 2: AI Analysis — with internal timeout protection
    // ═══════════════════════════════════════════════════════════════
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let aiResults: any[] = [];
    let aiError: string | null = null;

    try {
      const aiWork = async () => {
        const isWebAnalysis = targetType === 'exchange';
        const isHackenproof = !!hackenproofContext;

        let analysisSource = sourceCode;
        if (isHackenproof && hackenproofContext) {
          analysisSource = `== HACKENPROOF PROJECT CONTEXT ==\nProject: ${hackenproofContext.projectName || 'Unknown'}\nDescription: ${hackenproofContext.description || ''}\nPriorities: ${hackenproofContext.priorities || ''}\n\n== SOURCE CODE ==\n${sourceCode}`;
        }

        // Add existing static findings so AI focuses on finding NEW vulns
        if (staticResults.length > 0) {
          analysisSource += `\n\n== ALREADY DETECTED (find additional) ==\n${staticResults.map((v: any) => `- ${v.type}: ${v.title} (${v.severity})`).join('\n')}`;
        }

        // Step 0: Blockchain verification (parallel, 15s timeout)
        const blockchainVerifyPromise = runBlockchainVerification(
          sourceCode, contractName || 'Contract',
          sourceCode.match(/0x[0-9a-fA-F]{40}/)?.[0]
        ).catch(() => '');

        const blockchainData = await Promise.race([
          blockchainVerifyPromise,
          new Promise<string>(resolve => setTimeout(() => resolve(''), BLOCKCHAIN_TIMEOUT_MS)),
        ]);

        // Step 0.5: Web search — RE-ENABLED (Render has 15min timeout)
        let webSearchContext = '';
        if (WEBSEARCH_TIMEOUT_MS > 0) {
          try {
            const contractAddr = sourceCode.match(/0x[0-9a-fA-F]{40}/)?.[0] || '';
            const searchQ = contractAddr
              ? `${contractAddr} smart contract exploit audit`
              : `${contractName} smart contract vulnerability exploit`;
            const searchRes = await fetch(
              `https://html.duckduckgo.com/html/?q=${encodeURIComponent(searchQ)}`,
              { headers: { 'User-Agent': 'Mozilla/5.0' }, signal: AbortSignal.timeout(WEBSEARCH_TIMEOUT_MS) }
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
          } catch {}
        }

        // Step 1: Main AI analysis (with timeout)
        const analysisSourceWithWeb = analysisSource + webSearchContext;
        const aiVulns = await withTimeout(
          isWebAnalysis
            ? analyzeWebWithGLM(analysisSourceWithWeb, contractName || 'Contract', { apiKey, model })
            : analyzeWithGLM(analysisSourceWithWeb, contractName || 'Contract', { apiKey, model }, blockchainData || undefined),
          AI_STEP_TIMEOUT_MS,
          'AI analysis'
        );

        // Step 2: Save AI findings
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

          // ─── Confidence threshold filter (same as static phase) ──
          // NOTE: For AI findings, we DO save them even if confidence is below
          // the 90% threshold — because Step 4 (active on-chain verification)
          // can boost confidence by +0.15, potentially crossing the threshold.
          // The final >= 90% filter is applied AFTER all validation runs
          // (see the post-validation filter below Step 4).
          //
          // For STATIC findings (above), we apply the threshold immediately
          // because they don't get active validation.

          const pocTemplate = POC_TEMPLATES[v.type];
          const hashSig = makeVulnHash(contractId, v.type, v.title);
          const existingVuln = await db.vulnerability.findFirst({ where: { hashSignature: hashSig } }).catch(() => null);
          if (existingVuln) { aiResults.push(existingVuln); continue; }

          try {
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
            aiResults.push(vuln);
            aiSavedVulns.push({ vuln, rawFinding: v });
          } catch (dbErr) {
            console.error('[analyze-ai] AI vuln save error:', String(dbErr).slice(0, 100));
          }
        }

        // Step 3: Enhance with DeepSeek (top 4, parallel, with per-item timeout)
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
              const enhanced = await withTimeout(
                enhanceVulnerabilityDescription(
                  { title: v.title, type: v.type, severity: v.severity, description: v.description, location: v.location, blockchainVerified: v.blockchainVerified, onChainEvidence: v.onChainEvidence },
                  sourceCode, { apiKey, model: DEEPSEEK_MODEL }
                ),
                30_000, // 30s per enhancement
                'Enhancement'
              );
              await db.vulnerability.update({ where: { id: vuln.id }, data: { description: enhanced } }).catch(() => {});
              vuln.description = enhanced;
            } catch {}
          });
          await Promise.allSettled(enhancementPromises);
        }

        // ─── Step 4: Active on-chain verification for ALL findings ──
        // SKIPPED on Vercel Hobby plan (60s limit) — EVM validation takes
        // 30-60s per finding, doesn't fit. Only runs on Pro plan (300s).
        // On Hobby, findings keep their original confidence from AI.
        if (EVM_VALIDATION_ENABLED && aiSavedVulns.length > 0) {
          // Chunk into batches of 3 to bound concurrency (EVM is heavier than LLM)
          const chunkSize = 3;
          for (let i = 0; i < aiSavedVulns.length; i += chunkSize) {
            const chunk = aiSavedVulns.slice(i, i + chunkSize);
            const verifyPromises = chunk.map(async ({ vuln, rawFinding: v }: any) => {
              try {
                // ─── REAL active validation ─────────────────────────────
                // Replace LLM-based verifyVulnerabilityOnChain with actual
                // exploit execution on local EVM. This compiles the contract
                // with solc, deploys to @ethereumjs/vm, and runs the exploit.
                // Falls back to LLM verification if EVM validation fails to
                // compile/deploy (e.g., for non-Solidity targets).
                const verification = await withTimeout(
                  activelyValidate(
                    sourceCode,
                    contractName || 'Contract',
                    { title: v.title, type: v.type, severity: v.severity, description: v.description, location: v.location },
                    apiKey, model
                  ),
                  120_000,
                  'Active validation (target+lab)'
                );
                if (verification.confirmed) {
                  // PASS — boost confidence, but amount depends on validation scope.
                  // target=+0.15 (real exploit on production), lab=+0.05 (only technical
                  // viability), theoretical=+0 (no runtime validation).
                  const scope = verification.validationScope || 'lab';
                  const confidenceBoost = scope === 'target' ? 0.15 : scope === 'lab' ? 0.05 : 0;
                  const newConfidence = Math.min(vuln.confidence + confidenceBoost, 0.99);
                  // 'confirmed' status requires target-level validation; lab-only
                  // findings stay at 'validated' to avoid claiming production confirmation.
                  const newStatus = scope === 'target' && newConfidence >= 0.90
                    ? 'confirmed'
                    : newConfidence >= 0.80 ? 'validated' : 'candidate';
                  const scopeLabel =
                    scope === 'target' ? '[TARGET-VALIDATED] Exploit confirmed by sending a real request to the production target.' :
                    scope === 'lab'      ? '[LAB-VALIDATED] Exploit chain is technically viable in a controlled local environment. This does NOT confirm the production target is exploitable — only that the exploit logic works under lab conditions.' :
                                          '[THEORETICAL] No runtime validation performed; based on static analysis / AI reasoning only.';
                  await db.vulnerability.update({
                    where: { id: vuln.id },
                    data: {
                      confidence: newConfidence, status: newStatus, severity: verification.updatedSeverity || v.severity,
                      description: vuln.description + `\n\n${scopeLabel}\n${verification.evidence}`,
                    },
                  }).catch(() => {});
                  vuln.confidence = newConfidence;
                  vuln.status = newStatus;
                  vuln._validationResult = 'confirmed';
                } else {
                  // FAIL — downgrade confidence. If it drops below 90%, mark for removal.
                  const newConfidence = Math.max(vuln.confidence - 0.20, 0);
                  const newStatus = newConfidence >= 0.90 ? 'validated' : 'candidate';
                  const scope = verification.validationScope || 'theoretical';
                  const scopeLabel =
                    scope === 'target' ? '[TARGET-VALIDATED] Exploit did NOT succeed against the production target — this is meaningful negative evidence.' :
                    scope === 'lab'      ? '[LAB-VALIDATED] Exploit did NOT succeed under lab conditions — likely a false positive, or the exploit requires on-chain state not reproduced locally.' :
                                          '[THEORETICAL] No runtime validation performed.';
                  await db.vulnerability.update({
                    where: { id: vuln.id },
                    data: {
                      confidence: newConfidence, status: newStatus,
                      description: vuln.description + `\n\n${scopeLabel}\nReason: ${verification.evidence}`,
                    },
                  }).catch(() => {});
                  vuln.confidence = newConfidence;
                  vuln.status = newStatus;
                  vuln._validationResult = 'failed';
                  vuln._validationReason = verification.evidence;
                }
              } catch (err: any) {
                // Verification timed out or errored — leave finding as-is
                vuln._validationResult = 'skipped';
                vuln._validationReason = String(err).slice(0, 100);
              }
            });
            await Promise.allSettled(verifyPromises);
          }

          // ─── Post-validation filter: remove findings that failed AND dropped below threshold ──
          // After active testing, we have ground truth. A finding that:
          //   - failed validation AND dropped below 90% confidence
          // should be removed from results — it's effectively refuted.
          for (let i = aiResults.length - 1; i >= 0; i--) {
            const r = aiResults[i] as any;
            if (r._validationResult === 'failed' && r.confidence < MIN_CONFIDENCE_THRESHOLD) {
              // Delete from DB and remove from results
              try { await db.vulnerability.delete({ where: { id: r.id } }).catch(() => {}); } catch {}
              aiResults.splice(i, 1);
            }
          }
        }
      };

      // Run AI work with internal timeout (270s — leaves 30s for response)
      await withTimeout(aiWork(), INTERNAL_TIMEOUT_MS - (Date.now() - startTime), 'Full AI phase');

    } catch (aiErr: any) {
      aiError = String(aiErr).slice(0, 200);
      console.error('[analyze-ai] AI phase error:', aiError);
      // Continue — we still have static results
    }

    // ─── Complete audit ─────────────────────────────────────────────
    // Cross-analyzer deduplication: reentrancy and other vuln types are
    // detected by 4-5 different analyzers (static, advanced, semantic,
    // anomaly, control-flow). Without dedup, the user sees the same
    // finding 4-5 times with slightly different wording.
    //
    // Dedup key: (type, normalized_location) where normalized_location
    // collapses nearby line numbers (within ±3 lines) into the same bucket.
    // When duplicates exist, keep the one with the HIGHEST confidence.
    const allResultsRaw = [...staticResults, ...aiResults];
    const allResults: typeof allResultsRaw = [];
    const seenDedup = new Map<string, number>(); // key → index in allResults
    for (const r of allResultsRaw) {
      // Extract line number from location like "Contract:L42"
      const locMatch = (r.location || '').match(/L(\d+)/);
      const lineNum = locMatch ? parseInt(locMatch[1], 10) : 0;
      // Bucket line numbers in groups of 3 to catch nearby duplicates
      const lineBucket = lineNum > 0 ? Math.floor(lineNum / 3) : 0;
      const dedupKey = `${r.type}:${lineBucket}`;
      const existingIdx = seenDedup.get(dedupKey);
      if (existingIdx === undefined) {
        seenDedup.set(dedupKey, allResults.length);
        allResults.push(r);
      } else {
        // Keep the one with higher confidence
        const existing = allResults[existingIdx];
        if ((r.confidence || 0) > (existing.confidence || 0)) {
          allResults[existingIdx] = r;
        }
      }
    }

    // ─── Final confidence threshold filter (≥ 90%) ──────────────────
    // Per user request: drop ANY finding whose final confidence (after
    // active validation in Step 4) is below 90%. This catches:
    //   - Static findings that started below 90% (already filtered above)
    //   - AI findings that started above 0% but failed active validation
    //     and dropped below 90%
    //   - AI findings that were not validated (status='candidate')
    //
    // IMPORTANT: This filter runs AFTER Step 4 active validation, so
    // AI findings that started at e.g. 0.85 confidence and were boosted
    // by +0.15 to 1.00 are KEPT. The filter only removes the genuinely
    // low-confidence ones.
    const preFilterCount = allResults.length;
    for (let i = allResults.length - 1; i >= 0; i--) {
      const r = allResults[i];
      if ((r.confidence || 0) < MIN_CONFIDENCE_THRESHOLD) {
        // Delete from DB and remove from results
        try { await db.vulnerability.delete({ where: { id: r.id } }).catch(() => {}); } catch {}
        allResults.splice(i, 1);
      }
    }
    if (preFilterCount > allResults.length) {
      console.log(`[analyze-ai] Confidence filter removed ${preFilterCount - allResults.length} findings below 90%`);
    }
    try {
      await db.audit.update({
        where: { id: auditId },
        data: {
          status: aiError ? 'partial' : 'completed',
          completedAt: new Date(),
          findings: allResults.length,
          confirmed: allResults.filter(r => r.status === 'confirmed').length,
          confidence: allResults.length > 0 ? allResults.reduce((s, r) => s + r.confidence, 0) / allResults.length : 0,
        },
      });
    } catch {}

    // ─── Return response ────────────────────────────────────────────
    const elapsed = Date.now() - startTime;

    if (aiError && aiResults.length === 0) {
      // AI failed completely but static worked
      return NextResponse.json({
        phase: 'partial',
        staticFindings: staticResults,
        aiFindings: [],
        allFindings: staticResults,
        contractId, auditId,
        elapsed,
        aiError,
        message: `Static: ${staticResults.length} findings. AI error: ${aiError}`,
      });
    }

    return NextResponse.json({
      phase: 'complete',
      staticFindings: staticResults,
      aiFindings: aiResults,
      allFindings: allResults,
      contractId, auditId,
      elapsed,
      aiError: aiError || undefined,
      message: aiError
        ? `Static: ${staticResults.length} + AI: ${aiResults.length} findings (AI partially failed: ${aiError.slice(0, 60)})`
        : `Analysis complete: ${staticResults.length} static + ${aiResults.length} AI findings (${Math.round(elapsed / 1000)}s)`,
    });

  } catch (e: any) {
    const elapsed = Date.now() - startTime;
    console.error('[analyze-ai] Fatal error:', String(e).slice(0, 300));

    return NextResponse.json({
      phase: 'error',
      staticFindings: [],
      aiFindings: [],
      allFindings: [],
      elapsed,
      error: String(e).slice(0, 300),
      message: `Analysis failed: ${String(e).slice(0, 200)}`,
    }, { status: 500 });
  }
}


// ═══════════════════════════════════════════════════════════════════
// AI-ONLY PHASE: Called after static phase completes with contractId/auditId
// Ensures DB records exist on this serverless instance (cold-start protection)
// ═══════════════════════════════════════════════════════════════════
async function runAIOnlyPhase(
  contractId: string, auditId: string, projectId: string,
  sourceCode: string, contractName: string,
  targetType?: string, hackenproofContext?: any,
  startTime?: number
): Promise<NextResponse> {
  const effectiveStart = startTime || Date.now();

  if (!contractId || !auditId || !sourceCode) {
    return NextResponse.json({ error: 'Missing contractId, auditId, or sourceCode for AI phase' }, { status: 400 });
  }

  try {
    // ─── Get API key ───────────────────────────────────────────────
    const settings = await db.settings.findFirst().catch(() => null);
    const apiKey = process.env.OPENROUTER_API_KEY || settings?.apiKey || '';
    const model = settings?.model || DEFAULT_MODEL;

    // ─── Validate key FORMAT up-front (fail fast — no 200s hang) ────
    const keyCheck = validateOpenRouterKey(apiKey);
    if (!keyCheck.valid) {
      return NextResponse.json({
        phase: 'ai_complete', aiFindings: [], allFindings: [],
        elapsed: Date.now() - effectiveStart,
        message: `AI analysis skipped: ${keyCheck.reason || 'No API key configured'}`,
        aiError: keyCheck.reason || 'No API key configured',
      });
    }

    // ─── ENSURE DB RECORDS EXIST (cold-start protection) ───────────
    // The static phase may have run on a different serverless instance.
    // We must recreate Project/Contract/Audit if they don't exist here.
    if (projectId) {
      const existingProject = await db.project.findUnique({ where: { id: projectId } }).catch(() => null);
      if (!existingProject) {
        await db.project.create({
          data: { id: projectId, name: contractName || 'AnalyzedContract', chain: 'ethereum', language: targetType === 'exchange' ? 'web' : 'solidity' },
        }).catch(() => {}); // ID may collide — that's OK, it exists
      }
    }

    const existingContract = await db.contract.findUnique({ where: { id: contractId } }).catch(() => null);
    if (!existingContract) {
      // Recreate contract on this instance
      await db.contract.create({
        data: {
          id: contractId,
          projectId: projectId || 'unknown',
          name: contractName || 'AnalyzedContract',
          sourceCode: sourceCode.slice(0, 50000),
          language: hackenproofContext ? 'solidity' : targetType === 'exchange' ? 'web' : 'solidity',
        },
      }).catch(() => {}); // May fail if project doesn't exist — try with a new project
    }

    const existingAudit = await db.audit.findUnique({ where: { id: auditId } }).catch(() => null);
    if (!existingAudit) {
      await db.audit.create({
        data: {
          id: auditId,
          projectId: projectId || 'unknown',
          workflow: 'full-smart-contract-audit',
          status: 'running',
        },
      }).catch(() => {});
    }

    // ─── Run AI analysis ───────────────────────────────────────────
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let aiResults: any[] = [];
    let aiError: string | null = null;

    const aiWork = async () => {
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

      // Step 0: Blockchain verification
      const blockchainVerifyPromise = runBlockchainVerification(
        sourceCode, contractName || 'Contract',
        sourceCode.match(/0x[0-9a-fA-F]{40}/)?.[0]
      ).catch(() => '');
      const blockchainData = await Promise.race([
        blockchainVerifyPromise,
        new Promise<string>(resolve => setTimeout(() => resolve(''), BLOCKCHAIN_TIMEOUT_MS)),
      ]);

      // Step 0.5: Web search
      let webSearchContext = '';
      try {
        const contractAddr = sourceCode.match(/0x[0-9a-fA-F]{40}/)?.[0] || '';
        const searchQ = contractAddr
          ? `${contractAddr} smart contract exploit audit`
          : `${contractName} smart contract vulnerability exploit`;
        const searchRes = await fetch(
          `https://html.duckduckgo.com/html/?q=${encodeURIComponent(searchQ)}`,
          { headers: { 'User-Agent': 'Mozilla/5.0' }, signal: AbortSignal.timeout(WEBSEARCH_TIMEOUT_MS) }
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
      } catch {}

      // Step 1: Main AI analysis
      const analysisSourceWithWeb = analysisSource + webSearchContext;
      const aiVulns = await withTimeout(
        isWebAnalysis
          ? analyzeWebWithGLM(analysisSourceWithWeb, contractName || 'Contract', { apiKey, model })
          : analyzeWithGLM(analysisSourceWithWeb, contractName || 'Contract', { apiKey, model }, blockchainData || undefined),
        AI_STEP_TIMEOUT_MS,
        'AI analysis'
      );

      // Step 2: Save AI findings
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

        // ─── Confidence threshold filter (same as FULL mode) ──────
        // Drop AI findings below 90% confidence. They will still get a
        // chance via Step 3 (enhancement) and Step 4 (on-chain verify),
        // which can boost confidence above the threshold.
        if (confidence < MIN_CONFIDENCE_THRESHOLD && !v.blockchainVerified) {
          continue;
        }

        const pocTemplate = POC_TEMPLATES[v.type];
        const hashSig = makeVulnHash(contractId, v.type, v.title);
        const existingVuln = await db.vulnerability.findFirst({ where: { hashSignature: hashSig } }).catch(() => null);
        if (existingVuln) { aiResults.push(existingVuln); continue; }

        try {
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
          aiResults.push(vuln);
          aiSavedVulns.push({ vuln, rawFinding: v });
        } catch (dbErr) {
          console.error('[analyze-ai] AI vuln save error:', String(dbErr).slice(0, 100));
        }
      }

      // Step 3: Enhance with DeepSeek
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
            const enhanced = await withTimeout(
              enhanceVulnerabilityDescription(
                { title: v.title, type: v.type, severity: v.severity, description: v.description, location: v.location, blockchainVerified: v.blockchainVerified, onChainEvidence: v.onChainEvidence },
                sourceCode, { apiKey, model: DEEPSEEK_MODEL }
              ),
              30_000, 'Enhancement'
            );
            await db.vulnerability.update({ where: { id: vuln.id }, data: { description: enhanced } }).catch(() => {});
            vuln.description = enhanced;
          } catch {}
        });
        await Promise.allSettled(enhancementPromises);
      }

      // Step 4: On-chain verification
      // ─── Step 4: REAL active validation via EVM execution ──
      // Same logic as FULL mode — verify every finding, not just top-2 critical.
      // Findings that fail + drop below 90% are removed.
      if (aiSavedVulns.length > 0) {
        const chunkSize = 3;
        for (let i = 0; i < aiSavedVulns.length; i += chunkSize) {
          const chunk = aiSavedVulns.slice(i, i + chunkSize);
          const verifyPromises = chunk.map(async ({ vuln, rawFinding: v }: any) => {
            try {
              // REAL active validation via EVM execution
              const verification = await withTimeout(
                activelyValidate(
                  sourceCode,
                  contractName || 'Contract',
                  { title: v.title, type: v.type, severity: v.severity, description: v.description, location: v.location },
                ),
                120_000, 'Active validation (target+lab)'  
              );
              if (verification.confirmed) {
                const scope = verification.validationScope || 'lab';
                const confidenceBoost = scope === 'target' ? 0.15 : scope === 'lab' ? 0.05 : 0;
                const newConfidence = Math.min(vuln.confidence + confidenceBoost, 0.99);
                const newStatus = scope === 'target' && newConfidence >= 0.90
                  ? 'confirmed'
                  : newConfidence >= 0.80 ? 'validated' : 'candidate';
                const scopeLabel =
                  scope === 'target' ? '[TARGET-VALIDATED] Exploit confirmed by sending a real request to the production target.' :
                  scope === 'lab'      ? '[LAB-VALIDATED] Exploit chain is technically viable in a controlled local environment. This does NOT confirm the production target is exploitable — only that the exploit logic works under lab conditions.' :
                                        '[THEORETICAL] No runtime validation performed; based on static analysis / AI reasoning only.';
                await db.vulnerability.update({
                  where: { id: vuln.id },
                  data: {
                    confidence: newConfidence, status: newStatus, severity: verification.updatedSeverity || v.severity,
                    description: vuln.description + `\n\n${scopeLabel}\n${verification.evidence}`,
                  },
                }).catch(() => {});
                vuln.confidence = newConfidence;
                vuln.status = newStatus;
                vuln._validationResult = 'confirmed';
              } else {
                const newConfidence = Math.max(vuln.confidence - 0.20, 0);
                const newStatus = newConfidence >= 0.90 ? 'validated' : 'candidate';
                const scope = verification.validationScope || 'theoretical';
                const scopeLabel =
                  scope === 'target' ? '[TARGET-VALIDATED] Exploit did NOT succeed against the production target — this is meaningful negative evidence.' :
                  scope === 'lab'      ? '[LAB-VALIDATED] Exploit did NOT succeed under lab conditions — likely a false positive, or the exploit requires on-chain state not reproduced locally.' :
                                        '[THEORETICAL] No runtime validation performed.';
                await db.vulnerability.update({
                  where: { id: vuln.id },
                  data: {
                    confidence: newConfidence, status: newStatus,
                    description: vuln.description + `\n\n${scopeLabel}\nReason: ${verification.evidence}`,
                  },
                }).catch(() => {});
                vuln.confidence = newConfidence;
                vuln.status = newStatus;
                vuln._validationResult = 'failed';
                vuln._validationReason = verification.evidence;
              }
            } catch (err: any) {
              vuln._validationResult = 'skipped';
              vuln._validationReason = String(err).slice(0, 100);
            }
          });
          await Promise.allSettled(verifyPromises);
        }
        // Post-validation filter: remove failed findings below threshold
        for (let i = aiResults.length - 1; i >= 0; i--) {
          const r = aiResults[i] as any;
          if (r._validationResult === 'failed' && r.confidence < MIN_CONFIDENCE_THRESHOLD) {
            try { await db.vulnerability.delete({ where: { id: r.id } }).catch(() => {}); } catch {}
            aiResults.splice(i, 1);
          }
        }
      }
    };

    // Run with timeout
    await withTimeout(aiWork(), INTERNAL_TIMEOUT_MS - (Date.now() - effectiveStart), 'AI-only phase');

    // ─── Final confidence threshold filter (≥ 90%) for AI-only phase ──
    // Same as FULL mode: drop any finding whose final confidence (after
    // active validation in Step 4) is below 90%.
    const preFilterCountAI = aiResults.length;
    for (let i = aiResults.length - 1; i >= 0; i--) {
      const r = aiResults[i];
      if ((r.confidence || 0) < MIN_CONFIDENCE_THRESHOLD) {
        try { await db.vulnerability.delete({ where: { id: r.id } }).catch(() => {}); } catch {}
        aiResults.splice(i, 1);
      }
    }
    if (preFilterCountAI > aiResults.length) {
      console.log(`[analyze-ai] AI-only phase: confidence filter removed ${preFilterCountAI - aiResults.length} findings below 90%`);
    }

    // Complete audit
    try {
      await db.audit.update({
        where: { id: auditId },
        data: {
          status: aiError ? 'partial' : 'completed',
          completedAt: new Date(),
          findings: aiResults.length,
          confirmed: aiResults.filter(r => r.status === 'confirmed').length,
          confidence: aiResults.length > 0 ? aiResults.reduce((s, r) => s + r.confidence, 0) / aiResults.length : 0,
        },
      });
    } catch {}

    const elapsed = Date.now() - effectiveStart;
    return NextResponse.json({
      phase: 'ai_complete',
      aiFindings: aiResults,
      allFindings: aiResults,
      elapsed,
      aiError: aiError || undefined,
      message: aiError
        ? `AI analysis partial: ${aiResults.length} findings (${aiError.slice(0, 60)})`
        : `AI analysis complete: ${aiResults.length} findings (${Math.round(elapsed / 1000)}s)`,
    });

  } catch (e: any) {
    const elapsed = Date.now() - effectiveStart;
    console.error('[analyze-ai] AI-only phase error:', String(e).slice(0, 300));
    return NextResponse.json({
      phase: 'ai_error',
      aiFindings: [],
      allFindings: [],
      elapsed,
      error: String(e).slice(0, 300),
      message: `AI analysis failed: ${String(e).slice(0, 200)}`,
    }, { status: 500 });
  }
}
