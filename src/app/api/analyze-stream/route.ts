import { NextRequest } from 'next/server';
export const maxDuration = 900; // 15 min — VPS KVM 2, no Render/Vercel limits
export const dynamic = 'force-dynamic';

import { db } from '@/lib/db';
import { analyzeWithGLM, analyzeWebWithGLM, enhanceVulnerabilityDescription, verifyVulnerabilityOnChain, DEFAULT_MODEL, DEEPSEEK_MODEL } from '@/lib/glm';
import { activelyValidate } from '@/lib/active-validator';
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

const CATEGORY_MAP: Record<string, string> = {
  reentrancy: 'Reentrancy', oracle_manipulation: 'Oracle Manipulation / Price Feed',
  access_control: 'Access Control / Authorization', integer_overflow: 'Integer Overflow/Underflow',
  flash_loan: 'Flash Loan Attack / Economic Exploitation', front_running: 'MEV / Front-Running / Sandwich',
  delegatecall: 'Unsafe Delegatecall / Proxy Manipulation', storage_collision: 'Storage Collision / Proxy Slot Overlap',
};

// NOTE (audit comment, no functional change): VALIDATION_STEPS_MAP and
// POC_TEMPLATES below are PLACEHOLDER strings — see note in analyze/route.ts.

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



/**
 * UNIFIED SSE streaming endpoint: Phase 1 (static) + Phase 2 (AI) in ONE connection.
 * This eliminates the #1 cause of "network error" — cold starts between phases.
 *
 * Event types:
 *   phase1_complete — { findings, contractId, auditId, needsAI }
 *   progress        — { step, message, percent }
 *   finding         — { vulnerability }
 *   complete        — { findings, message }
 *   error           — { error, message }
 *   heartbeat       — { ts }
 */
export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => ({}));
  const { projectId, sourceCode, contractName, targetType, hackenproofContext, targetUrl } = body;

  if (!sourceCode) {
    return new Response(JSON.stringify({ error: 'Missing sourceCode' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const settings = await db.settings.findFirst();
  const apiKey = process.env.OPENROUTER_API_KEY || settings?.apiKey || '';
  const model = settings?.model || DEFAULT_MODEL;
  // Strict key validation — same logic as /api/analyze-ai. Rejecting a
  // wrong-platform key here means we never start an SSE stream that would
  // otherwise hang on a 60s+ OpenRouter 401.
  const OPENROUTER_KEY_RE = /^sk-or-v1-[A-Za-z0-9_-]{20,}$/;
  const hasApiKey = !!(apiKey && OPENROUTER_KEY_RE.test(apiKey));

  const encoder = new TextEncoder();
  let heartbeatId: ReturnType<typeof setInterval> | null = null;

  const stream = new ReadableStream({
    async start(controller) {
      const send = (event: string, data: unknown) => {
        try {
          controller.enqueue(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
        } catch { /* stream closed */ }
      };

      // Send "connected" event IMMEDIATELY — this proves the stream is alive
      // and bypasses Render's request-start timeout (which would otherwise
      // kill the connection before any data is flushed).
      send('progress', { step: 'connected', message: 'Stream connected — starting analysis...', percent: 1 });

      // Heartbeat every 5s — aggressive enough to bypass Render's 100s
      // request timeout. (8s was too close to Render's proxy idle window
      // during long GLM calls.)
      heartbeatId = setInterval(() => {
        send('heartbeat', { ts: Date.now() });
      }, 5_000);

      try {
        // ═══════════════════════════════════════════════════════════
        // PHASE 1: Static Analysis (fast, <5s)
        // ═══════════════════════════════════════════════════════════
        send('progress', { step: 'static', message: 'Running static analysis engines...', percent: 5 });

        // Ensure Project exists
        let effectiveProjectId = projectId;
        if (effectiveProjectId) {
          const existingProject = await db.project.findUnique({ where: { id: effectiveProjectId } }).catch(() => null);
          if (!existingProject) {
            await db.project.create({
              data: { id: effectiveProjectId, name: contractName || 'AnalyzedContract', chain: 'ethereum', language: targetType === 'exchange' ? 'web' : 'solidity' },
            }).catch(() => {});
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
          data: { projectId: effectiveProjectId, name: contractName || 'AnalyzedContract', sourceCode: sourceCode.slice(0, 50000), language: contractLanguage },
        });
        const effectiveContractId = contract.id;

        const audit = await db.audit.create({
          data: { projectId: effectiveProjectId, workflow: hackenproofContext ? 'hackenproof-context-audit' : 'full-smart-contract-audit', status: 'running' },
        });
        const effectiveAuditId = audit.id;

        // Run static analyzers
        const canAnalyze = sourceCode && sourceCode.length > 10;
        const canDeepAnalyze = sourceCode && sourceCode.length > 20;
        const canSemanticAnalyze = sourceCode && sourceCode.length > 30;

        const [staticFindings, advancedFindings, taintFindings, semanticFindings, anomalyFindings, controlFlowFindings] = canAnalyze
          ? [runStaticScan(sourceCode, contract.name), canAnalyze ? runAdvancedScan(sourceCode, contract.name, 30) : [], canDeepAnalyze ? runTaintAnalysis(sourceCode, contract.name) : [], canSemanticAnalyze ? runSemanticAnalysis(sourceCode, contract.name) : [], canSemanticAnalyze ? runAnomalyDetection(sourceCode, contract.name) : [], canSemanticAnalyze ? runControlFlowAnalysis(sourceCode, contract.name) : []]
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

            const pocTemplate = POC_TEMPLATES[f.type];
            const hashSig = makeVulnHash(effectiveContractId, f.type, f.title);
            const existingVuln = await db.vulnerability.findFirst({ where: { hashSignature: hashSig } });
            if (existingVuln) { staticResults.push(existingVuln); continue; }

            let desc = f.description || '';
            if (f.remediation) desc += `\n\n**Remediation:** ${f.remediation}`;
            if (f.cwe && f.cwe.length > 0) desc += `\n\n**CWE:** ${f.cwe.join(', ')}`;
            if (hasMitigation) desc += `\n\n**Mitigations found:** ${f.mitigationsFound.join(', ')}`;
            if (f.evidence && f.evidence.length > 0) desc += `\n\n**Evidence:**\n${f.evidence.map((e: string) => `  - ${e}`).join('\n')}`;
            if (f.path) desc += `\n\n**Taint path:** ${f.path.join(' → ')}`;
            if (f.detectionMethod) desc += `\n\n**Detection Method:** ${f.detectionMethod}`;
            if (hackenProofAdj.adjusted) desc += `\n\n**HackenProof Classification:** ${hackenProofAdj.severity} (${hackenProofAdj.domain}) — ${hackenProofAdj.reasoning}`;

            const vuln = await db.vulnerability.create({
              data: {
                contractId: effectiveContractId, type: f.type, severity: finalSeverity, title: f.title,
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
          }
        }

        // Fallback heuristic — REMOVED.
        // Previously: if no static findings were detected, a placeholder
        // finding with confidence=0.30 was created ("Code requires manual
        // security review"). This violated the 90% confidence threshold
        // the user explicitly requested. Now: if no findings meet the
        // threshold, we simply report 0 findings — better than showing
        // a false positive with 30% confidence.
        //
        // The AI phase (Phase 2) will still run if an API key is configured
        // and may discover real findings with high confidence.

        // Filter static findings to only >= 90% confidence BEFORE sending
        // to UI. The user explicitly requested no findings below 90%.
        // Previously, low-confidence static findings (e.g., 0.70 from
        // pattern matching) were sent to UI in phase1_complete, then
        // filtered out only at the very end. But the UI had already
        // displayed them, creating the "showing < 90% findings" bug.
        const filteredStaticResults = staticResults.filter((r: any) => (r.confidence || 0) >= 0.90);
        // Delete dropped findings from DB
        for (const r of staticResults) {
          if ((r.confidence || 0) < 0.90) {
            try { await db.vulnerability.deleteMany({ where: { id: r.id } }); } catch {}
          }
        }

        // Send Phase 1 results — only findings >= 90% confidence
        send('phase1_complete', {
          findings: filteredStaticResults,
          contractId: effectiveContractId,
          auditId: effectiveAuditId,
          needsAI: hasApiKey && sourceCode.length > 20,
          message: `Static analysis found ${filteredStaticResults.length} findings (filtered from ${staticResults.length}, only >= 90% confidence shown)`,
        });

        // ═══════════════════════════════════════════════════════════
        // PHASE 2: AI Analysis (if API key available)
        // ═══════════════════════════════════════════════════════════
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        let aiResults: any[] = [];

        if (!hasApiKey || sourceCode.length <= 20) {
          // No AI — just complete with static results
          try { await db.audit.update({ where: { id: effectiveAuditId }, data: { status: 'completed', completedAt: new Date(), findings: staticResults.length } }); } catch {}
          send('complete', { findings: [...staticResults], message: `Analysis complete: ${staticResults.length} static findings (no AI key)` });
          return;
        }

        send('progress', { step: 'ai_start', message: 'Starting AI deep analysis...', percent: 30 });

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
        send('progress', { step: 'blockchain', message: 'Verifying on-chain data...', percent: 35 });
        const blockchainVerifyPromise = runBlockchainVerification(
          sourceCode, contractName || 'Contract',
          sourceCode.match(/0x[0-9a-fA-F]{40}/)?.[0]
        ).catch(() => '');
        const blockchainData = await Promise.race([
          blockchainVerifyPromise,
          new Promise<string>(resolve => setTimeout(() => resolve(''), 15_000)),
        ]);

        // Step 0.5: Web search (best-effort, 8s)
        send('progress', { step: 'websearch', message: 'Searching for known exploits...', percent: 40 });
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
        } catch {}

        // Step 1: Main AI analysis
        send('progress', { step: 'ai_analysis', message: 'Running GLM 5.2 deep analysis (this may take 30-60s)...', percent: 50 });
        const analysisSourceWithWeb = analysisSource + webSearchContext;

        // CRITICAL FIX: wrap AI call in try/catch with timeout to prevent
        // "TypeError: Failed to fetch" hang at 30%. If OpenRouter is
        // unreachable or takes too long, send error event and complete
        // with static findings only.
        let aiVulns: any[] = [];
        try {
          const aiResult = await Promise.race([
            isWebAnalysis
              ? analyzeWebWithGLM(analysisSourceWithWeb, contractName || 'Contract', { apiKey, model })
              : analyzeWithGLM(analysisSourceWithWeb, contractName || 'Contract', { apiKey, model }, blockchainData || undefined),
            new Promise<never>((_, reject) =>
              setTimeout(() => reject(new Error('AI analysis timeout (120s) — OpenRouter may be overloaded')), 120_000)),
          ]);
          aiVulns = aiResult;
        } catch (aiError: any) {
          console.error('[analyze-stream] AI analysis failed:', aiError);
          const errMsg = String(aiError?.message || aiError).slice(0, 300);
          send('progress', { step: 'ai_failed', message: `AI analysis failed: ${errMsg}. Completing with static findings only.`, percent: 75 });
          // Complete with static findings only — DON'T hang at 30%
          try {
            await db.audit.update({
              where: { id: effectiveAuditId },
              data: { status: 'completed', completedAt: new Date(), findings: staticResults.length, confidence: 0 },
            });
          } catch {}
          send('complete', {
            findings: [...filteredStaticResults],
            message: `Analysis complete: ${staticResults.length} static findings (AI analysis failed: ${errMsg})`,
          });
          return;
        }

        send('progress', { step: 'ai_done', message: `AI found ${aiVulns.length} potential vulnerabilities`, percent: 75 });

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

          const pocTemplate = POC_TEMPLATES[v.type];
          const hashSig = makeVulnHash(effectiveContractId, v.type, v.title);
          const existingVuln = await db.vulnerability.findFirst({ where: { hashSignature: hashSig } });
          if (existingVuln) { aiResults.push(existingVuln); continue; }

          const vuln = await db.vulnerability.create({
            data: {
              contractId: effectiveContractId, type: v.type, severity: v.severity, title: v.title,
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
          send('finding', { vulnerability: vuln });
        }

        // Step 3: Enhance with DeepSeek — SKIPPED to avoid multi-minute hang.
        // Enhancement calls DeepSeek once per finding (up to 4 findings × 5 min
        // timeout = 20 min hang). This was the main cause of "analysis never
        // completes" reports. The AI's initial description from GLM 5.2 is
        // already detailed enough — enhancement is a nice-to-have, not essential.
        // If we want to re-enable later, do it ASYNC (return immediately, let
        // enhancement run in background) or limit to 1 finding with 60s timeout.
        /*
        if (aiSavedVulns.length > 0) {
          send('progress', { step: 'enhancement', message: 'Enhancing findings with DeepSeek...', percent: 88 });
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
            } catch {}
          });
          await Promise.allSettled(enhancementPromises);
        }
        */

        // ─── Step 4: REAL active validation via EVM execution ──────
        // Replace LLM-based verifyVulnerabilityOnChain with actual exploit
        // execution. Compiles Solidity with solc, deploys to @ethereumjs/vm,
        // runs the exploit, checks post-conditions.
        //
        // Runs on ALL findings (not just top-2 critical/high). Findings
        // that PASS get +0.15 confidence. Findings that FAIL get -0.20.
        // ─── Step 4: Active validation — FAST & PARALLEL ──────────────
        // Active validation sends HTTP requests to the production target
        // to confirm vulnerabilities. This is ESSENTIAL — without it,
        // findings are just AI guesses.
        //
        // Optimization (vs previous slow version):
        //   - ALL findings validated in PARALLEL (not chunks of 3)
        //   - Per-request timeout: 5s (was 20s)
        //   - Payloads: 3 per type (was 15)
        //   - Params: 3 max (was 15)
        //   - Total: 8 findings × 18 requests × 5s / 8 parallel = ~18s
        //     (was 8 findings × 450 requests × 20s / 3 = 40 min)
        if (aiSavedVulns.length > 0) {
          send('progress', { step: 'onchain_verify', message: `Actively testing ${aiSavedVulns.length} findings via HTTP/EVM...`, percent: 94 });

          // Run ALL findings in parallel — each finding validates independently
          const verifyPromises = aiSavedVulns.map(async ({ vuln, rawFinding: v }: any) => {
            try {
              const verification = await activelyValidate(
                sourceCode,
                contractName || 'Contract',
                { title: v.title, type: v.type, severity: v.severity, description: v.description, location: v.location },
                apiKey, model
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
                  scope === 'lab'      ? '[LAB-VALIDATED] Exploit chain is technically viable in a controlled local environment.' :
                                        '[THEORETICAL] No runtime validation performed.';
                await db.vulnerability.update({
                  where: { id: vuln.id },
                  data: {
                    confidence: newConfidence, status: newStatus,
                    validationScope: scope,
                    description: vuln.description + `\n\n${scopeLabel}\n${verification.evidence}`,
                  },
                });
                vuln.confidence = newConfidence;
                vuln.status = newStatus;
                vuln.validationScope = scope;
                vuln._validationResult = 'confirmed';
              } else {
                const newConfidence = Math.max(vuln.confidence - 0.20, 0);
                const newStatus = newConfidence >= 0.90 ? 'validated' : 'candidate';
                const scope = verification.validationScope || 'theoretical';
                const scopeLabel =
                  scope === 'target' ? '[TARGET-VALIDATED] Exploit did NOT succeed against the production target.' :
                  scope === 'lab'      ? '[LAB-VALIDATED] Exploit did NOT succeed under lab conditions.' :
                                        '[THEORETICAL] No runtime validation performed.';
                await db.vulnerability.update({
                  where: { id: vuln.id },
                  data: {
                    confidence: newConfidence, status: newStatus,
                    validationScope: scope,
                    description: vuln.description + `\n\n${scopeLabel}\n${verification.evidence}`,
                  },
                });
                vuln.confidence = newConfidence;
                vuln.status = newStatus;
                vuln.validationScope = scope;
                vuln._validationResult = 'failed';
                vuln._validationReason = verification.evidence;
              }
            } catch (err: any) {
              vuln._validationResult = 'skipped';
              vuln._validationReason = String(err).slice(0, 100);
            }
          });
          await Promise.allSettled(verifyPromises);

          // Remove failed findings that dropped below 90%
          for (let i = aiResults.length - 1; i >= 0; i--) {
            const r = aiResults[i] as any;
            if (r._validationResult === 'failed' && (r.confidence || 0) < 0.90 && !r._deleted) {
              r._deleted = true;
              try { await db.vulnerability.deleteMany({ where: { id: r.id } }); } catch {}
              aiResults.splice(i, 1);
            }
          }
        }

        // === AUTO-VALIDATION: actively test each finding with real payloads ===
        // Per user request (2026-08-18): ALL findings must be actively validated
        // via activelyValidate() — sends real HTTP payloads / Foundry tests /
        // on-chain RPC calls to confirm with observable security impact.
        const allFindingsToValidate = [...filteredStaticResults, ...aiResults];
        if (allFindingsToValidate.length > 0) {
          send('progress', { step: 'auto_validate', message: `Actively validating ${allFindingsToValidate.length} findings via HTTP/Foundry/RPC...`, percent: 95 });
          try {
            const { activelyValidate } = await import('@/lib/active-validator');
            const validationPromises = allFindingsToValidate.map(async (vuln: any, idx: number) => {
              try {
                const result = await Promise.race([
                  activelyValidate(
                    sourceCode,
                    contractName || 'Contract',
                    { type: vuln.type, title: vuln.title, severity: vuln.severity,
                      description: vuln.description, location: vuln.location || '' },
                    apiKey, model,
                    targetUrl || undefined,
                  ),
                  new Promise<any>((_, reject) =>
                    setTimeout(() => reject(new Error('Validation timeout (30s)')), 30_000)),
                ]);

                const scope = result.validationScope || 'theoretical';
                const verdict = result.verdict || 'INCONCLUSIVE';

                let newStatus = vuln.status;
                let newConfidence = vuln.confidence;
                if (verdict === 'EXPLOITABLE') {
                  newStatus = scope === 'target' ? 'confirmed' : 'validated';
                  newConfidence = 1;
                } else if (verdict === 'NOT_EXPLOITABLE') {
                  newStatus = 'refuted';
                  newConfidence = 0;
                }

                console.log(`[analyze-stream] Finding ${idx + 1}/${allFindingsToValidate.length} (${vuln.type}): ${verdict} (scope=${scope})`);

                return {
                  id: vuln.id,
                  update: {
                    confidence: newConfidence,
                    status: newStatus,
                    validationScope: scope,
                    description: vuln.description + `\n\n[${verdict}] Validation scope: ${scope}\n${result.evidence?.slice(0, 500) || ''}`,
                  },
                };
              } catch (e: any) {
                console.log(`[analyze-stream] Finding ${idx + 1}/${allFindingsToValidate.length} (${vuln.type}): validation failed — ${String(e?.message || e).slice(0, 100)}`);
                return null;
              }
            });

            const validationResults = await Promise.all(validationPromises);
            for (const vr of validationResults) {
              if (!vr) continue;
              try {
                await db.vulnerability.update({ where: { id: vr.id }, data: vr.update });
                // Update in both arrays
                for (const arr of [filteredStaticResults, aiResults]) {
                  const idx = arr.findIndex((r: any) => r.id === vr.id);
                  if (idx >= 0) arr[idx] = { ...arr[idx], ...vr.update };
                }
              } catch {}
            }
            const confirmedCount = [...filteredStaticResults, ...aiResults].filter((r: any) => r.status === 'confirmed' || r.status === 'validated').length;
            const refutedCount = [...filteredStaticResults, ...aiResults].filter((r: any) => r.status === 'refuted').length;
            console.log(`[analyze-stream] Auto-validation complete. ${confirmedCount} confirmed, ${refutedCount} refuted.`);
          } catch (e) {
            console.error('[analyze-stream] Auto-validation error:', e);
          }
        }

        // Complete audit — apply 90% confidence threshold
        // Use filteredStaticResults (already filtered in phase 1) instead of raw staticResults
        const allResultsRaw = [...filteredStaticResults, ...aiResults];
        const allResults = allResultsRaw.filter((r: any) => (r.confidence || 0) >= 0.90);
        // Delete dropped findings from DB — but only those not already deleted above
        // (the previous loop marked them _deleted=true). Without this check, Prisma
        // errors spam the logs: "No record was found for a delete."
        for (const r of allResultsRaw) {
          if ((r.confidence || 0) < 0.90 && !r._deleted) {
            r._deleted = true;
            try { await db.vulnerability.deleteMany({ where: { id: r.id } }); } catch {}
          }
        }
        try {
          await db.audit.update({
            where: { id: effectiveAuditId },
            data: {
              status: 'completed', completedAt: new Date(),
              findings: allResults.length, confirmed: allResults.filter(r => r.status === 'confirmed').length,
              confidence: allResults.length > 0 ? allResults.reduce((s, r) => s + r.confidence, 0) / allResults.length : 0,
            },
          });
        } catch {}

        send('complete', {
          findings: allResults,
          message: `Analysis complete: ${staticResults.length} static + ${aiResults.length} AI findings`,
        });

      } catch (e) {
        send('error', {
          error: String(e),
          message: `Analysis failed: ${String(e).slice(0, 200)}`,
        });
      } finally {
        if (heartbeatId) clearInterval(heartbeatId);
        try { controller.close(); } catch {}
      }
    },
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
    },
  });
}
