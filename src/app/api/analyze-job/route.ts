import { NextRequest, NextResponse } from 'next/server';
export const maxDuration = 900;
export const dynamic = 'force-dynamic';

import { db } from '@/lib/db';
import { analyzeWithGLM, analyzeWebWithGLM, analyzeWithGLMDeep, analyzeWebWithGLMDeep, DEFAULT_MODEL } from '@/lib/glm';
import { activelyValidate } from '@/lib/active-validator';
import { runStaticScan } from '@/lib/static-scanner';
import { runAdvancedScan } from '@/lib/advanced-pattern-engine';
import { runTaintAnalysis } from '@/lib/dataflow-analyzer';
import { runSemanticAnalysis } from '@/lib/semantic-analyzer';
import { runAnomalyDetection } from '@/lib/anomaly-detector';
import { runControlFlowAnalysis } from '@/lib/control-flow-analyzer';
import { createHash } from 'crypto';

const CATEGORY_MAP: Record<string, string> = {
  reentrancy: 'Reentrancy', oracle_manipulation: 'Oracle Manipulation',
  access_control: 'Access Control', xss: 'XSS', sql_injection: 'SQL Injection',
  ssrf: 'SSRF', open_redirect: 'Open Redirect', cors_misconfig: 'CORS Misconfiguration',
  csp_missing: 'Missing CSP', csrf: 'CSRF', idor: 'IDOR', api_leak: 'API Key Leak',
  business_logic: 'Business Logic', postmessage_abuse: 'PostMessage Abuse',
};

function makeVulnHash(contractId: string, type: string, title: string): string {
  return createHash('sha256').update(`${contractId}:${type}:${title}`).digest('hex').slice(0, 32);
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const { sourceCode, contractName, targetType, targetUrl, hackenproofContext } = body;

    if (!sourceCode && !targetUrl) {
      return NextResponse.json({ error: 'Missing sourceCode or targetUrl' }, { status: 400 });
    }

    const settings = await db.settings.findFirst().catch(() => null);
    const apiKey = process.env.OPENROUTER_API_KEY || settings?.apiKey || '';
    const model = settings?.model || DEFAULT_MODEL;

    if (!apiKey || !apiKey.startsWith('sk-or-v1-')) {
      return NextResponse.json({ error: 'OpenRouter API key not configured' }, { status: 401 });
    }

    const project = await db.project.create({
      data: { name: contractName || targetUrl || 'Analysis', chain: 'ethereum', language: targetType === 'exchange' ? 'web' : 'solidity' },
    });
    const contract = await db.contract.create({
      data: { projectId: project.id, name: contractName || 'AnalyzedContract', sourceCode: (sourceCode || '').slice(0, 50000), language: targetType === 'exchange' ? 'web' : 'solidity' },
    });
    const audit = await db.audit.create({
      data: { projectId: project.id, workflow: 'background-analysis', status: 'running' },
    });

    const job = await db.analysisJob.create({
      data: {
        status: 'pending', progress: 0, message: 'Job created',
        targetUrl: targetUrl || null, targetType: targetType || 'contract',
        sourceCode: (sourceCode || '').slice(0, 5000), contractName: contractName || null,
        projectId: project.id, contractId: contract.id, auditId: audit.id,
      },
    });

    // Start background analysis — do NOT await
    runAnalysisInBackground(job.id, {
      sourceCode: sourceCode || '', contractName: contractName || 'AnalyzedContract',
      targetType: targetType || 'contract', targetUrl: targetUrl || undefined,
      hackenproofContext: hackenproofContext || null, apiKey, model,
      projectId: project.id, contractId: contract.id, auditId: audit.id,
    }).catch(async (err) => {
      await db.analysisJob.update({
        where: { id: job.id },
        data: { status: 'failed', error: String(err).slice(0, 500), progress: 100, message: 'Analysis failed' },
      }).catch(() => {});
    });

    return NextResponse.json({
      jobId: job.id, status: 'pending',
      message: 'Analysis started. Poll /api/job-status for progress.',
    });
  } catch (e: any) {
    return NextResponse.json({ error: String(e).slice(0, 300) }, { status: 500 });
  }
}

async function runAnalysisInBackground(jobId: string, config: {
  sourceCode: string; contractName: string; targetType: string; targetUrl?: string;
  hackenproofContext: any; apiKey: string; model: string;
  projectId: string; contractId: string; auditId: string;
}) {
  const { sourceCode, contractName, targetType, targetUrl, apiKey, model, contractId, auditId } = config;
  const isWeb = targetType === 'exchange' || contractName.endsWith('.html');

  const updateJob = async (progress: number, message: string) => {
    await db.analysisJob.update({ where: { id: jobId }, data: { progress, message, status: progress < 100 ? 'running' : 'completed' } }).catch(() => {});
  };

  try {
    await updateJob(5, 'Running static analysis...');

    // Phase 1: Static
    const staticResults: any[] = [];
    try { staticResults.push(...(await runStaticScan(sourceCode, contractName))); } catch {}
    try { staticResults.push(...(await runAdvancedScan(sourceCode, contractName))); } catch {}
    if (!isWeb) {
      try { staticResults.push(...(await runTaintAnalysis(sourceCode, contractName))); } catch {}
      try { staticResults.push(...(await runSemanticAnalysis(sourceCode, contractName))); } catch {}
      try { staticResults.push(...(await runAnomalyDetection(sourceCode, contractName))); } catch {}
      try { staticResults.push(...(await runControlFlowAnalysis(sourceCode, contractName))); } catch {}
    }

    const savedStatic: any[] = [];
    for (const v of staticResults) {
      const hashSig = makeVulnHash(contractId, v.type, v.title);
      try {
        const vuln = await db.vulnerability.create({
          data: { contractId, type: v.type, severity: v.severity || 'medium', title: v.title,
            description: v.description || '', location: v.location || `${contractName}:L1`,
            confidence: v.confidence || 0.5, status: v.confidence >= 0.9 ? 'validated' : 'candidate',
            v1Symbolic: v.v1Symbolic || null, v2Fuzzing: v.v2Fuzzing || null,
            v3Formal: v.v3Formal || null, v4Economic: v.v4Economic || null,
            hashSignature: hashSig, patternTag: v.type, target: contractName,
            vulnCategory: CATEGORY_MAP[v.type] || v.type,
            validationSteps: v.validationSteps || '', poc: v.poc || '',
            pocFilename: `${v.type}_attack.t.sol`, codeSnippet: sourceCode ? sourceCode.slice(0, 200) : null },
        });
        savedStatic.push({ vuln, rawFinding: v });
      } catch {}
    }

    await updateJob(20, `Static analysis: ${savedStatic.length} findings`);

    // Phase 2: MULTI-PASS AI ANALYSIS
    //   Pass 1 (surface): find obvious vulnerabilities (XSS, SQLi, reentrancy, etc.)
    //   Pass 2 (deep):    find non-obvious, multi-step, cross-function vulns
    //   Merge: dedupe by hash, surface + deep findings proceed to validation
    await updateJob(30, 'Starting AI surface analysis (pass 1/2)...');
    let aiVulns: any[] = [];
    try {
      // Pass 1 — surface scan (240s timeout per callGLM)
      const aiPromise = isWeb
        ? analyzeWebWithGLM(sourceCode.slice(0, 30000), contractName, { apiKey, model })
        : analyzeWithGLM(sourceCode, contractName, { apiKey, model }, undefined);
      const timeoutPromise = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('AI pass 1 timeout after 260s')), 260_000)
      );
      aiVulns = await Promise.race([aiPromise, timeoutPromise]);
    } catch (err: any) {
      await updateJob(40, `AI pass 1 error (continuing): ${String(err).slice(0, 100)}`);
      // Don't throw — continue with static findings + try pass 2
    }

    await updateJob(50, `AI pass 1 found ${aiVulns.length} surface vulnerabilities. Starting deep analysis (pass 2/2)...`);

    // Pass 2 — DEEP analysis (finds non-obvious, multi-step vulnerabilities)
    let deepVulns: any[] = [];
    try {
      const firstPassSummary = aiVulns.map(v => ({
        title: v.title, type: v.type, severity: v.severity, description: (v.description || '').slice(0, 200),
      }));
      const deepPromise = isWeb
        ? analyzeWebWithGLMDeep(sourceCode.slice(0, 30000), contractName, { apiKey, model }, firstPassSummary)
        : analyzeWithGLMDeep(sourceCode, contractName, { apiKey, model }, firstPassSummary);
      const deepTimeout = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('AI pass 2 (deep) timeout after 260s')), 260_000)
      );
      deepVulns = await Promise.race([deepPromise, deepTimeout]);
    } catch (err: any) {
      await updateJob(60, `AI pass 2 (deep) error (continuing with pass 1 only): ${String(err).slice(0, 100)}`);
    }

    // Merge surface + deep findings
    aiVulns = [...aiVulns, ...deepVulns];

    await updateJob(65, `AI total: ${aiVulns.length} findings (${deepVulns.length} deep)`);

    const savedAi: any[] = [];
    let droppedLowSeverity = 0;
    for (const v of aiVulns) {
      // ─── SEVERITY FLOOR ──────────────────────────────────────────
      // Discard `low` / `info` severity findings UNLESS the type is one that
      // the obvious-vuln detector or active validator can promote to higher.
      // This implements the user's requirement: "find at least medium/high/critical".
      // Low-severity config noise (missing HSTS, verbose Server header, etc.) is
      // filtered out unless the description contains a concrete exploit chain.
      const sev = (v.severity || 'medium').toLowerCase();
      const isLow = sev === 'low' || sev === 'info';
      const allowedLowTypes = new Set(['api_leak', 'info_exposure']); // these can be promoted by obvious-check
      const hasConcreteChain = /(\bRCE\b|data exfiltrat|fund theft|wallet drain|credential leak|private key|mnemonic)/i.test(v.description || '');
      if (isLow && !allowedLowTypes.has((v.type || '').toLowerCase()) && !hasConcreteChain) {
        droppedLowSeverity++;
        continue;
      }

      const hashSig = makeVulnHash(contractId, v.type, v.title);
      try {
        const existing = await db.vulnerability.findFirst({ where: { hashSignature: hashSig } });
        if (existing) continue;

        // BINARY model: no confidence percentages. Status tells the truth.
        // 'candidate' = AI found something, NOT YET TESTED
        // Normalize all string fields — AI sometimes returns arrays for
        // validationSteps/pocOutline/description. Prisma expects String.
        const str = (val: any): string => {
          if (val == null) return '';
          if (typeof val === 'string') return val;
          if (Array.isArray(val)) return val.map(s => typeof s === 'string' ? s : String(s)).join('\n');
          return String(val);
        };
        const num = (val: any, fallback = 0.5): number => {
          if (typeof val === 'number' && !isNaN(val)) return val;
          if (typeof val === 'string') { const n = parseFloat(val); if (!isNaN(n)) return n; }
          return fallback;
        };
        const vuln = await db.vulnerability.create({
          data: { contractId,
            type: str(v.type) || 'unknown',
            severity: str(v.severity) || 'medium',
            title: str(v.title) || 'Untitled Finding',
            description: str(v.description) || '',
            location: str(v.location) || `${contractName}:L1`,
            confidence: 0, status: 'candidate',
            v1Symbolic: num(v.v1Symbolic, 0.5), v2Fuzzing: num(v.v2Fuzzing, 0.5),
            v3Formal: num(v.v3Formal, 0.5), v4Economic: num(v.v4Economic, 0),
            hashSignature: hashSig, patternTag: str(v.type) || 'unknown', target: contractName,
            vulnCategory: CATEGORY_MAP[str(v.type)] || str(v.type) || 'unknown',
            validationSteps: str(v.validationSteps), poc: str(v.pocOutline || v.poc),
            pocFilename: `${str(v.type) || 'unknown'}_attack.t.sol`,
            codeSnippet: sourceCode ? sourceCode.slice(0, 200) : null },
        });
        savedAi.push({ vuln, rawFinding: v });
      } catch (err: any) {
        // Log the error but don't crash — continue saving other findings
        console.error(`[analyze-job] Failed to save finding "${v?.title}": ${String(err?.message || err).slice(0, 200)}`);
      }
    }

    if (droppedLowSeverity > 0) {
      await updateJob(70, `Filtered out ${droppedLowSeverity} low-severity findings without concrete exploit chain. Saving ${savedAi.length} medium+ findings...`);
    }

    await updateJob(75, `Saved ${savedAi.length} AI findings. Starting validation...`);

    // Phase 3: THREE-STATE VERDICT VALIDATION
    //   EXPLOITABLE     → status='confirmed' (target) or 'validated' (lab)
    //   NOT_EXPLOITABLE → status='refuted' (tested, exploit doesn't work)
    //   INCONCLUSIVE    → status='candidate' (couldn't determine — no URL, no API, network error, etc.)
    if (savedAi.length > 0) {
      const verifyPromises = savedAi.map(async ({ vuln, rawFinding: v }: any) => {
        try {
          const verification = await activelyValidate(
            sourceCode, contractName,
            { title: v.title, type: v.type, severity: v.severity, description: v.description, location: v.location },
            apiKey, model,
            targetUrl || undefined  // Pass targetUrl DIRECTLY, not hidden in description
          );
          const scope = verification.validationScope || 'theoretical';
          const verdict = verification.verdict || (verification.confirmed ? 'EXPLOITABLE' : 'INCONCLUSIVE');

          if (verdict === 'EXPLOITABLE') {
            // EXPLOIT CONFIRMED — exploit works
            const newStatus = scope === 'target' ? 'confirmed' : 'validated';
            const label = scope === 'target'
              ? '[EXPLOITABLE] Exploit confirmed against production target via real HTTP request.'
              : '[EXPLOITABLE] Exploit confirmed in lab (Foundry test passed).';
            await db.vulnerability.update({ where: { id: vuln.id },
              data: { confidence: 1, status: newStatus, validationScope: scope,
                description: vuln.description + `\n\n${label}\n${verification.evidence}` } }).catch(() => {});
            vuln.confidence = 1; vuln.status = newStatus; vuln.validationScope = scope;
          } else if (verdict === 'NOT_EXPLOITABLE') {
            // TESTED AND REFUTED — exploit does NOT work
            const label = scope === 'target'
              ? '[NOT_EXPLOITABLE] Exploit tested against production target and did NOT succeed.'
              : '[NOT_EXPLOITABLE] Exploit tested in lab and did NOT succeed.';
            await db.vulnerability.update({ where: { id: vuln.id },
              data: { confidence: 0, status: 'refuted', validationScope: scope,
                description: vuln.description + `\n\n${label}\n${verification.evidence}` } }).catch(() => {});
            vuln.confidence = 0; vuln.validationScope = scope; vuln.status = 'refuted';
          } else {
            // INCONCLUSIVE — couldn't determine, leave as candidate
            const label = '[INCONCLUSIVE] Validation ran but could not determine exploitability. ' +
              (scope === 'theoretical'
                ? 'Test could not execute (no URL, network error, or no test suite for this vuln type).'
                : 'Test executed but result was ambiguous. Manual verification needed.');
            await db.vulnerability.update({ where: { id: vuln.id },
              data: { confidence: 0, status: 'candidate', validationScope: scope,
                description: vuln.description + `\n\n${label}\n${verification.evidence}` } }).catch(() => {});
            vuln.confidence = 0; vuln.validationScope = scope; vuln.status = 'candidate';
          }
        } catch {
          // VALIDATION ERROR — can't determine, leave as candidate
          await db.vulnerability.update({ where: { id: vuln.id },
            data: { validationScope: 'theoretical',
              description: vuln.description + '\n\n[INCONCLUSIVE] Validation could not run — exception during test execution. Manual verification needed.' } }).catch(() => {});
          vuln.validationScope = 'theoretical';
          vuln.status = 'candidate';
        }
      });
      await Promise.allSettled(verifyPromises);
    }

    const allResults = [...savedStatic.map(s => s.vuln), ...savedAi.map(s => s.vuln)];
    const exploitCount = allResults.filter((r: any) => r.status === 'confirmed' || r.status === 'validated').length;
    const refutedCount = allResults.filter((r: any) => r.status === 'refuted').length;
    const inconclusiveCount = allResults.filter((r: any) => r.status === 'candidate').length;

    await updateJob(100, `Analysis complete: ${exploitCount} exploitable, ${refutedCount} not exploitable, ${inconclusiveCount} inconclusive (out of ${allResults.length})`);
    await db.audit.update({ where: { id: auditId }, data: { status: 'completed', findings: allResults.length, completedAt: new Date() } }).catch(() => {});
    await db.analysisJob.update({ where: { id: jobId }, data: { status: 'completed', resultCount: exploitCount } }).catch(() => {});

  } catch (err: any) {
    // Fix bug #1: audit lifecycle — always mark as completed or failed
    await db.audit.update({ where: { id: auditId },
      data: { status: 'failed', completedAt: new Date() } }).catch(() => {});
    await db.analysisJob.update({ where: { id: jobId },
      data: { status: 'failed', error: String(err).slice(0, 500), progress: 100, message: 'Analysis failed' } }).catch(() => {});
  }
}
