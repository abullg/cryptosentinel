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
import { runActiveProbes, buildProbeInputsFromCrawl, type PreConfirmedFinding } from '@/lib/active-probe';
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
    const { sourceCode, contractName, targetType, targetUrl, hackenproofContext,
            // New crawl fields — populated by /api/fetch-url deep-crawler
            discoveredEndpoints, discoveredForms, discoveredParams,
    } = body;

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
      // Pass crawl data so we can probe every discovered endpoint BEFORE
      // AI even starts — this is what the user means by "literally search
      // everywhere on the site where it might be".
      discoveredEndpoints: Array.isArray(discoveredEndpoints) ? discoveredEndpoints : [],
      discoveredForms: Array.isArray(discoveredForms) ? discoveredForms : [],
      discoveredParams: Array.isArray(discoveredParams) ? discoveredParams : [],
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
  // New: crawl data from /api/fetch-url deep-crawler
  discoveredEndpoints: string[];
  discoveredForms: { action: string; method: string; fields: string[] }[];
  discoveredParams: string[];
}) {
  const { sourceCode, contractName, targetType, targetUrl, apiKey, model, contractId, auditId,
          discoveredEndpoints, discoveredForms, discoveredParams } = config;
  const isWeb = targetType === 'exchange' || contractName.endsWith('.html');

  const updateJob = async (progress: number, message: string) => {
    await db.analysisJob.update({ where: { id: jobId }, data: { progress, message, status: progress < 100 ? 'running' : 'completed' } }).catch(() => {});
  };

  // ─── GLOBAL TIMEOUT: entire job must complete in 10 min ───
  // If anything hangs (AI call, validation, DB write), this fires and
  // completes the job with whatever findings we have. NEVER hang forever.
  let jobTimedOut = false;
  const globalTimeout = setTimeout(async () => {
    jobTimedOut = true;
    console.error('[analyze-job] GLOBAL TIMEOUT (10 min) — completing with current findings');
    try {
      await updateJob(95, 'Analysis timeout (10 min) — completing with current findings.');
      // Get whatever findings we have
      const existingVulns = await db.vulnerability.findMany({ where: { contractId } }).catch(() => []);
      await db.audit.update({ where: { id: auditId },
        data: { status: 'completed', completedAt: new Date(), findings: existingVulns.length } }).catch(() => {});
      await db.analysisJob.update({ where: { id: jobId },
        data: { status: 'completed', progress: 100, message: `Timeout after 10 min — ${existingVulns.length} findings saved`, resultCount: existingVulns.filter((v: any) => v.status === 'confirmed' || v.status === 'validated').length } }).catch(() => {});
    } catch {}
  }, 600_000); // 10 minutes

  try {
    const globalStartTime = Date.now();
    await updateJob(5, 'Running static analysis...');

    // ─── Phase 0: PER-ENDPOINT ACTIVE PROBES (runs FIRST, before AI) ───
    // The user explicitly asked us to "literally search everywhere on the
    // site where it might be". The deep crawler discovered endpoints/forms/
    // params; now we send a battery of payloads (XSS, SQLi, SSRF, cmd
    // injection, SSTI, path traversal, open redirect, etc.) to EVERY
    // discovered surface and check the response for HARD evidence
    // (payload reflected verbatim, SQL error string, SLEEP delay ≥3s,
    // /etc/passwd content, AWS metadata, etc.).
    //
    // Findings with HARD HTTP evidence are saved as status='confirmed'
    // immediately — no AI needed. This means even if AI fails/times out,
    // we still surface real vulnerabilities to the user.
    let preConfirmed: PreConfirmedFinding[] = [];
    if (isWeb && targetUrl && (discoveredEndpoints.length > 0 || discoveredForms.length > 0 || discoveredParams.length > 0)) {
      await updateJob(10, `Active probing: ${discoveredEndpoints.length} endpoints, ${discoveredForms.length} forms, ${discoveredParams.length} params...`);
      try {
        const probeInputs = buildProbeInputsFromCrawl({
          discoveredEndpoints, discoveredForms, discoveredParams,
          targetUrl,
        });
        console.log(`[analyze-job] Active probes: ${probeInputs.length} inputs built from crawl data`);
        preConfirmed = await runActiveProbes(probeInputs);
        console.log(`[analyze-job] Active probes confirmed ${preConfirmed.length} findings with HARD HTTP evidence`);
      } catch (probeErr) {
        console.warn('[analyze-job] Active probes failed:', String(probeErr).slice(0, 150));
      }

      // Save confirmed findings to DB immediately — bypassing AI entirely
      for (const f of preConfirmed) {
        const hashSig = makeVulnHash(contractId, f.type, f.title);
        try {
          await db.vulnerability.create({
            data: {
              contractId,
              type: f.type,
              severity: f.severity,
              title: f.title,
              description: f.description,
              location: f.location,
              confidence: f.confidence,
              status: 'confirmed', // HARD HTTP evidence = confirmed
              hashSignature: hashSig,
              patternTag: f.type,
              target: contractName,
              vulnCategory: CATEGORY_MAP[f.type] || f.type,
              validationSteps: `Actively validated via real HTTP request. Evidence:\n${f.evidence}`,
              poc: f.pocOutline,
              pocFilename: `${f.type}_attack.t.sol`,
              codeSnippet: sourceCode ? sourceCode.slice(0, 200) : null,
              validationScope: 'target',
            },
          });
        } catch (e) {
          console.warn('[analyze-job] Failed to save pre-confirmed finding:', String(e).slice(0, 100));
        }
      }
      if (preConfirmed.length > 0) {
        await updateJob(15, `Active probing CONFIRMED ${preConfirmed.length} vulnerabilities (HARD HTTP evidence)`);
      } else {
        await updateJob(15, 'Active probing complete — no hard exploits found. Continuing to AI analysis...');
      }
    }

    if (jobTimedOut) return;

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

    if (jobTimedOut) return;

    // Phase 2: AI ANALYSIS (pass 1 — surface scan)
    // IMPORTANT: progress must INCREMENT gradually during AI pass — never
    // stay at the same % for 60s. The old code stayed at 30% for the entire
    // AI pass 1 (60s) which made the UI look frozen ("stuck at 30%").
    // Now: 30% → 40% → 45% during pass 1, then 50% → 60% → 65% during
    // pass 2, so the user always sees forward motion.
    await updateJob(30, 'Starting AI surface analysis (pass 1/2)...');
    let aiVulns: any[] = [];
    // Declare OUTSIDE try so catch block can access it
    let progressInterval: ReturnType<typeof setInterval> | null = null;
    let aiPass1Progress = 30;
    try {
      // Tick progress forward every 10s — 30 → 32 → 34 → ... → 45 max
      // This eliminates the "frozen at 30%" cosmetic bug.
      progressInterval = setInterval(() => {
        aiPass1Progress = Math.min(45, aiPass1Progress + 2);
        const elapsed = Math.round((Date.now() - (globalStartTime || Date.now())) / 1000);
        updateJob(aiPass1Progress, `AI pass 1 surface analysis... ${elapsed}s elapsed`).catch(() => {});
      }, 10_000);

      const aiPromise = isWeb
        ? analyzeWebWithGLM(sourceCode.slice(0, 30000), contractName, { apiKey, model })
        : analyzeWithGLM(sourceCode, contractName, { apiKey, model }, undefined);
      const timeoutPromise = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('AI pass 1 timeout after 90s')), 90_000)
      );
      aiVulns = await Promise.race([aiPromise, timeoutPromise]);
      if (progressInterval) clearInterval(progressInterval);
    } catch (err: any) {
      if (progressInterval) clearInterval(progressInterval);
      // Graceful degradation: save what we have, but DON'T jump straight to
      // 100% — that looks like a crash. Step through 50% → 70% → 100% so
      // the UI shows the failure path is intentional.
      await updateJob(50, `AI pass 1 failed: ${String(err).slice(0, 80)}. Falling back to static-only.`);
      if (jobTimedOut) return;
      const allResults = savedStatic.map(s => s.vuln);
      await new Promise(r => setTimeout(r, 300));
      await updateJob(75, `Saving ${allResults.length} static findings...`);
      await new Promise(r => setTimeout(r, 300));
      await updateJob(100, `Analysis complete (AI failed): ${allResults.length} static findings`);
      await db.audit.update({ where: { id: auditId }, data: { status: 'completed', findings: allResults.length, completedAt: new Date() } }).catch(() => {});
      await db.analysisJob.update({ where: { id: jobId }, data: { status: 'completed', resultCount: 0 } }).catch(() => {});
      clearTimeout(globalTimeout);
      return;
    }

    if (jobTimedOut) return;

    await updateJob(50, `AI pass 1: ${aiVulns.length} surface vulnerabilities. Starting deep analysis (pass 2/2)...`);

    // Pass 2 — DEEP analysis (with progress increment to avoid "stuck at 50%")
    let deepVulns: any[] = [];
    let deepProgressInterval: ReturnType<typeof setInterval> | null = null;
    let aiPass2Progress = 50;
    try {
      deepProgressInterval = setInterval(() => {
        aiPass2Progress = Math.min(62, aiPass2Progress + 2);
        const elapsed = Math.round((Date.now() - globalStartTime) / 1000);
        updateJob(aiPass2Progress, `AI pass 2 deep analysis... ${elapsed}s elapsed`).catch(() => {});
      }, 10_000);

      const firstPassSummary = aiVulns.map(v => ({
        title: v.title, type: v.type, severity: v.severity, description: (v.description || '').slice(0, 200),
      }));
      const deepPromise = isWeb
        ? analyzeWebWithGLMDeep(sourceCode.slice(0, 30000), contractName, { apiKey, model }, firstPassSummary)
        : analyzeWithGLMDeep(sourceCode, contractName, { apiKey, model }, firstPassSummary);
      const deepTimeout = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('AI pass 2 (deep) timeout after 90s')), 90_000)
      );
      deepVulns = await Promise.race([deepPromise, deepTimeout]);
      if (deepProgressInterval) clearInterval(deepProgressInterval);
    } catch (err: any) {
      if (deepProgressInterval) clearInterval(deepProgressInterval);
      await updateJob(65, `AI pass 2 (deep) failed: ${String(err).slice(0, 80)}. Continuing with pass 1 only.`);
    }

    if (jobTimedOut) return;

    // Merge surface + deep findings
    aiVulns = [...aiVulns, ...deepVulns];

    await updateJob(65, `AI total: ${aiVulns.length} findings (${deepVulns.length} deep)`);

    const savedAi: any[] = [];
    let droppedLowSeverity = 0;
    for (const v of aiVulns) {
      const sev = (v.severity || 'medium').toLowerCase();
      const isLow = sev === 'low' || sev === 'info';
      const allowedLowTypes = new Set(['api_leak', 'info_exposure']);
      const hasConcreteChain = /(\bRCE\b|data exfiltrat|fund theft|wallet drain|credential leak|private key|mnemonic)/i.test(v.description || '');
      if (isLow && !allowedLowTypes.has((v.type || '').toLowerCase()) && !hasConcreteChain) {
        droppedLowSeverity++;
        continue;
      }

      const hashSig = makeVulnHash(contractId, v.type, v.title);
      try {
        const existing = await db.vulnerability.findFirst({ where: { hashSignature: hashSig } });
        if (existing) continue;

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
        console.error(`[analyze-job] Failed to save finding "${v?.title}": ${String(err?.message || err).slice(0, 200)}`);
      }
    }

    if (jobTimedOut) return;

    if (droppedLowSeverity > 0) {
      await updateJob(70, `Filtered out ${droppedLowSeverity} low-severity findings. Saving ${savedAi.length} medium+ findings...`);
    }

    await updateJob(75, `Saved ${savedAi.length} AI findings. Starting validation...`);

    // Phase 3: ACTIVE VALIDATION (parallel, 30s per finding)
    if (savedAi.length > 0 && !jobTimedOut) {
      const verifyPromises = savedAi.map(async ({ vuln, rawFinding: v }: any) => {
        try {
          const verification = await Promise.race([
            activelyValidate(
              sourceCode, contractName,
              { title: v.title, type: v.type, severity: v.severity, description: v.description, location: v.location },
              apiKey, model,
              targetUrl || undefined
            ),
            new Promise<any>((_, reject) =>
              setTimeout(() => reject(new Error('Validation timeout (30s)')), 30_000)),
          ]);

          const scope = verification.validationScope || 'theoretical';
          const verdict = verification.verdict || (verification.confirmed ? 'EXPLOITABLE' : 'INCONCLUSIVE');

          if (verdict === 'EXPLOITABLE') {
            const newStatus = scope === 'target' ? 'confirmed' : 'validated';
            const label = scope === 'target'
              ? '[EXPLOITABLE] Exploit confirmed against production target via real HTTP request.'
              : '[EXPLOITABLE] Exploit confirmed in lab (Foundry test passed).';
            await db.vulnerability.update({ where: { id: vuln.id },
              data: { confidence: 1, status: newStatus, validationScope: scope,
                description: vuln.description + `\n\n${label}\n${verification.evidence}` } }).catch(() => {});
            vuln.confidence = 1; vuln.status = newStatus; vuln.validationScope = scope;
          } else if (verdict === 'NOT_EXPLOITABLE') {
            const label = scope === 'target'
              ? '[NOT_EXPLOITABLE] Exploit tested against production target and did NOT succeed.'
              : '[NOT_EXPLOITABLE] Exploit tested in lab and did NOT succeed.';
            await db.vulnerability.update({ where: { id: vuln.id },
              data: { confidence: 0, status: 'refuted', validationScope: scope,
                description: vuln.description + `\n\n${label}\n${verification.evidence}` } }).catch(() => {});
            vuln.confidence = 0; vuln.validationScope = scope; vuln.status = 'refuted';
          } else {
            const label = '[INCONCLUSIVE] Validation ran but could not determine exploitability.';
            await db.vulnerability.update({ where: { id: vuln.id },
              data: { confidence: 0, status: 'candidate', validationScope: scope,
                description: vuln.description + `\n\n${label}\n${verification.evidence}` } }).catch(() => {});
            vuln.confidence = 0; vuln.validationScope = scope; vuln.status = 'candidate';
          }
        } catch {
          await db.vulnerability.update({ where: { id: vuln.id },
            data: { validationScope: 'theoretical',
              description: vuln.description + '\n\n[INCONCLUSIVE] Validation could not run.' } }).catch(() => {});
          vuln.validationScope = 'theoretical';
          vuln.status = 'candidate';
        }
      });
      await Promise.allSettled(verifyPromises);
    }

    const allResults = [...savedStatic.map(s => s.vuln), ...savedAi.map(s => s.vuln)];
    const exploitCount = allResults.filter((r: any) => r.status === 'confirmed' || r.status === 'validated').length
      + preConfirmed.length; // pre-confirmed = HARD HTTP evidence from active probes
    const refutedCount = allResults.filter((r: any) => r.status === 'refuted').length;
    const inconclusiveCount = allResults.filter((r: any) => r.status === 'candidate').length;

    const summary = preConfirmed.length > 0
      ? `Analysis complete: ${exploitCount} exploitable (${preConfirmed.length} from active HTTP probes + ${allResults.filter((r: any) => r.status === 'confirmed' || r.status === 'validated').length} from AI), ${refutedCount} not exploitable, ${inconclusiveCount} inconclusive (out of ${allResults.length + preConfirmed.length})`
      : `Analysis complete: ${exploitCount} exploitable, ${refutedCount} not exploitable, ${inconclusiveCount} inconclusive (out of ${allResults.length})`;
    await updateJob(100, summary);
    await db.audit.update({ where: { id: auditId }, data: { status: 'completed', findings: allResults.length + preConfirmed.length, completedAt: new Date() } }).catch(() => {});
    await db.analysisJob.update({ where: { id: jobId }, data: { status: 'completed', resultCount: exploitCount } }).catch(() => {});

  } catch (err: any) {
    await db.audit.update({ where: { id: auditId },
      data: { status: 'failed', completedAt: new Date() } }).catch(() => {});
    await db.analysisJob.update({ where: { id: jobId },
      data: { status: 'failed', error: String(err).slice(0, 500), progress: 100, message: 'Analysis failed' } }).catch(() => {});
  } finally {
    clearTimeout(globalTimeout);
  }
}
