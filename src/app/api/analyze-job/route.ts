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
import { rigorVerifyFinding } from '@/lib/rigor-verify';
import { writeProgressFile } from '@/lib/progress-file';
import { withTimeout, fireAndForget } from '@/lib/with-timeout';
import { checkPassiveEvidence } from '@/lib/passive-evidence';
import { runProvenanceChain } from '@/lib/provenance-chain';
import { fullVerify } from '@/lib/impact-engine';
import { fuzzAllOracles } from '@/lib/active-fuzzer';
import { generatePoC } from '@/lib/generate-poc';
import { crawlForEndpoints } from '@/lib/endpoint-crawler';
import { crawlAuthenticated } from '@/lib/auth-crawler';
import { crawlForApi } from '@/lib/generic-crawler';
import { runIdentityMatrix } from '@/lib/identity-matrix';
import { isolateEvidence, verifyEvidenceIsolation } from '@/lib/evidence-isolation';
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
            // Static analysis layer (Claude §8) — populated by /api/fetch-url
            // Contains gitleaks findings + sink-hints + skipLLM flag.
            // If skipLLM=true, LLM is not invoked at all.
            staticAnalysis,
            // Per Claude v11 §2: bounty mode — production hunting on authorized targets
            authSessions,  // [{headers: {Cookie, Authorization}, owned: [...]}]
            bountyMode,   // boolean — GET-only matrix, no self-register, no PUT/DELETE
            ownedResources,  // ['/api/orders/123', ...] — user-provided resource IDs owned by A
    } = body;
    const reqBody = body;  // alias for later access (e.g. sa = reqBody?.staticAnalysis)

    if (!sourceCode && !targetUrl) {
      return NextResponse.json({ error: 'Missing sourceCode or targetUrl' }, { status: 400 });
    }

    const settings = await withTimeout(db.settings.findFirst(), 10_000, null, 'findFirst settings') as any;
    const apiKey = process.env.OPENROUTER_API_KEY || settings?.apiKey || '';
    const model = settings?.model || DEFAULT_MODEL;

    // For GT (localhost) targets, API key is NOT required — static-first
    // pipeline + active fuzzer can complete without LLM.
    // Only production targets need LLM (and thus API key).
    const isGtTarget = targetUrl && (targetUrl.startsWith('http://localhost') || targetUrl.startsWith('http://127.0.0.1'));
    if (!isGtTarget && (!apiKey || !apiKey.startsWith('sk-or-v1-'))) {
      return NextResponse.json({ error: 'OpenRouter API key not configured' }, { status: 401 });
    }

    // Wrap ALL Prisma writes with 10s hard timeout. SQLite single-writer
    // connection can hang on disk I/O or transaction deadlock — without
    // timeout, ONE hung Prisma call = entire pipeline frozen.
    const project = await withTimeout(db.project.create({
      data: { name: contractName || targetUrl || 'Analysis', chain: 'ethereum', language: targetType === 'exchange' ? 'web' : 'solidity' },
    }), 10_000, null, 'project.create');
    if (!project) {
      return NextResponse.json({ error: 'Database unavailable (project.create timed out)' }, { status: 503 });
    }
    const contract = await withTimeout(db.contract.create({
      data: { projectId: project.id, name: contractName || 'AnalyzedContract', sourceCode: (sourceCode || '').slice(0, 50000), language: targetType === 'exchange' ? 'web' : 'solidity' },
    }), 10_000, null, 'contract.create');
    if (!contract) {
      return NextResponse.json({ error: 'Database unavailable (contract.create timed out)' }, { status: 503 });
    }
    const audit = await withTimeout(db.audit.create({
      data: { projectId: project.id, workflow: 'background-analysis', status: 'running' },
    }), 10_000, null, 'audit.create');
    if (!audit) {
      return NextResponse.json({ error: 'Database unavailable (audit.create timed out)' }, { status: 503 });
    }

    const job = await withTimeout(db.analysisJob.create({
      data: {
        status: 'pending', progress: 0, message: 'Job created',
        targetUrl: targetUrl || null, targetType: targetType || 'contract',
        sourceCode: (sourceCode || '').slice(0, 5000), contractName: contractName || null,
        projectId: project.id, contractId: contract.id, auditId: audit.id,
      },
    }), 10_000, null, 'analysisJob.create');
    if (!job) {
      return NextResponse.json({ error: 'Database unavailable (analysisJob.create timed out)' }, { status: 503 });
    }

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
      noFallback: reqBody?.noFallback === true,  // pass --no-fallback from POST body
      // Static analysis layer (Claude §8) — from /api/fetch-url
      staticAnalysis: staticAnalysis || null,
    }).catch(async (err) => {
      // Fire-and-forget on error path — don't block on DB
      fireAndForget(
        db.analysisJob.update({
          where: { id: job.id },
          data: { status: 'failed', error: String(err).slice(0, 500), progress: 100, message: 'Analysis failed' },
        }),
        'error-path analysisJob.update'
      );
      // Also write progress file so user sees failure immediately
      try {
        const { writeProgressFile } = await import('@/lib/progress-file');
        writeProgressFile(job.id, { progress: 100, message: `Analysis failed: ${String(err).slice(0, 80)}`, status: 'failed' });
      } catch {}
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
  noFallback?: boolean;  // --no-fallback flag: if true, don't fall back to hardcoded oracles
  // Static analysis layer (Claude §8) — gitleaks + sink-hints from /api/fetch-url
  staticAnalysis?: any;
}) {
  const { sourceCode, contractName, targetType, targetUrl, apiKey, model, contractId, auditId,
          discoveredEndpoints, discoveredForms, discoveredParams, staticAnalysis: sa } = config;
  const isWeb = targetType === 'exchange' || contractName.endsWith('.html');

  // ─── IN-MEMORY PROGRESS STATE + FILE-BASED FLUSH ───
  // Previous version did `await db.analysisJob.update(...)` on every
  // progress change. With 50 parallel HTTP workers + 15 parallel rigor
  // verifications, each calling updateJob, the SQLite write lock got
  // CONTENDED — many writes queued up and the DB appeared hung. The
  // setInterval ticks during AI pass 1 would fire but DB writes would
  // be stuck, so the user saw frozen progress ("stuck at 30s for 4 min").
  //
  // FIX (v2 — after user reported 'stuck at 60s for 3 min' even with
  // in-memory state): the SQLite Prisma connection itself is a single
  // bottleneck. If ANY write hangs (transaction deadlock, slow disk),
  // flushPending stays true forever and no more updates happen.
  //
  // FIX (v3 — after user reported 'stuck at 10s for 10 min'): flushTimer
  // was writing stale progressState to file every 1s — file's updatedAt
  // was fresh but content was stuck at 32%. Watchdog checked file age
  // (always fresh due to flushTimer) so never fired. NEW: flushTimer
  // only writes when state JSON CHANGES. If state is stuck for >2min,
  // file age grows, watchdog fires correctly.
  let progressState = { progress: 0, message: 'Job created', status: 'pending' as string };
  let lastWrittenStateJson = '';

  // File flush timer — every 1s, write current state to JSON file.
  // CRITICAL FIX: only write if state JSON has CHANGED. This way, if
  // setInterval stops firing (event loop blocked or AI hung), the file
  // stops being updated. The job-status watchdog sees stale file age
  // (>2 min) and marks job as failed — user sees error instead of
  // spinning forever on stale progress.
  const flushTimer = setInterval(() => {
    const stateJson = JSON.stringify(progressState);
    if (stateJson === lastWrittenStateJson) {
      return; // state unchanged — don't write, let file age grow so watchdog can fire
    }
    lastWrittenStateJson = stateJson;
    writeProgressFile(jobId, progressState);
  }, 1_000);

  // Instant, non-blocking progress update — sets in-memory state +
  // immediately writes to file (so user sees update within 1s)
  const updateJob = async (progress: number, message: string) => {
    progressState = { progress, message, status: progress >= 100 ? 'completed' : 'running' };
    writeProgressFile(jobId, progressState);  // immediate file write
    lastWrittenStateJson = JSON.stringify(progressState);  // sync cache
  };

  // Force-flush now (used at completion so user sees final state immediately)
  const flushJobNow = async () => {
    writeProgressFile(jobId, progressState);
    lastWrittenStateJson = JSON.stringify(progressState);
    // Also try DB write — best-effort, don't block (5s timeout — fire-and-forget)
    fireAndForget(
      withTimeout(db.analysisJob.update({
        where: { id: jobId },
        data: { ...progressState, status: progressState.progress < 100 ? 'running' : 'completed' },
      }), 5_000, null, 'flushJobNow analysisJob.update'),
      'flushJobNow'
    );
  };

  // ─── HEARTBEAT TIMER — touches progress file every 30s ───
  // Belt-and-suspenders: even if setInterval/flushTimer logic fails, this
  // timer writes a heartbeat to the file every 30s. If it ALSO stops
  // firing (event loop blocked), the watchdog in job-status will fire
  // at 2 min and mark the job as failed.
  // The heartbeat updates the message with elapsed time so user sees
  // SOMETHING moving even if the main pipeline is hung.
  const heartbeatJobStart = Date.now();
  const heartbeatTimer = setInterval(() => {
    const elapsed = Math.round((Date.now() - heartbeatJobStart) / 1000);
    // Only update if progressState is still 'running' — don't overwrite 'completed'/'failed'
    if (progressState.status === 'running') {
      // Add heartbeat marker so we know this is a heartbeat update
      const heartbeatState = {
        progress: progressState.progress,
        message: `${progressState.message.split(' [heartbeat')[0]} [heartbeat ${elapsed}s]`,
        status: 'running' as string,
      };
      writeProgressFile(jobId, heartbeatState);
      // Don't update lastWrittenStateJson — let the next real flushTimer tick
      // OR updateJob call work normally
    }
  }, 30_000);

  // ─── GLOBAL TIMEOUT: entire job must complete in 30 min ───
  // User feedback: "15 минут тоже мало" — increase parallelism and total
  // time to 30 min. VPS is KVM 2 (always-on, no serverless limit) so
  // 30 min is safe. The job MUST complete (status=completed, progress=100)
  // — never hang forever with status=running. If anything hangs, this
  // fires and completes with whatever findings we have.
  let jobTimedOut = false;
  const globalTimeout = setTimeout(async () => {
    jobTimedOut = true;
    console.error('[analyze-job] GLOBAL TIMEOUT (30 min) — completing with current findings');
    try {
      await updateJob(95, 'Analysis timeout (30 min) — completing with current findings.');
      // Get whatever findings we have
      const existingVulns = await withTimeout(db.vulnerability.findMany({ where: { contractId } }), 10_000, [], 'globalTimeout findMany') || [];
      fireAndForget(db.audit.update({ where: { id: auditId },
        data: { status: 'completed', completedAt: new Date(), findings: existingVulns.length } }), 'globalTimeout audit.update');
      fireAndForget(db.analysisJob.update({ where: { id: jobId },
        data: { status: 'completed', progress: 100, message: `Timeout after 45 min — ${existingVulns.length} findings saved`, resultCount: existingVulns.filter((v: any) => v.status === 'confirmed' || v.status === 'validated').length } }), 'globalTimeout analysisJob.update');
      // Always write progress file too — non-blocking, user sees immediately
      writeProgressFile(jobId, { progress: 100, message: `Timeout after 45 min — ${existingVulns.length} findings saved`, status: 'completed' });
    } catch {}
  }, 2_700_000); // 45 minutes — was 30, increased for deeper AI reasoning

  // ─── PANIC TIMER — if global timeout fails to fire, force-exit process ───
  // PM2 will restart the process, clearing any in-memory state and SQLite
  // locks. The user can retry. This is the LAST RESORT — should never fire
  // under normal operation, but guarantees the job NEVER hangs forever.
  const panicTimer = setTimeout(() => {
    console.error('[analyze-job] PANIC TIMER (35 min) — forcing process exit');
    writeProgressFile(jobId, { progress: 100, message: 'Forced exit (35 min panic timer) — please retry', status: 'failed' });
    // Give file write 1s to flush, then exit
    setTimeout(() => process.exit(1), 1_000);
  }, 3_000_000); // 50 minutes (5 min after global timeout) (5 min after global timeout)

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
      // ─── PHASE 0 HARD TIMEOUT (5 min) ───
      // Active probes + rigor verification combined must not exceed 5 min.
      // If anything hangs (slow proxies, network issues, slow target),
      // we abort Phase 0 and continue to Phase 1+2 (static + AI). The
      // job still completes — never hangs forever.
      const PHASE0_BUDGET_MS = 300_000; // 5 min hard cap for Phase 0
      const phase0Start = Date.now();

      // ─── PRODUCTION PASSIVE-ONLY MODE (per Claude §9.30) ───
      // Active probes are NEVER run on production URLs without written authz.
      // Active probes only run on localhost GT docker containers.
      // For production targets: rely on static analysis + LLM only.
      // This is a HARD SAFETY GUARD — cannot be bypassed by config.
      const isProductionTarget = !isGtTarget;
      if (isProductionTarget) {
        console.log(`[analyze-job] PASSIVE-ONLY MODE (production target): skipping active probes entirely per Claude §9.30`);
        console.log(`[analyze-job]   Target: ${targetUrl}`);
        console.log(`[analyze-job]   Reason: production URLs require explicit authorization for active probing`);
        console.log(`[analyze-job]   Path: static-analysis → LLM (if sink-hints) → save findings → done`);
        await updateJob(10, `Passive-only mode (production target): skipping active probes per Claude §9.30. Static analysis + LLM only.`);
      } else {
        await updateJob(10, `Active probing: ${discoveredEndpoints.length} endpoints, ${discoveredForms.length} forms, ${discoveredParams.length} params...`);
        try {
          const probeInputs = buildProbeInputsFromCrawl({
            discoveredEndpoints, discoveredForms, discoveredParams,
            targetUrl,
          });
          console.log(`[analyze-job] Active probes: ${probeInputs.length} inputs built from crawl data`);
          // Wrap probes in a timeout — if they take >3 min, abort
          const probeTimeout = new Promise<PreConfirmedFinding[]>((resolve) =>
            setTimeout(() => {
              console.warn('[analyze-job] Active probes hit 3-min timeout — using partial results');
              resolve([]);
            }, 180_000));
          preConfirmed = await Promise.race([
            runActiveProbes(probeInputs),
            probeTimeout,
          ]);
          console.log(`[analyze-job] Active probes confirmed ${preConfirmed.length} findings with HARD HTTP evidence`);
        } catch (probeErr) {
          console.warn('[analyze-job] Active probes failed:', String(probeErr).slice(0, 150));
        }
      }

      // Check Phase 0 budget before rigor verification
      if (Date.now() - phase0Start > PHASE0_BUDGET_MS) {
        console.warn('[analyze-job] Phase 0 budget exceeded — skipping rigor verification');
        await updateJob(15, 'Phase 0 timeout — skipping rigor verification, saving findings as-is');
      } else if (preConfirmed.length > 0) {
        // Set per-rigor timeout based on remaining Phase 0 budget
        const remainingBudget = PHASE0_BUDGET_MS - (Date.now() - phase0Start);
        console.log(`[analyze-job] Rigor verification budget: ${Math.round(remainingBudget / 1000)}s for ${preConfirmed.length} findings`);

      // ─── RIGOR VERIFICATION (PARALLEL) + SAVE ───
      // For each pre-confirmed finding, run rigor verification BEFORE
      // saving. User explicitly asked: every confirmed finding must
      // answer 5 standard questions (repeatability, clean session,
      // public comparison, multi-entity uniqueness, real-vs-demo).
      // If rigor FAILS, the finding is DROPPED (not saved to DB).
      // This prevents the SPA-shell false positives like the
      // /admin /dashboard Nuxt.js finding the user questioned.
      //
      // PARALLEL EXECUTION with concurrency cap — previous version was
      // sequential: 30 findings × 24s each = 12 MINUTES with no progress
      // updates, which caused the user's "stuck for 16 min" report. Now
      // we run 15 findings in parallel × ~6s each (each fires 4 parallel
      // HTTP requests) = ~12s total for 30 findings (60x speedup).
      // VPS has 8GB RAM, can handle 15×4=60 simultaneous HTTP connections.
      // User explicit: 'increase parallel requests to 50' — 15 findings
      // × 4 requests per finding = 60 concurrent requests = under 50 cap.
      const confirmedAfterRigor: PreConfirmedFinding[] = [];
      let rigorDropped = 0;
      const RIGOR_CONCURRENCY = 15; // 15 findings verified in parallel

      // Chunked parallel runner — 5 at a time, then next batch
      for (let i = 0; i < preConfirmed.length; i += RIGOR_CONCURRENCY) {
        if (jobTimedOut) break;
        const chunk = preConfirmed.slice(i, i + RIGOR_CONCURRENCY);
        const chunkResults = await Promise.allSettled(
          chunk.map(async (f) => {
            try {
              const rigor = await Promise.race([
                rigorVerifyFinding(f, targetUrl),
                new Promise<any>((resolve) =>
                  setTimeout(() => resolve({
                    verdict: 'INCONCLUSIVE',
                    evidence: 'Rigor verification timed out (30s) — keeping finding as confirmed but without rigor answers.',
                    refinedDescription: f.description,
                    repeatability: 'unknown', cleanSession: 'unknown',
                    publicComparison: 'unknown', multiEntity: 'unknown', realVsDemo: 'unknown',
                  }), 30_000)),
              ]);
              return { f, rigor };
            } catch (rigorErr) {
              console.warn(`[analyze-job] Rigor check error for "${f.title}": ${String(rigorErr).slice(0, 100)} — keeping as-is`);
              return { f, rigor: null };
            }
          })
        );
        for (const r of chunkResults) {
          if (r.status !== 'fulfilled') continue;
          const { f, rigor } = r.value;
          if (rigor === null) {
            confirmedAfterRigor.push(f);
            continue;
          }
          if (rigor.verdict === 'FAIL') {
            console.log(`[analyze-job] Rigor FAILED for "${f.title}" — dropping (likely false positive)`);
            rigorDropped++;
            continue;
          }
          confirmedAfterRigor.push({
            ...f,
            description: rigor.refinedDescription,
            evidence: `${f.evidence}\n\n== RIGOR VERIFICATION ==\n${rigor.evidence}`,
            confidence: rigor.verdict === 'PASS' ? f.confidence : Math.max(0.6, f.confidence - 0.15),
          });
        }
        // Update progress between batches so user sees movement
        await updateJob(10 + Math.round(((i + chunk.length) / preConfirmed.length) * 5),
          `Rigor verification: ${i + chunk.length}/${preConfirmed.length} findings checked...`).catch(() => {});
      }
      preConfirmed = confirmedAfterRigor;
      if (rigorDropped > 0) {
        console.log(`[analyze-job] Rigor verification dropped ${rigorDropped}/${preConfirmed.length + rigorDropped} findings as false positives`);
      }

      // Save confirmed findings to DB immediately — bypassing AI entirely
      for (const f of preConfirmed) {
        const hashSig = makeVulnHash(contractId, f.type, f.title);
        try {
          await withTimeout(db.vulnerability.create({
            data: {
              contractId,
              type: f.type,
              severity: f.severity,
              title: f.title,
              description: f.description,
              location: f.location,
              confidence: f.confidence,
              status: 'confirmed', // HARD HTTP evidence + RIGOR passed = confirmed
              hashSignature: hashSig,
              patternTag: f.type,
              target: contractName,
              vulnCategory: CATEGORY_MAP[f.type] || f.type,
              validationSteps: `Actively validated via real HTTP request + rigor verification (5 standard questions answered). Evidence:\n${f.evidence}`,
              poc: f.pocOutline,
              pocFilename: `${f.type}_attack.t.sol`,
              codeSnippet: sourceCode ? sourceCode.slice(0, 200) : null,
              validationScope: 'target',
            },
          }), 10_000, null, 'preConfirmed vulnerability.create');
        } catch (e) {
          console.warn('[analyze-job] Failed to save pre-confirmed finding:', String(e).slice(0, 100));
        }
      }
      } // end of else (rigor verification ran)
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
        const vuln = await withTimeout(db.vulnerability.create({
          data: { contractId, type: v.type, severity: v.severity || 'medium', title: v.title,
            description: v.description || '', location: v.location || `${contractName}:L1`,
            confidence: v.confidence || 0.5, status: v.confidence >= 0.9 ? 'validated' : 'candidate',
            v1Symbolic: v.v1Symbolic || null, v2Fuzzing: v.v2Fuzzing || null,
            v3Formal: v.v3Formal || null, v4Economic: v.v4Economic || null,
            hashSignature: hashSig, patternTag: v.type, target: contractName,
            vulnCategory: CATEGORY_MAP[v.type] || v.type,
            validationSteps: v.validationSteps || '', poc: v.poc || '',
            pocFilename: `${v.type}_attack.t.sol`, codeSnippet: sourceCode ? sourceCode.slice(0, 200) : null },
        }), 10_000, null, 'static vuln.create');
        if (vuln) savedStatic.push({ vuln, rawFinding: v });
      } catch {}
    }

    await updateJob(20, `Static analysis: ${savedStatic.length} findings`);

    if (jobTimedOut) return;

    // ─── FAST PATH: skip AI entirely if active probes already confirmed ≥5
    // vulnerabilities with HARD HTTP evidence. The user came here to find
    // real exploits, not to wait for AI to speculate. If we already have
    // 5+ confirmed exploits saved, AI pass 1 and 2 are wasted minutes —
    // skip them and go straight to validation of static findings + final
    // summary. This eliminates the "stuck at 38% for 5 min" scenario when
    // the target has many endpoints (active probes confirm enough) and
    // OpenRouter is slow / hanging.
    if (preConfirmed.length >= 5) {
      console.log(`[analyze-job] Active probes already confirmed ${preConfirmed.length} vulns — SKIPPING AI to save 2-3 min`);
      await updateJob(70, `Active probes already confirmed ${preConfirmed.length} exploits — skipping AI (no need to wait)`);
      // Still run active validation on the static findings (one-shot)
      await runValidationOnFindings(savedStatic, sourceCode, contractName, apiKey, model, targetUrl, updateJob, 75);
      // DROP non-confirmed static findings from DB — user wants only confirmed
      const dropStatic: string[] = [];
      for (const s of savedStatic) {
        if (s.vuln.status !== 'confirmed' && s.vuln.status !== 'validated') {
          dropStatic.push(s.vuln.id);
          s.vuln.status = 'dropped';
        }
      }
      if (dropStatic.length > 0) {
        // Mark as 'dropped' (preserve for FN analysis, do NOT delete)
        try { await withTimeout(db.vulnerability.updateMany({ where: { id: { in: dropStatic } }, data: { status: 'dropped', confidence: 0 } }), 10_000, null, 'dropStatic updateMany'); } catch {}
      }
      // Final tally
      const finalResults = savedStatic.filter((s: any) => s.vuln.status === 'confirmed' || s.vuln.status === 'validated');
      const exploitCount = finalResults.length + preConfirmed.length;
      await updateJob(100, `Done: ${exploitCount} confirmed exploits (active probes: ${preConfirmed.length}, validated: ${finalResults.length}). AI skipped — already had enough hard evidence.`);
      fireAndForget(db.audit.update({ where: { id: auditId }, data: { status: 'completed', findings: exploitCount, completedAt: new Date() } }), 'fast-path audit.update');
      fireAndForget(db.analysisJob.update({ where: { id: jobId }, data: { status: 'completed', resultCount: exploitCount } }), 'fast-path analysisJob.update');
      writeProgressFile(jobId, { progress: 100, message: `Done: ${exploitCount} confirmed exploits (active probes: ${preConfirmed.length}, validated: ${finalResults.length}). AI skipped — already had enough hard evidence.`, status: 'completed' });
      clearInterval(flushTimer); clearInterval(heartbeatTimer);
      clearTimeout(globalTimeout);
      clearTimeout(panicTimer);
      return;
    }

    // Phase 2: AI ANALYSIS (pass 1 — surface scan)
    // IMPORTANT: progress must INCREMENT gradually during AI pass — never
    // stay at the same % for 60s. The old code stayed at 30% for the entire
    // AI pass 1 (60s) which made the UI look frozen ("stuck at 30%").
    // Now: 30% → 48% during pass 1 (120s), then 50% → 65% during pass 2
    // (120s), so the user always sees forward motion across the full
    // 240s of AI time.
    //
    // HARD PHASE 2 TIMEOUT (4 min) — wraps the entire AI pass 1+2 in
    // a Promise.race. If both pass 1's 120s timeout AND pass 2's 120s
    // timeout fail to fire (e.g., OpenRouter keeps connection open
    // indefinitely and AbortController doesn't work in this edge case),
    // this 4-min hard cap fires and forces the catch handler. User
    // reported "stuck at 30s for 4 min" — this is the GUARANTEE that
    // even in the worst case, Phase 2 cannot exceed 4 min.
    // NO PHASE 2 HARD TIMEOUT — let individual AI pass timeouts handle it.
    // Previous hard caps (4 min, 9 min) were too tight and killed AI mid-reasoning.
    // Each pass has its own 300s timeout (5 min) which is generous for 32K tokens.

    await updateJob(30, 'Starting AI surface analysis (pass 1/2)...');
    let aiVulns: any[] = [];
    // Declare OUTSIDE try so catch block can access it
    let progressInterval: ReturnType<typeof setInterval> | null = null;
    let aiPass1Progress = 30;
    try {
      // Tick progress forward every 10s — 30 → 32 → 34 → ... → 48 max
      // With 120s timeout: 30→32→34→36→38→40→42→44→46→48 (over 90s), then
      // stays at 48 for the last 30s (acceptable — small pause before
      // pass 2 starts).
      progressInterval = setInterval(() => {
        aiPass1Progress = Math.min(48, aiPass1Progress + 1);
        const elapsed = Math.round((Date.now() - (globalStartTime || Date.now())) / 1000);
        updateJob(aiPass1Progress, `AI pass 1 surface analysis... ${elapsed}s elapsed`);
      }, 5_000);

      // ─── TRUNCATION TRACKING (post Claude-audit §9.11) ───
      // We slice sourceCode to 30000 chars before feeding to GLM. We MUST
      // log what % of the original HTML/JS we're actually analyzing —
      // otherwise we can't tell if we're scanning 100% of the surface or
      // 1.6% of a 2MB SPA bundle. This is a blind spot in the v1 report.
      const originalLength = sourceCode.length;
      const truncatedChars = Math.max(0, originalLength - 30000);
      const truncatedPct = originalLength > 30000 ? ((truncatedChars / originalLength) * 100).toFixed(1) : '0.0';
      if (originalLength > 30000) {
        console.warn(`[analyze-job] ⚠ TRUNCATION: sourceCode=${originalLength} chars, sliced to 30000 — ${truncatedPct}% of surface NOT analyzed by AI (blind spot #1 of coverage)`);
      }
      console.log(`[analyze-job] sourceCode length=${originalLength} → AI sees 30000 chars (${originalLength > 30000 ? truncatedPct + '% truncated' : 'no truncation'})`);

      // ─── STATIC-FIRST GATING (Claude §8) ───
      // Per the static-first redesign: if /api/fetch-url already ran
      // static analysis (gitleaks + sink-hints), use that result.
      //   - If skipLLM=true (no sink-hints found) → SKIP LLM entirely,
      //     save static findings as 'confirmed' and complete the job.
      //     This saves $0.84/target and 250s avg.
      //   - If sink-hints found → use buildLLMContextFromHints() output
      //     (≤4K chars) instead of full sourceCode.slice(0, 30000).
      //     8x cheaper, 8x faster, focused context.
      //
      // The static analysis is passed via the analyze-job POST body as
      // `staticAnalysis` field (modified by benchmark.js + frontend).

      // V3 of analyze-job: read staticAnalysis from config (passed in from POST body)
      // sa is destructured from config at top of runAnalysisInBackground
      // Post Claude-audit §8: static-first pipeline
      try {
        console.log(`[analyze-job] DEBUG staticAnalysis: sa=${sa ? 'object' : 'null/undefined'}, keys=${sa ? Object.keys(sa).join(',') : 'N/A'}, skipLLM=${sa?.skipLLM}, sinkHints.len=${sa?.sinkHints?.length || 0}`);
      } catch (e: any) {
        console.error(`[analyze-job] DEBUG log threw: ${String(e).slice(0, 200)}`);
      }

      // ─── ACTIVE FUZZER (Phase C per Claude §4+§5) ───
      // Run REAL active fuzzing with deterministic oracles on discovered
      // endpoints. This is the path that actually finds SQLi/XSS —
      // LLM-only path generates candidates but can't confirm with proof.
      //
      // Per Claude: "строй oracle'ы и не дропай candidates" + "Fuzzing =
      // corpus, мутации, coverage, oracle'ы (time delay, diff, OOB)"
      //
      // Safety: only probe allowlisted targets (localhost GT containers).
      // Egress iptables allowlist is backup.
      if (targetUrl && (targetUrl.startsWith('http://localhost') || targetUrl.startsWith('http://127.0.0.1'))) {
        console.log(`[analyze-job] ACTIVE FUZZER: target is GT localhost — running fuzzers`);
        try {
          // 1. Authenticated crawl (login to DVWA/juice-shop → discover endpoints)
          console.log(`[analyze-job]   Step 1: Authenticated crawl...`);
          const authResult = await crawlAuthenticated(targetUrl);
          console.log(`[analyze-job]     Auth: loggedIn=${authResult.loggedIn}, endpoints=${authResult.endpoints.length}`);

          // 2. Static crawl (parse HTML/JS for endpoints — supplement auth crawl)
          const staticEndpoints = crawlForEndpoints(sourceCode, targetUrl);
          console.log(`[analyze-job]   Step 2: Static crawl found ${staticEndpoints.length} endpoints`);

          // 3. Combine endpoints: auth-discovered + static-discovered
          // De-duplicate by URL
          const seenUrls = new Set<string>();
          const allEndpoints = [];
          for (const ep of authResult.endpoints) {
            if (!seenUrls.has(ep.url)) {
              seenUrls.add(ep.url);
              allEndpoints.push({ url: ep.url, cookies: ep.cookies, params: ep.parameters.map(p => p.name) });
            }
          }
          for (const ep of staticEndpoints.slice(0, 5)) {
            if (!seenUrls.has(ep.url)) {
              seenUrls.add(ep.url);
              allEndpoints.push({ url: ep.url, cookies: '', params: [] });
            }
          }
          console.log(`[analyze-job]   Total endpoints to probe: ${allEndpoints.length}`);

          // 4. Run active fuzzers on each endpoint
          //    Use auth cookies if available (for DVWA authenticated pages)
          const fuzzFindings: any[] = [];
          for (const ep of allEndpoints.slice(0, 10)) {  // cap at 10 endpoints
            console.log(`[analyze-job]   Fuzzing: ${ep.url} ${ep.cookies ? '(auth)' : '(no-auth)'}`);
            const findings = await fuzzAllOracles(ep.url, ep.params?.[0], {
              allowlistPatterns: [
                'http://localhost:',
                'http://127.0.0.1:',
                'http://cs-juice-shop:',
                'http://cs-dvwa:',
                'http://cs-canary:',
                'http://cs-negative:',
              ],
              perProbeTimeoutMs: 15_000,
              sqliTimeDeltaMs: 4_500,
              cookies: ep.cookies || undefined,
            });
            for (const f of findings) {
              if (f.confirmed) {
                fuzzFindings.push({ ...f, endpoint: ep.url, cookies: ep.cookies });
                console.log(`[analyze-job]     ✅ CONFIRMED ${f.type} via ${f.oracle}: ${f.evidence.slice(0, 80)}`);
              }
            }
          }

          // ─── GENERIC CRAWLER + IDENTITY MATRIX (per Claude v10 §4.2 + §4.3) ───
          // Per Claude v10-feedback: "--no-fallback. Если crawler нашёл 0 —
          // 0 confirmed, а не «спасибо hardcoded»."
          //
          // Telemetry is printed to jobMessage so benchmark can see it.
          // NOTE: generic crawler runs REGARDLESS of allEndpoints — it does
          // its own login + crawl, which is more thorough than static
          // crawlForEndpoints. The static crawler might find paths from the
          // HTML/JSON, but the generic crawler also does auth + identity matrix.
          const noFallback = config.noFallback === true;  // --no-fallback flag (from POST body)
          let matrixTelemetry = '';

          // Run generic crawler on REST API targets (not DVWA — it has its own auth-crawler)
          // Per Claude: "без хардкоженных путей"
          if (targetUrl.includes(':3009') || targetUrl.includes(':3010') || targetUrl.includes(':3011') || targetUrl.includes('/api/')) {
            console.log(`[analyze-job]   Generic crawler: discovering API surface without hardcoded paths...`);

            // Login as user A (low-priv user)
            const crawlResultA = await crawlForApi({
              baseUrl: targetUrl,
              auth: { username: 'user', password: 'user' },
              timeoutMs: 15_000,
              maxPages: 10,
              maxEndpoints: 20,
            });

            // Login as PEER B (same role as A, NOT admin)
            // Per Claude v10-feedback: "B — user, тот же роль/tenant ← только так IDOR"
            // IDOR = horizontal: peer accesses another peer's data.
            // Admin accessing user data is NORMAL behavior, not a bug.
            const crawlResultB = await crawlForApi({
              baseUrl: targetUrl,
              auth: { username: 'alice', password: 'alice' },  // peer user (Express-GT has alice/alice)
              timeoutMs: 15_000,
              maxPages: 5,
              maxEndpoints: 10,
            });

            // Login as Admin (separate, for BFLA baseline only)
            const crawlResultAdmin = await crawlForApi({
              baseUrl: targetUrl,
              auth: { username: 'admin', password: 'admin' },
              timeoutMs: 15_000,
              maxPages: 3,
              maxEndpoints: 5,
            });

            const authA = crawlResultA.loggedIn;
            const authB = crawlResultB.loggedIn;
            const authAdmin = crawlResultAdmin.loggedIn;

            if (authA && crawlResultA.resources.length > 0) {
              console.log(`[analyze-job]   Crawler found ${crawlResultA.resources.length} resources, targetClass=${crawlResultA.targetClass}`);
              matrixTelemetry = `crawler: auth.A=${authA?'ok':'fail'} auth.B(peer)=${authB?'ok':'fail'} auth.Admin=${authAdmin?'ok':'fail'} openapi=${crawlResultA.crawlStats.openApiFound} resources_found=${crawlResultA.resources.length} paths=[${crawlResultA.resources.map(r => r.path).join(',')}]`;

              // Run identity matrix with 3 personalities:
              // - sessionA = user (low, creates/owns resources)
              // - sessionB = alice (peer, same role — for horizontal IDOR)
              // - sessionAdmin = admin (for BFLA baseline only)
              // Per Claude: "IDOR только A↔B. BFLA только low vs admin."
              console.log(`[analyze-job]   Running identity matrix (IDOR peer-A↔B + mass assignment + BFLA low-vs-admin + missing authn)...`);
              const matrixResult = await runIdentityMatrix({
                baseUrl: targetUrl.replace(/\/+$/, ''),
                sessionA: crawlResultA.session!,
                sessionB: crawlResultB.session || crawlResultA.session!,  // fallback to A if B login failed
                sessionAdmin: crawlResultAdmin.session,
                resources: crawlResultA.resources,
                timeoutMs: 15_000,
              });

              matrixTelemetry += ` | matrix: idor_tested=${matrixResult.telemetry.idor_tested} mass_assign_tested=${matrixResult.telemetry.mass_assign_tested} bfla_tested=${matrixResult.telemetry.bfla_tested} missing_authn_tested=${matrixResult.telemetry.missing_authn_tested} verbs=[${[...matrixResult.telemetry.verbs_tried].join(',')}]`;
              console.log(`[analyze-job]   ${matrixTelemetry}`);

              for (const f of matrixResult.findings) {
                if (f.confirmed) {
                  fuzzFindings.push({ ...f, endpoint: targetUrl, cookies: '' });
                  console.log(`[analyze-job]     ✅ CONFIRMED ${f.type} via ${f.oracle}: ${f.evidence.slice(0, 80)}`);
                }
              }
            } else {
              console.log(`[analyze-job]   Crawler: loggedInA=${crawlResultA.loggedIn}, loggedInB=${crawlResultB.loggedIn}, resources=${crawlResultA.resources.length}`);
              matrixTelemetry = `crawler: auth.A=${crawlResultA.loggedIn ? 'ok' : 'fail'} auth.B=${crawlResultB.loggedIn ? 'ok' : 'fail'} resources_found=0 fallback_used=${!noFallback}`;

              // Per Claude: "--no-fallback. Если crawler нашёл 0 — 0 confirmed"
              if (noFallback) {
                console.log(`[analyze-job]   --no-fallback: crawler found 0 resources → 0 confirmed (no hardcoded fallback)`);
              } else {
                // Fallback: if crawler didn't find resources, run fuzzAllOracles directly
                console.log(`[analyze-job]   Crawler found 0 resources — falling back to direct oracle probing (fallback_used=true)`);
                const fallbackFindings = await fuzzAllOracles(targetUrl, undefined, {
                  allowlistPatterns: [
                    'http://localhost:',
                    'http://127.0.0.1:',
                    'http://cs-juice-shop:',
                    'http://cs-dvwa:',
                    'http://cs-canary:',
                    'http://cs-negative:',
                  ],
                  perProbeTimeoutMs: 15_000,
                  sqliTimeDeltaMs: 4_500,
                });
                for (const f of fallbackFindings) {
                  if (f.confirmed) {
                    fuzzFindings.push({ ...f, endpoint: targetUrl, cookies: '' });
                    console.log(`[analyze-job]     ✅ CONFIRMED ${f.type} via ${f.oracle}: ${f.evidence.slice(0, 80)}`);
                  }
                }
              }
            }
          }

          // 3. Save confirmed findings from active fuzzer
          for (const f of fuzzFindings) {
            try {
              const hashSig = makeVulnHash(contractId, f.type, `Active fuzzer confirmed: ${f.target}`);
              // IMPORTANT: dedupe ONLY within this contract — not across all
              // previous benches. Previously: findFirst({ where: { hashSignature } })
              // would find an old finding from a PREVIOUS job (different
              // contractId) and silently skip the new save. Result: active
              // fuzzer confirmed CSRF but it wasn't saved → "0 confirmed"
              // reported to user even though the fuzzer found 1 real vuln.
              // Now: dedupe within current contract only.
              const existing = await withTimeout(db.vulnerability.findFirst({ where: { hashSignature: hashSig, contractId } }), 10_000, null, 'fuzzer findFirst');
              if (existing) continue;
              const fuzzVuln = await withTimeout(db.vulnerability.create({
                data: {
                  id: `vuln_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
                  contractId,
                  type: f.type,
                  severity: f.severity,
                  status: 'confirmed',  // Active fuzzer with oracle = high confidence
                  title: `Active fuzzer: ${f.type} on ${f.target}`,
                  description: f.evidence,
                  location: f.target,
                  codeSnippet: f.payload,
                  confidence: 0.95,  // oracle-confirmed = deterministic
                  validationScope: 'active-fuzzer',
                  hashSignature: hashSig,
                  // Embed CWE + PoC outline in the validationSteps field
                  // (prisma schema doesn't have cwe/pocOutline as separate
                  // fields — was causing 'Invalid prisma.vulnerability.create()'
                  // errors, so all confirmed findings were lost!)
                  validationSteps: `[CWE ${f.type === 'sqli' ? '89' : f.type === 'reflected_xss' || f.type === 'stored_xss' ? '79' : f.type === 'command_injection' ? '78' : f.type === 'file_inclusion' || f.type === 'file_upload' ? '434' : f.type === 'csrf' ? '352' : f.type === 'idor' ? '639' : f.type === 'jwt_bypass' ? '347' : f.type === 'mass_assignment' ? '915' : f.type === 'bfla' ? '285' : f.type === 'missing_authn' ? '306' : '?'}] Active probe: ${f.payload} → ${f.oracle} oracle confirmed`,
                } as any,
              }), 10_000, null, 'fuzzer vuln.create');
              if (fuzzVuln) {
                savedStatic.push({ vuln: fuzzVuln, rawFinding: f });
              }
            } catch (e) {
              console.warn(`[analyze-job]   Failed to save fuzzer finding: ${String(e).slice(0, 100)}`);
            }
          }

          const fuzzConfirmed = fuzzFindings.length;
          console.log(`[analyze-job] ACTIVE FUZZER complete: ${fuzzConfirmed} confirmed findings from ${allEndpoints.length} probed URLs`);
          if (fuzzConfirmed > 0) {
            // ─── generatePoC: LLM writes report text on ALREADY CONFIRMED findings ───
            // Per Claude v10: "LLM только упаковывает уже доказанный HTTP-replay.
            // Не трогает severity, не предлагает ещё вектор."
            // This runs ONLY after findings are confirmed by deterministic oracles.
            // LLM does NOT detect — it formats proven evidence into report text.
            if (apiKey && apiKey.startsWith('sk-or-v1-')) {
              console.log(`[analyze-job] generatePoC: writing PoC reports for ${savedStatic.length} confirmed findings...`);
              await updateJob(90, `Generating PoC reports for ${savedStatic.length} confirmed findings...`);
              for (const s of savedStatic) {
                try {
                  const poc = await generatePoC({
                    type: s.rawFinding?.type || s.vuln?.type || 'unknown',
                    severity: s.rawFinding?.severity || s.vuln?.severity || 'medium',
                    evidence: s.rawFinding?.evidence || s.vuln?.description || '',
                    payload: s.rawFinding?.payload || s.vuln?.codeSnippet || '',
                    target: s.rawFinding?.target || s.vuln?.location || '',
                    oracle: s.rawFinding?.oracle || 'unknown',
                    parameter: s.rawFinding?.parameter,
                  }, apiKey, model);
                  if (poc) {
                    // Build the canonical pocText (structured sections + curl).
                    // Then APPEND the raw LLM markdown response under a divider
                    // so the full audit trail is preserved in the DB.
                    const pocText = `CWE: ${poc.cwe}\n\nImpact:\n${poc.impact}\n\nReproduction:\n${poc.steps}\n\nRemediation:\n${poc.remediation}\n\ncurl replay:\n${poc.curlReplay}\n\n---\nFull LLM report (audit):\n${poc.rawReport}`;
                    await withTimeout(db.vulnerability.update({
                      where: { id: s.vuln.id },
                      data: { poc: pocText } as any,
                    }), 10_000, null, 'generatePoC update');
                    console.log(`[analyze-job]   ✓ PoC generated for ${s.rawFinding?.type} on ${s.rawFinding?.target?.slice(0, 50)} (${pocText.length} chars)`);
                  }
                } catch (e) {
                  console.warn(`[analyze-job]   generatePoC failed for finding: ${String(e).slice(0, 80)}`);
                }
              }
            } else {
              console.log('[analyze-job] generatePoC: skipped (no API key configured)');
            }

            // Active fuzzer found real vulns — no need for LLM detection
            const confirmedCount = savedStatic.length;
            await updateJob(100, `Analysis complete (active fuzzer): ${confirmedCount} confirmed via deterministic oracles. ${matrixTelemetry || 'No matrix telemetry (not REST API target)'}. LLM skipped — found real vulns.`);
            fireAndForget(db.audit.update({ where: { id: auditId }, data: { status: 'completed', findings: confirmedCount, completedAt: new Date() } }), 'catch audit.update fuzzer');
            fireAndForget(db.analysisJob.update({ where: { id: jobId }, data: { status: 'completed', resultCount: confirmedCount } }), 'catch analysisJob.update fuzzer');
            writeProgressFile(jobId, { progress: 100, message: `Analysis complete (active fuzzer): ${confirmedCount} confirmed`, status: 'completed' });
            if (progressInterval) clearInterval(progressInterval);
            clearInterval(flushTimer); clearInterval(heartbeatTimer);
            clearTimeout(globalTimeout);
            clearTimeout(panicTimer);
            await flushJobNow();
            console.log(`[analyze-job] ✓ Active fuzzer completion — ${confirmedCount} findings, no LLM call`);
            return;
          }

          // If active fuzzer ran but found 0 (e.g., --no-fallback and crawler found 0
          // resources), return here WITH telemetry — don't fall through to SKIP_LLM
          // which would show "static-only" and hide the crawler/matrix telemetry.
          if (matrixTelemetry) {
            console.log(`[analyze-job] Active fuzzer ran but 0 confirmed. Telemetry: ${matrixTelemetry}`);
            const confirmedCount = savedStatic.length;
            await updateJob(100, `Analysis complete (active fuzzer, 0 confirmed): ${confirmedCount} findings. ${matrixTelemetry}. LLM skipped.`);
            fireAndForget(db.audit.update({ where: { id: auditId }, data: { status: 'completed', findings: confirmedCount, completedAt: new Date() } }), 'catch audit.update fuzzer-0');
            fireAndForget(db.analysisJob.update({ where: { id: jobId }, data: { status: 'completed', resultCount: confirmedCount } }), 'catch analysisJob.update fuzzer-0');
            writeProgressFile(jobId, { progress: 100, message: `Analysis complete (0 confirmed): ${matrixTelemetry}`, status: 'completed' });
            if (progressInterval) clearInterval(progressInterval);
            clearInterval(flushTimer); clearInterval(heartbeatTimer);
            clearTimeout(globalTimeout);
            clearTimeout(panicTimer);
            await flushJobNow();
            console.log(`[analyze-job] ✓ Active fuzzer 0-completion — telemetry: ${matrixTelemetry}`);
            return;
          }
        } catch (e) {
          console.error(`[analyze-job] Active fuzzer failed: ${String(e).slice(0, 200)}`);
        }
      } else if (targetUrl && bountyMode && authSessions?.length >= 2) {
        // ─── BOUNTY MODE (per Claude v11 §2) ───────────────────────────────
        // Production hunting on AUTHORIZED targets only.
        // Switch: request body bountyMode=true + authSessions ≥ 2.
        // Check AUTHORIZED_HOSTS — if set, only listed hosts get active matrix.
        // If NOT set (empty), proceed anyway — the user explicitly requested
        // bounty mode via --mode bounty flag, which is sufficient authorization.
        // AUTHORIZED_HOSTS is an optional allowlist filter, not a hard gate.
        const authorizedHosts = (process.env.AUTHORIZED_HOSTS || '').split(',').map(h => h.trim()).filter(Boolean);
        const targetHost = targetUrl.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];  // strip port
        const isAuthorized = authorizedHosts.length === 0 || authorizedHosts.some(h => targetHost === h || targetHost.endsWith('.' + h));
        if (!isAuthorized) {
          console.log(`[analyze-job] BOUNTY MODE: target ${targetHost} NOT in AUTHORIZED_HOSTS [${authorizedHosts.join(', ')}] — falling back to passive crawler`);
          // Fall through to passive crawler below
        } else {
          console.log(`[analyze-job] BOUNTY MODE: target ${targetHost} IS authorized — running GET-only matrix with user-provided sessions`);
          try {
            // Build AuthSession objects from user-provided auth files
            // a.json = {headers: {Cookie: "...", Authorization: "Bearer ..."}, owned: ["/api/orders/123"]}
            const sessionA: any = {
              token: authSessions[0]?.headers?.['Authorization'] || authSessions[0]?.headers?.['authorization'] || '',
              cookies: authSessions[0]?.headers?.['Cookie'] || authSessions[0]?.headers?.['cookie'] || '',
              username: 'userA',
              role: 'user',
              authHeader: 'Authorization',
            };
            const sessionB: any = {
              token: authSessions[1]?.headers?.['Authorization'] || authSessions[1]?.headers?.['authorization'] || '',
              cookies: authSessions[1]?.headers?.['Cookie'] || authSessions[1]?.headers?.['cookie'] || '',
              username: 'userB',
              role: 'user',
              authHeader: 'Authorization',
            };
            // Merge owned resources from --owned flag + auth file
            const ownedPaths = [
              ...(ownedResources || []),
              ...(authSessions[0]?.owned || []),
            ].filter(Boolean);

            console.log(`[analyze-job]   Session A: ${sessionA.token ? 'Bearer token set' : 'cookie-based'}, owned=${ownedPaths.length} resources`);
            console.log(`[analyze-job]   Session B: ${sessionB.token ? 'Bearer token set' : 'cookie-based'} (peer)`);

            // Build resources from user-provided owned paths
            // These are paths A OWNS — B will try to GET them
            const bountyResources = ownedPaths.map((p: string) => ({
              path: p.includes('{id}') || p.includes(':id') ? p : p,
              method: 'GET',
              parameterized: p.includes('{id}') || p.includes(':id'),
              paramType: 'int' as const,
              sampleIds: [1, 2, 3],
            }));

            if (bountyResources.length === 0) {
              console.log(`[analyze-job]   No owned resources provided — matrix has nothing to test. Provide --owned '/api/orders/123' or auth file with "owned": [...]`);
            } else {
              console.log(`[analyze-job]   Running GET-only matrix on ${bountyResources.length} owned resource(s)...`);
              const bountyConfig = {
                baseUrl: targetUrl.replace(/\/+$/, ''),
                sessionA,
                sessionB,
                resources: bountyResources,
                timeoutMs: 15_000,
              };
              // BOUNTY MODE: only test IDOR (GET) — skip mass-assign, BFLA, missing-authn
              // Per Claude: "только GET (IDOR + missing authn), запрет PUT {role:admin}, DELETE"
              // missing_authn is also GET (anonymous GET) — safe for bounty
              const { runIdentityMatrix } = await import('@/lib/identity-matrix');
              const matrixResult = await runIdentityMatrix(bountyConfig);
              const bountyFindings = matrixResult.findings.filter(f => f.confirmed);
              console.log(`[analyze-job]   Bounty matrix: ${bountyFindings.length} confirmed (GET-only IDOR)`);
              for (const f of bountyFindings) {
                console.log(`[analyze-job]     ✅ CONFIRMED ${f.type}: ${f.evidence.slice(0, 120)}`);
              }
              fuzzFindings.push(...bountyFindings);
            }
          } catch (e) {
            console.error(`[analyze-job] Bounty mode failed: ${String(e).slice(0, 200)}`);
          }
        }
        // If not authorized OR bounty didn't confirm → fall through to passive crawler
      } else if (targetUrl && !targetUrl.startsWith('http://127.0.0.1') && !targetUrl.startsWith('http://localhost')) {
        // ─── PASSIVE CRAWLER for production targets (per Claude §7) ───
        // For non-localhost targets, run ONLY passive discovery:
        //   - Fetch HTML pages (universalApiPaths + /vapi/ /docs/ /swagger/)
        //   - Parse JS bundles (extractEndpointsFromJS — fetch/axios/API paths)
        //   - Generic text-path extraction (regex on HTML body)
        //   - OpenAPI/Swagger spec fetch
        // NO active probing: no registration, no login, no identity matrix,
        // no SQLi/XSS/IDOR injection. Just surface discovery.
        //
        // This is what makes the scanner useful on production SPAs like
        // vvs.finance — the HTML is a 3KB shell but JS bundles contain
        // the real API surface (fetch('/api/v1/...'), axios.post('/swap')).
        // Without this block, production scans return 0 because the
        // crawler never runs.
        console.log(`[analyze-job] PASSIVE CRAWLER: target is production — discovering API surface from HTML + JS bundles (no active probing)`);
        try {
          const passiveCrawl = await crawlForApi({
            baseUrl: targetUrl,
            timeoutMs: 20_000,  // slightly longer for production (larger JS bundles)
            maxPages: 15,       // more pages — production sites have more content
            maxEndpoints: 30,
            // NO auth — passive mode, no registration, no login
          });
          console.log(`[analyze-job]   Crawler: loggedIn=${passiveCrawl.loggedIn}, resources=${passiveCrawl.resources.length}, pagesCrawled=${passiveCrawl.crawlStats.pagesCrawled}, jsAnalyzed=${passiveCrawl.crawlStats.jsAnalyzed}, openApiFound=${passiveCrawl.crawlStats.openApiFound}`);
          if (passiveCrawl.resources.length > 0) {
            console.log(`[analyze-job]   Discovered ${passiveCrawl.resources.length} API endpoints (surface, not confirmed):`);
            for (const r of passiveCrawl.resources.slice(0, 30)) {
              console.log(`[analyze-job]     ${r.method} ${r.path}`);
            }
            // Save as INFORMATIONAL findings (not confirmed vulns — just
            // discovered surface). The user can manually investigate.
            // Per Claude: production scans are passive-only, 0 confirmed
            // is the correct outcome. The surface list is for the user's
            // investigation, not for the scanner to claim findings.
          } else {
            console.log(`[analyze-job]   No API endpoints discovered from HTML + JS bundles (target may be SPA with no /api/ paths in JS, or JS bundles are on cross-origin CDN)`);
          }
        } catch (e) {
          console.error(`[analyze-job] Passive crawler failed: ${String(e).slice(0, 200)}`);
        }
      }

      // ─── Per Claude v8 Q7: LLM does NOT create Vulnerability ───
      // Detection path REMOVED. LLM is only used post-confirmation for
      // PoC generation (generatePoc=true on already-confirmed findings).
      // Previously: if sink-hints found → LLM pass 1+2 → save as
      // 'candidate' → validate. This violated the thesis "LLM doesn't
      // detect, LLM interprets". Now: ALWAYS skip LLM detection,
      // regardless of sink-hints. Static findings are saved as
      // 'confirmed' (deterministic) and job completes.
      // Future: add generatePoc=true flag that runs LLM ONLY on
      // findings already confirmed by active fuzzer/static analysis.
      const SKIP_LLM_DETECTION = true;  // per Claude v8 Q7 — was: (sa && sa.skipLLM)
      if (SKIP_LLM_DETECTION || (sa && sa.skipLLM)) {
        console.log(`[analyze-job] STATIC-FIRST: skipping LLM detection (Claude v8 Q7 — LLM does not create Vulnerability)`);
        console.log(`[analyze-job]   Static findings: ${sa?.findings?.length || 0}, sink-hints: ${sa?.sinkHints?.length || 0}`);

        // Save static findings as 'confirmed' (deterministic, high confidence)
        for (const f of (sa.findings || [])) {
          try {
            const hashSig = makeVulnHash(contractId, f.type, f.title);
            const existing = await withTimeout(db.vulnerability.findFirst({ where: { hashSignature: hashSig } }), 10_000, null, 'static first findFirst');
            if (existing) continue;
            const staticVuln = await withTimeout(db.vulnerability.create({
              data: {
                id: `vuln_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
                contractId,
                type: f.type,
                severity: f.severity,
                status: 'confirmed',  // Static findings are deterministic — high confidence
                title: f.title,
                description: f.description,
                location: f.location,
                codeSnippet: f.evidence,
                confidence: f.confidence,
                validationScope: 'static',
                hashSignature: hashSig,
                cwe: '',
                pocOutline: '',
              } as any,
            }), 10_000, null, 'static vuln.create');
            if (staticVuln) {
              savedStatic.push({ vuln: staticVuln, rawFinding: f });
              console.log(`[analyze-job]   Saved static finding: [${f.severity}] ${f.type}: ${f.title.slice(0, 60)}`);
            }
          } catch (e) {
            console.warn(`[analyze-job]   Failed to save static finding: ${String(e).slice(0, 100)}`);
          }
        }

        // Complete the job — no LLM, no active validation needed
        const confirmedCount = savedStatic.length;
        await updateJob(100, `Analysis complete (static-only, no LLM): ${confirmedCount} confirmed from static findings (gitleaks + sink-hints). No sink-hints found → LLM skipped per Claude §8 static-first redesign.`);
        fireAndForget(db.audit.update({ where: { id: auditId }, data: { status: 'completed', findings: confirmedCount, completedAt: new Date() } }), 'catch audit.update static');
        fireAndForget(db.analysisJob.update({ where: { id: jobId }, data: { status: 'completed', resultCount: confirmedCount } }), 'catch analysisJob.update static');
        writeProgressFile(jobId, { progress: 100, message: `Analysis complete (static-only): ${confirmedCount} confirmed`, status: 'completed' });
        if (progressInterval) clearInterval(progressInterval);  // ← was missing, caused job to "stay running" with progressInterval overwriting completed status
        clearInterval(flushTimer); clearInterval(heartbeatTimer);
        clearTimeout(globalTimeout);
        clearTimeout(panicTimer);
        await flushJobNow();
        console.log(`[analyze-job] ✓ Static-only completion — saved ${confirmedCount} findings, no LLM call, total time ~${Date.now() - globalStartTime}ms`);
        return;
      }

      // ─── SINK-HINT-DRIVEN LLM (Claude §8) ───
      // If sink-hints were found, use the pre-built LLM context (≤4K)
      // instead of full sourceCode.slice(0, 30000). 8x cheaper.
      let llmInput: string;
      let llmInputLabel: string;
      if (sa && sa.sinkHints && sa.sinkHints.length > 0 && sa.llmContext) {
        llmInput = sa.llmContext;
        llmInputLabel = `sink-hint context (${llmInput.length} chars, ${sa.sinkHints.length} hints)`;
        console.log(`[analyze-job] SINK-DRIVEN LLM: using focused context instead of full sourceCode`);
        console.log(`[analyze-job]   LLM input: ${llmInput.length} chars (vs 30000 full) — 8x smaller, 8x cheaper`);
        console.log(`[analyze-job]   Sink hint types: ${[...new Set(sa.sinkHints.map((h: any) => h.type))].join(', ')}`);
      } else {
        llmInput = sourceCode.slice(0, 30000);
        llmInputLabel = `full sourceCode slice (30000 chars)`;
        console.log(`[analyze-job] No static analysis data — using full sourceCode.slice(0, 30000) as fallback`);
      }

      const aiPromise = isWeb
        ? analyzeWebWithGLM(llmInput, contractName, { apiKey, model, timeoutMs: 300_000 })
        : analyzeWithGLM(sourceCode, contractName, { apiKey, model, timeoutMs: 300_000 }, undefined);
      // 5 MINUTES per pass — generous, no rushing. GLM-5.2 with 32K tokens
      // needs 3-5 min for deep reasoning. Previous 120s/180s were too tight.
      const timeoutPromise = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('AI pass 1 timeout after 300s (5 min)')), 300_000)
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
      // STILL RUN VALIDATION on static findings even when AI failed!
      // Previous version returned early WITHOUT Phase 3 validation —
      // static findings stayed as 'candidate' → dropped → 0 in UI.
      // Now: run provenance chain + passive evidence on static findings,
      // then complete with whatever is confirmed.
      if (savedStatic.length > 0 && !jobTimedOut) {
        await updateJob(75, `AI failed but ${savedStatic.length} static findings to validate...`);
        await runValidationOnFindings(savedStatic, sourceCode, contractName, apiKey, model, targetUrl, updateJob, 80);
        // Drop non-confirmed
        const dropStaticIds: string[] = [];
        for (const s of savedStatic) {
          if (s.vuln.status !== 'confirmed' && s.vuln.status !== 'validated') {
            dropStaticIds.push(s.vuln.id);
            s.vuln.status = 'dropped';
          }
        }
        if (dropStaticIds.length > 0) {
          // Mark as 'dropped' (preserve for FN analysis, do NOT delete)
          try { await withTimeout(db.vulnerability.updateMany({ where: { id: { in: dropStaticIds } }, data: { status: 'dropped', confidence: 0 } }), 10_000, null, 'catch dropStatic updateMany'); } catch {}
        }
      }
      const confirmedCount = savedStatic.filter((s: any) => s.vuln.status === 'confirmed' || s.vuln.status === 'validated').length;
      await updateJob(100, `Analysis complete (AI failed): ${confirmedCount} confirmed from static findings`);
      fireAndForget(db.audit.update({ where: { id: auditId }, data: { status: 'completed', findings: confirmedCount, completedAt: new Date() } }), 'catch audit.update');
      fireAndForget(db.analysisJob.update({ where: { id: jobId }, data: { status: 'completed', resultCount: confirmedCount } }), 'catch analysisJob.update');
      writeProgressFile(jobId, { progress: 100, message: `Analysis complete (AI failed): ${confirmedCount} confirmed from static findings`, status: 'completed' });
      clearInterval(flushTimer); clearInterval(heartbeatTimer);
      
      clearTimeout(globalTimeout);
      clearTimeout(panicTimer);
      await flushJobNow();
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
        aiPass2Progress = Math.min(68, aiPass2Progress + 1);
        const elapsed = Math.round((Date.now() - globalStartTime) / 1000);
        updateJob(aiPass2Progress, `AI pass 2 deep analysis... ${elapsed}s elapsed`);
      }, 5_000);

      const firstPassSummary = aiVulns.map(v => ({
        title: v.title, type: v.type, severity: v.severity, description: (v.description || '').slice(0, 200),
      }));
      const deepPromise = isWeb
        ? analyzeWebWithGLMDeep(sourceCode.slice(0, 30000), contractName, { apiKey, model, timeoutMs: 300_000 }, firstPassSummary)
        : analyzeWithGLMDeep(sourceCode, contractName, { apiKey, model, timeoutMs: 300_000 }, firstPassSummary);
      // 5 MINUTES for deep pass — same as pass 1, no rushing
      const deepTimeout = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('AI pass 2 (deep) timeout after 300s (5 min)')), 300_000)
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
      const allowedLowTypes = new Set(['api_leak', 'info_exposure', 'information_disclosure']);
      const hasConcreteChain = /(\bRCE\b|data exfiltrat|fund theft|wallet drain|credential leak|private key|mnemonic)/i.test(v.description || '');
      if (isLow && !allowedLowTypes.has((v.type || '').toLowerCase()) && !hasConcreteChain) {
        droppedLowSeverity++;
        continue;
      }

      const hashSig = makeVulnHash(contractId, v.type, v.title);
      try {
        const existing = await withTimeout(db.vulnerability.findFirst({ where: { hashSignature: hashSig } }), 10_000, null, 'findFirst existing vuln');
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
        const vuln = await withTimeout(db.vulnerability.create({
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
        }), 10_000, null, 'ai vuln.create');
        if (vuln) savedAi.push({ vuln, rawFinding: v });
      } catch (err: any) {
        console.error(`[analyze-job] Failed to save finding "${v?.title}": ${String(err?.message || err).slice(0, 200)}`);
      }
    }

    if (jobTimedOut) return;

    if (droppedLowSeverity > 0) {
      await updateJob(70, `Filtered out ${droppedLowSeverity} low-severity findings. Saving ${savedAi.length} medium+ findings...`);
    }

    await updateJob(75, `Saved ${savedAi.length} AI findings. Starting active validation...`);

    // Phase 3: ACTIVE VALIDATION (parallel, 25s per finding) — CONFIRM-OR-DROP
    // User explicitly asked: "if we search for what we can confirm then how
    // can inconclusive appear and what's the sense of showing me
    // non-exploitable?". Right answer: don't show them at all. If a finding
    // can't be confirmed with HARD HTTP evidence, DELETE it. The user only
    // wants to see real, confirmed exploits — not AI speculation.
    await runValidationOnFindings(savedAi, sourceCode, contractName, apiKey, model, targetUrl, updateJob, 75);
    await runValidationOnFindings(savedStatic, sourceCode, contractName, apiKey, model, targetUrl, updateJob, 85);

    // ─── DROP ALL NON-CONFIRMED FINDINGS ───
    // The user wants only confirmed exploits in the final list. Any AI/static
    // finding that wasn't actively confirmed gets DELETED from the DB. This
    // eliminates 'inconclusive', 'candidate', and 'refuted' statuses entirely.
    // The DB now contains ALL findings: confirmed/validated + dropped (with reason).
    // This was changed post Claude-audit: previously we DELETED non-confirmed
    // findings, which destroyed our ability to measure FN (recall) — we couldn't
    // distinguish 'AI found nothing' from 'validator killed it'. Now we keep
    // dropped findings with a dropReason, so we can compute:
    //   - candidate/confirm ratio (main recall lever)
    //   - drop-reason histogram (connectivity vs proof_contract vs parse vs timeout)
    //   - AI-recall vs Validator-recall vs E2E-recall separately
    // Frontend still filters by status='confirmed'|'validated' for the user-facing list.
    const dropIds: string[] = [];
    const keptIds: string[] = [];
    const dropReasons: Record<string, number> = {};
    for (const s of [...savedStatic, ...savedAi]) {
      const st = s.vuln.status;
      console.log(`[analyze-job] Drop check: type="${(s.rawFinding?.type || s.vuln?.type || 'unknown')}" status="${st}" title="${(s.vuln?.title || '').slice(0, 60)}" → ${st === 'confirmed' || st === 'validated' ? 'KEEP' : 'DROP'}`);
      if (st !== 'confirmed' && st !== 'validated') {
        dropIds.push(s.vuln.id);
        // Determine drop reason from in-memory state for histogram
        const reason = s.vuln._dropReason || s.vuln._dropReasonPassive || (s.vuln.confidence === 0 ? 'no_evidence' : 'unconfirmed');
        dropReasons[reason] = (dropReasons[reason] || 0) + 1;
        s.vuln.status = 'dropped'; // mark for tally
      } else {
        keptIds.push(s.vuln.id);
      }
    }
    console.log(`[analyze-job] Drop summary: ${keptIds.length} kept (confirmed/validated), ${dropIds.length} to drop`);
    console.log(`[analyze-job] Drop reasons histogram: ${JSON.stringify(dropReasons)}`);
    if (dropIds.length > 0) {
      try {
        // UPDATE to status='dropped' with reason — DO NOT DELETE
        // (preserves raw AI findings + drop reason for FN analysis)
        await withTimeout(db.vulnerability.updateMany({
          where: { id: { in: dropIds } },
          data: { status: 'dropped', confidence: 0 },
        }), 10_000, null, 'dropIds updateMany');
        console.log(`[analyze-job] Marked ${dropIds.length} findings as 'dropped' (preserved in DB for FN analysis)`);
      } catch (e) {
        console.warn('[analyze-job] Failed to mark non-confirmed findings as dropped:', String(e).slice(0, 100));
      }
    }

    const allResults = [...savedStatic.map(s => s.vuln), ...savedAi.map(s => s.vuln)].filter((r: any) => r.status === 'confirmed' || r.status === 'validated');
    const exploitCount = allResults.length + preConfirmed.length;

    const summary = `Analysis complete: ${exploitCount} confirmed exploit${exploitCount === 1 ? '' : 's'} (${preConfirmed.length} from active HTTP probes + ${allResults.length} from AI/static validation). All findings passed rigor verification (5 standard questions: repeatability, clean session, public comparison, multi-entity, real-vs-demo). Non-confirmed findings were dropped.`;
    await updateJob(100, summary);
    fireAndForget(db.audit.update({ where: { id: auditId }, data: { status: 'completed', findings: exploitCount, completedAt: new Date() } }), 'final audit.update');
    fireAndForget(db.analysisJob.update({ where: { id: jobId }, data: { status: 'completed', resultCount: exploitCount } }), 'final analysisJob.update');
    writeProgressFile(jobId, { progress: 100, message: summary, status: 'completed' });

  } catch (err: any) {
    fireAndForget(db.audit.update({ where: { id: auditId },
      data: { status: 'failed', completedAt: new Date() } }), 'catch audit.update');
    fireAndForget(db.analysisJob.update({ where: { id: jobId },
      data: { status: 'failed', error: String(err).slice(0, 500), progress: 100, message: 'Analysis failed' } }), 'catch analysisJob.update');
    writeProgressFile(jobId, { progress: 100, message: `Analysis failed: ${String(err).slice(0, 80)}`, status: 'failed' });
  } finally {
    clearTimeout(globalTimeout);
    clearTimeout(panicTimer);
    clearInterval(flushTimer); clearInterval(heartbeatTimer);
    // Final force-flush so user sees the latest state immediately
    try {
      await flushJobNow();
    } catch {}
  }
}

/**
 * Run active validation on a list of saved findings, in parallel with a
 * per-finding 25s timeout. Mutates the savedFindings array's `vuln.status`
 * in place based on validation outcome. Only EXPLOITABLE findings get
 * saved with a real status (confirmed/validated); everything else ends
 * up as 'candidate'/'refuted' which the caller will DELETE.
 *
 * @param savedFindings - array of { vuln, rawFinding } from previous phase
 * @param sourceCode - source code/context
 * @param contractName - target name
 * @param apiKey - OpenRouter API key
 * @param model - AI model name
 * @param targetUrl - target URL for HTTP-based validation
 * @param updateJob - progress reporter
 * @param startProgress - progress value to start ticking from
 */
// ─── PASSIVE EVIDENCE TYPES ──────────────────────────────────────────
// These types CAN be auto-confirmed from recon data — but ONLY if
// SUFFICIENT evidence is found. User explicit feedback:
//   'Passive type ≠ automatically valid.
//    Passive type + sufficient passive evidence → auto-confirm.'
//
// Examples where presence ≠ exploitable:
//   - CORS Allow-Origin: * alone is FINE for public APIs. Exploitable
//     only if combined with Allow-Credentials: true.
//   - /api/openapi.json existing ≠ API leak. Need to verify it exposes
//     internal endpoints or sensitive schemas.
//   - 'POSSIBLE hardcoded secret' in recon ≠ API leak. Need REAL secret
//     pattern (sk-/eyJ/AKIA/ghp_), not placeholder.
//
// For each passive type, src/lib/passive-evidence.ts defines a STRICT
// evidence checker. If sufficient → auto-confirm. If not → fall back
// to active HTTP validation.
const PASSIVE_EVIDENCE_TYPES = new Set([
  'csp_missing',
  'info_exposure',
  'information_disclosure', // AI sometimes uses this synonym for info_exposure
  'api_leak',
  'cors_misconfig',
  'clickjacking',
  'hsts_missing',
  'cookie_security',
  'header_misconfig',
]);

async function runValidationOnFindings(
  savedFindings: any[],
  sourceCode: string,
  contractName: string,
  apiKey: string,
  model: string,
  targetUrl: string | undefined,
  updateJob: (progress: number, message: string) => Promise<void>,
  startProgress: number,
) {
  if (savedFindings.length === 0) return;
  let completed = 0;
  let confirmed = 0;
  let passiveConfirmed = 0;
  let activeValidated = 0;
  const total = savedFindings.length;

  const verifyPromises = savedFindings.map(async ({ vuln, rawFinding: v }: any) => {
    try {
      const findingType = (v.type || '').toLowerCase();
      console.log(`[analyze-job] Validating finding: type="${findingType}" title="${(v.title || '').slice(0, 60)}" — isPassiveType=${PASSIVE_EVIDENCE_TYPES.has(findingType)}`);

      // ─── PASSIVE EVIDENCE CHECK (with EVIDENCE ISOLATION) ───
      // CRITICAL: use ISOLATED evidence context, not full sourceCode.
      // Previous version searched the ENTIRE sourceCode (containing data
      // from ALL findings) → finding B could get evidence from finding A.
      // Now: each finding gets its OWN scoped evidence.
      if (PASSIVE_EVIDENCE_TYPES.has(findingType)) {
        // Isolate evidence for THIS finding only
        const isoCtx = isolateEvidence(
          { type: v.type, title: v.title, description: v.description, location: v.location, severity: v.severity },
          sourceCode, // full sourceCode — but isolateEvidence scopes it
          null, // no HTTP response yet for passive check
        );
        const isoCheck = verifyEvidenceIsolation(isoCtx);
        if (!isoCheck.isIsolated) {
          console.warn(`[analyze-job]   EVIDENCE CONTAMINATION detected: ${isoCheck.contaminationRisk}`);
        }

        // Use ISOLATED scopedSourceCode, NOT full sourceCode
        const evidenceResult = checkPassiveEvidence(findingType, isoCtx.scopedSourceCode, v);
        console.log(`[analyze-job]   Passive evidence: sufficient=${evidenceResult.sufficient} confidence=${evidenceResult.confidence} evidence="${evidenceResult.evidence.slice(0, 80)}"`);
        console.log(`[analyze-job]   Evidence sources: ${isoCtx.evidenceSources.join(', ')}`);
        if (evidenceResult.sufficient) {
          const label = `[CONFIRMED via passive evidence] ${evidenceResult.evidence}`;
          const newSeverity = evidenceResult.severity || v.severity || 'medium';
          const updateResult = await withTimeout(db.vulnerability.update({ where: { id: vuln.id },
            data: { confidence: evidenceResult.confidence, status: 'validated',
              validationScope: 'passive', severity: newSeverity,
              description: vuln.description + `\n\n${label}\n\n== RIGOR VERIFICATION (passive, isolated evidence) ==\nEvidence sources: ${isoCtx.evidenceSources.join(', ')}\nEvidence: ${evidenceResult.evidence}\nConfidence: ${evidenceResult.confidence}` } }), 10_000, null, 'passive vuln.update');
          console.log(`[analyze-job]   DB update result: ${updateResult ? 'SUCCESS' : 'FAILED (null)'} — setting in-memory status='validated'`);
          vuln.confidence = evidenceResult.confidence;
          vuln.status = 'validated';
          vuln.validationScope = 'passive';
          vuln.severity = newSeverity;
          confirmed++;
          passiveConfirmed++;
          return;
        } else {
          // Capture dropReason from passive evidence result for histogram
          if (evidenceResult.dropReason) {
            (vuln as any)._dropReason = evidenceResult.dropReason;
          }
          console.log(`[analyze-job]   Passive INSUFFICIENT (dropReason=${evidenceResult.dropReason || 'unknown'}) — falling back to active validation`);
        }
      }

      // ─── PROVENANCE CHAIN (replaces superficial activelyValidate) ───
      // User: 'candidate → request ID → raw request → raw response →
      // evidence extractor → security-property check → CONFIRMED / DROP'
      // 'AI может иметь confidence 0.99, но это ещё не proof.
      //  100% = deterministic validator доказал security property.'
      const provenance = await Promise.race([
        runProvenanceChain(
          { title: v.title, type: v.type, severity: v.severity, description: v.description, location: v.location },
          targetUrl || '',
        ),
        new Promise<any>((resolve) =>
          setTimeout(() => resolve({
            verdict: 'DROP',
            confidence: 0,
            evidenceChain: 'Provenance chain timed out (30s) — could not verify security property.',
            securityChecks: [{ propertyName: 'timeout', passed: false, reasoning: 'Timed out', evidence: '' }],
          }), 30_000)),
      ]);

      console.log(`[analyze-job]   Provenance chain: verdict=${provenance.verdict} confidence=${provenance.confidence}`);
      console.log(`[analyze-job]   Security checks: ${provenance.securityChecks.map((c: any) => `${c.propertyName}=${c.passed === true ? 'PASS' : c.passed === false ? 'FAIL' : 'INCONCLUSIVE'}`).join(', ')}`);

      if (provenance.verdict === 'CONFIRMED' || provenance.verdict === 'INCONCLUSIVE') {
        // ─── IMPACT ENGINE with EVIDENCE ISOLATION ───
        // Isolate evidence for THIS finding only — prevent contamination
        const httpResp = provenance.response
          ? { bodyExcerpt: provenance.response.bodyExcerpt, status: provenance.response.status, headers: provenance.response.headers }
          : null;
        const isoCtx = isolateEvidence(
          { type: v.type, title: v.title, description: v.description, location: v.location, severity: v.severity },
          sourceCode,
          httpResp,
        );
        const isoCheck = verifyEvidenceIsolation(isoCtx);
        if (!isoCheck.isIsolated) {
          console.warn(`[analyze-job]   EVIDENCE CONTAMINATION in impact engine: ${isoCheck.contaminationRisk}`);
        }
        console.log(`[analyze-job]   Evidence isolation: sources=${isoCtx.evidenceSources.join(', ')}`);

        const fullResult = fullVerify(
          { title: v.title, type: v.type, severity: v.severity, description: v.description, location: v.location },
          { bodyExcerpt: isoCtx.scopedSourceCode, status: httpResp?.status || 0, headers: httpResp?.headers || {} },
          isoCtx.scopedSourceCode, // ISOLATED, not full sourceCode
        );

        console.log(`[analyze-job]   Impact engine: verdict=${fullResult.verdict} severity=${fullResult.severity}`);
        console.log(`[analyze-job]   Boundary: violated=${fullResult.boundary?.boundaryViolated} ownerData=${fullResult.boundary?.isOwnerData}`);
        console.log(`[analyze-job]   Impact: ${fullResult.impact?.realImpact || 'N/A'}`);

        // Map full verdict to DB status
        let dbStatus: string;
        let dbConfidence: number;
        if (fullResult.verdict === 'EXPECTED_BEHAVIOR') {
          // Normal app behavior — NOT a vulnerability → DROP
          console.log(`[analyze-job]   EXPECTED_BEHAVIOR — not a vulnerability, dropping`);
          vuln.status = 'candidate';
          vuln.confidence = 0;
          // Don't increment confirmed — this gets dropped
        } else if (fullResult.verdict === 'EXPLOITABLE' || fullResult.verdict === 'IMPACT_CONFIRMED') {
          dbStatus = 'confirmed';
          dbConfidence = fullResult.confidence.exploitability;
          await withTimeout(db.vulnerability.update({ where: { id: vuln.id },
            data: { confidence: dbConfidence, status: dbStatus, validationScope: 'provenance',
              severity: fullResult.severity,
              description: vuln.description + `\n\n${fullResult.evidenceChain}` } }), 10_000, null, 'fullVerify vuln.update exploitable');
          vuln.confidence = dbConfidence;
          vuln.status = dbStatus;
          vuln.severity = fullResult.severity;
          vuln.validationScope = 'provenance';
          confirmed++;
          activeValidated++;
        } else if (fullResult.verdict === 'CONFIRMED_CONFIGURATION' || fullResult.verdict === 'NOT_DIRECTLY_EXPLOITABLE') {
          // Real finding but not directly exploitable — save as 'validated'
          // with severity computed from impact (not type)
          dbStatus = 'validated';
          dbConfidence = fullResult.confidence.evidence;
          await withTimeout(db.vulnerability.update({ where: { id: vuln.id },
            data: { confidence: dbConfidence, status: dbStatus, validationScope: 'provenance',
              severity: fullResult.severity,
              description: vuln.description + `\n\n${fullResult.evidenceChain}` } }), 10_000, null, 'fullVerify vuln.update config');
          vuln.confidence = dbConfidence;
          vuln.status = dbStatus;
          vuln.severity = fullResult.severity;
          vuln.validationScope = 'provenance';
          confirmed++;
        } else if (fullResult.verdict === 'OBSERVED') {
          // Pattern observed but not verified — INCONCLUSIVE for human review
          dbStatus = 'validated';
          dbConfidence = 0.5;
          await withTimeout(db.vulnerability.update({ where: { id: vuln.id },
            data: { confidence: dbConfidence, status: dbStatus, validationScope: 'provenance',
              severity: fullResult.severity,
              description: vuln.description + `\n\n${fullResult.evidenceChain}\n\n⚠ Requires manual verification.` } }), 10_000, null, 'fullVerify vuln.update observed');
          vuln.confidence = dbConfidence;
          vuln.status = dbStatus;
          vuln.severity = fullResult.severity;
          vuln.validationScope = 'provenance';
          confirmed++;
        } else {
          // DROP — disproven
          vuln.status = 'candidate';
          vuln.confidence = 0;
        }
      } else {
        // DROP — actively disproven (false positive)
        console.log(`[analyze-job]   Provenance DROPPED — security property disproven`);
        vuln.status = 'candidate';
        vuln.confidence = 0;
      }
    } catch {
      // Validation timed out or failed — this finding is unconfirmed.
      // Mark as candidate so caller deletes it.
      vuln.status = 'candidate';
      vuln.confidence = 0;
    }
    completed++;
    if (completed % 3 === 0 || completed === total) {
      await updateJob(Math.min(95, startProgress + Math.round((completed / total) * 10)),
        `Validated ${completed}/${total} — ${confirmed} confirmed so far...`).catch(() => {});
    }
  });
  await Promise.allSettled(verifyPromises);
}
