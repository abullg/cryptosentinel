import { NextRequest, NextResponse } from 'next/server';
export const maxDuration = 900;
export const dynamic = 'force-dynamic';

import { db } from '@/lib/db';
import { analyzeWithGLM, analyzeWebWithGLM, DEFAULT_MODEL } from '@/lib/glm';
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
  const { sourceCode, contractName, targetType, apiKey, model, contractId, auditId } = config;
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

    // Phase 2: AI (with 90s hard timeout — if GLM hangs, continue with static)
    await updateJob(30, 'Starting AI deep analysis...');
    let aiVulns: any[] = [];
    try {
      // Race GLM against 90s timeout — if it loses, we still have static results
      const aiPromise = isWeb
        ? analyzeWebWithGLM(sourceCode.slice(0, 30000), contractName, { apiKey, model })
        : analyzeWithGLM(sourceCode, contractName, { apiKey, model }, undefined);
      const timeoutPromise = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('AI timeout after 150s')), 150_000)
      );
      aiVulns = await Promise.race([aiPromise, timeoutPromise]);
    } catch (err: any) {
      await updateJob(50, `AI error (continuing with static): ${String(err).slice(0, 100)}`);
      // Don't throw — continue with static findings only
    }

    await updateJob(60, `AI found ${aiVulns.length} potential vulnerabilities`);

    const savedAi: any[] = [];
    for (const v of aiVulns) {
      const hashSig = makeVulnHash(contractId, v.type, v.title);
      try {
        const existing = await db.vulnerability.findFirst({ where: { hashSignature: hashSig } });
        if (existing) continue;

        // BINARY model: no confidence percentages. Status tells the truth.
        // 'candidate' = AI found something, NOT YET TESTED
        const vuln = await db.vulnerability.create({
          data: { contractId, type: v.type, severity: v.severity || 'medium', title: v.title,
            description: v.description || '', location: v.location || `${contractName}:L1`,
            confidence: 0, status: 'candidate', // 0 = untested, will be replaced by validation
            v1Symbolic: v.v1Symbolic || null, v2Fuzzing: v.v2Fuzzing || null,
            v3Formal: v.v3Formal || null, v4Economic: v.v4Economic || null,
            hashSignature: hashSig, patternTag: v.type, target: contractName,
            vulnCategory: CATEGORY_MAP[v.type] || v.type,
            validationSteps: v.validationSteps || '', poc: v.pocOutline || '',
            pocFilename: `${v.type}_attack.t.sol`, codeSnippet: sourceCode ? sourceCode.slice(0, 200) : null },
        });
        savedAi.push({ vuln, rawFinding: v });
      } catch {}
    }

    await updateJob(75, `Saved ${savedAi.length} AI findings. Starting validation...`);

    // Phase 3: BINARY VALIDATION — exploit works or it doesn't. No percentages.
    //   confirmed = exploit WORKS (real HTTP payload reflected, or Foundry test passed)
    //   refuted   = exploit DOES NOT WORK (tested, failed)
    //   candidate = NOT TESTED (no URL, no Solidity, or validation error)
    if (savedAi.length > 0) {
      const verifyPromises = savedAi.map(async ({ vuln, rawFinding: v }: any) => {
        try {
          const vulnDesc = targetUrl ? `${v.description}\n\nTarget URL: ${targetUrl}` : v.description;
          const vulnLoc = targetUrl ? `${v.location}\nURL: ${targetUrl}` : v.location;

          const verification = await activelyValidate(
            sourceCode, contractName,
            { title: v.title, type: v.type, severity: v.severity, description: vulnDesc, location: vulnLoc },
            apiKey, model
          );
          const scope = verification.validationScope || 'theoretical';

          if (verification.confirmed) {
            // EXPLOIT WORKS — binary YES
            const newStatus = scope === 'target' ? 'confirmed' : 'validated';
            const label = scope === 'target'
              ? '[EXPLOIT CONFIRMED ON PRODUCTION] Real HTTP request sent, payload reflected/executed. This vulnerability IS exploitable.'
              : '[EXPLOIT CONFIRMED IN LAB] Foundry test passed. Exploit chain is viable.';
            await db.vulnerability.update({ where: { id: vuln.id },
              data: { confidence: 1, status: newStatus, validationScope: scope,
                description: vuln.description + `\n\n${label}\n${verification.evidence}` } }).catch(() => {});
            vuln.confidence = 1; vuln.status = newStatus; vuln.validationScope = scope;
          } else {
            // EXPLOIT DOES NOT WORK — binary NO
            const label = scope === 'target'
              ? '[NOT EXPLOITABLE] Real HTTP request sent to production target. Exploit did NOT succeed. This vulnerability is NOT exploitable.'
              : '[NOT EXPLOITABLE] Foundry test failed. Exploit does not work.';
            await db.vulnerability.update({ where: { id: vuln.id },
              data: { confidence: 0, status: 'refuted',
                validationScope: scope,
                description: vuln.description + `\n\n${label}\n${verification.evidence}` } }).catch(() => {});
            vuln.confidence = 0; vuln.validationScope = scope; vuln.status = 'refuted';
          }
        } catch {
          // VALIDATION ERROR — can't determine, leave as candidate
          await db.vulnerability.update({ where: { id: vuln.id },
            data: { validationScope: 'theoretical',
              description: vuln.description + '\n\n[UNTESTED] Validation could not run — no URL or test suite available.' } }).catch(() => {});
          vuln.validationScope = 'theoretical';
        }
      });
      await Promise.allSettled(verifyPromises);
    }

    const allResults = [...savedStatic.map(s => s.vuln), ...savedAi.map(s => s.vuln)];
    const resultCount = allResults.filter((r: any) => r.status === 'confirmed' || r.status === 'validated').length;

    await updateJob(100, `Analysis complete: ${allResults.length} total, ${resultCount} high-confidence`);
    await db.audit.update({ where: { id: auditId }, data: { status: 'completed', findings: allResults.length, completedAt: new Date() } }).catch(() => {});
    await db.analysisJob.update({ where: { id: jobId }, data: { status: 'completed', resultCount } }).catch(() => {});

  } catch (err: any) {
    // Fix bug #1: audit lifecycle — always mark as completed or failed
    await db.audit.update({ where: { id: auditId },
      data: { status: 'failed', completedAt: new Date() } }).catch(() => {});
    await db.analysisJob.update({ where: { id: jobId },
      data: { status: 'failed', error: String(err).slice(0, 500), progress: 100, message: 'Analysis failed' } }).catch(() => {});
  }
}
