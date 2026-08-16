import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { activelyValidate } from '@/lib/active-validator';

export const maxDuration = 300;
export const dynamic = 'force-dynamic';

/** POST /api/validate-vuln — Run active validation for a SINGLE vulnerability
 *  This runs real exploit testing (Foundry for contracts, HTTP payloads for web)
 *  and updates the vulnerability's confidence and status.
 *  Only vulnerabilities that PASS validation are shown to the user. */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { vulnerabilityId } = body;
    
    if (!vulnerabilityId) {
      return NextResponse.json({ error: 'Missing vulnerabilityId' }, { status: 400 });
    }
    
    const vuln = await db.vulnerability.findUnique({
      where: { id: vulnerabilityId },
      include: { contract: true },
    }).catch(() => null);
    
    if (!vuln) {
      return NextResponse.json({ error: 'Vulnerability not found' }, { status: 404 });
    }
    
    // Get API key
    const settings = await db.settings.findFirst().catch(() => null);
    const apiKey = process.env.OPENROUTER_API_KEY || settings?.apiKey || '';
    const model = settings?.model || 'z-ai/glm-5.2';
    
    // Run active validation
    const result = await activelyValidate(
      vuln.contract?.sourceCode || body.sourceCode || '',
      vuln.contract?.name || 'Contract',
      {
        type: vuln.type,
        title: vuln.title,
        severity: vuln.severity,
        description: vuln.description,
        location: vuln.location || '',
      },
      apiKey,
      model,
    );
    
    // Update vulnerability based on validation result.
    // IMPORTANT: confidence boost and final status depend on validation scope.
    //   target   = real exploit against production target → +0.15, can be 'confirmed'
    //   lab      = exploit viable in local Foundry/EVM only → +0.05, stays 'validated'
    //   theoretical = no runtime validation → +0, stays at current status
    const scope = result.validationScope || 'theoretical';
    if (result.confirmed) {
      const confidenceBoost = scope === 'target' ? 0.15 : scope === 'lab' ? 0.05 : 0;
      const newConfidence = Math.min(vuln.confidence + confidenceBoost, 0.99);
      // 'confirmed' status requires target-level validation
      const newStatus = scope === 'target' && newConfidence >= 0.90
        ? 'confirmed'
        : newConfidence >= 0.80 ? 'validated' : 'candidate';
      const scopeLabel =
        scope === 'target' ? '[TARGET-VALIDATED] Exploit confirmed by sending a real request to the production target.' :
        scope === 'lab'      ? '[LAB-VALIDATED] Exploit chain is technically viable in a controlled local environment. This does NOT confirm the production target is exploitable — only that the exploit logic works under lab conditions.' :
                              '[THEORETICAL] No runtime validation performed; based on static analysis / AI reasoning only.';
      await db.vulnerability.update({
        where: { id: vulnerabilityId },
        data: {
          confidence: newConfidence,
          status: newStatus,
          description: vuln.description + `\n\n${scopeLabel}\n${result.evidence}`,
        },
      }).catch(() => {});
      return NextResponse.json({
        valid: true,
        confidence: newConfidence,
        status: newStatus,
        validationScope: scope,
        evidence: result.evidence,
        testOutput: result.testOutput,
      });
    } else {
      // Failed validation — drop below 90% to remove from results
      const newConfidence = Math.max(vuln.confidence - 0.20, 0);
      const scopeLabel =
        scope === 'target' ? '[TARGET-VALIDATED] Exploit did NOT succeed against the production target — this is meaningful negative evidence.' :
        scope === 'lab'      ? '[LAB-VALIDATED] Exploit did NOT succeed under lab conditions — likely a false positive, or the exploit requires on-chain state not reproduced locally.' :
                              '[THEORETICAL] No runtime validation performed.';
      await db.vulnerability.update({
        where: { id: vulnerabilityId },
        data: {
          confidence: newConfidence,
          status: 'candidate',
          description: vuln.description + `\n\n${scopeLabel}\n${result.evidence}`,
        },
      }).catch(() => {});
      return NextResponse.json({
        valid: false,
        confidence: newConfidence,
        status: 'candidate',
        validationScope: scope,
        evidence: result.evidence,
      });
    }
  } catch (e: any) {
    return NextResponse.json({ error: String(e).slice(0, 300) }, { status: 500 });
  }
}
