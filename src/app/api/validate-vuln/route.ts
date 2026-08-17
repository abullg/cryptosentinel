import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { activelyValidate } from '@/lib/active-validator';

export const maxDuration = 600; // 10 min — VPS KVM 2, allows full Foundry + cast on-chain validation
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
    
    // Run active validation — pass targetUrl if available
    const targetUrl = body.targetUrl || vuln.location?.match(/https?:\/\/[^\s"'<>]+/)?.[0] || '';
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
      targetUrl || undefined,
    );
    
    // BINARY model: confirmed or refuted. No percentages.
    const scope = result.validationScope || 'theoretical';
    if (result.confirmed) {
      const newStatus = scope === 'target' ? 'confirmed' : 'validated';
      const label = scope === 'target'
        ? '[EXPLOIT CONFIRMED ON PRODUCTION] Real HTTP request sent, exploit confirmed.'
        : '[EXPLOIT CONFIRMED IN LAB] Foundry test passed.';
      await db.vulnerability.update({
        where: { id: vulnerabilityId },
        data: {
          confidence: 1,
          status: newStatus,
          validationScope: scope,
          description: vuln.description + `\n\n${label}\n${result.evidence}`,
        },
      }).catch(() => {});
      return NextResponse.json({
        valid: true, confidence: 1, status: newStatus,
        validationScope: scope, evidence: result.evidence,
      });
    } else {
      const label = scope === 'target'
        ? '[NOT EXPLOITABLE] Tested against production — exploit failed.'
        : '[NOT EXPLOITABLE] Lab test failed.';
      await db.vulnerability.update({
        where: { id: vulnerabilityId },
        data: {
          confidence: 0,
          status: 'refuted',
          validationScope: scope,
          description: vuln.description + `\n\n${label}\n${result.evidence}`,
        },
      }).catch(() => {});
      return NextResponse.json({
        valid: false, confidence: 0, status: 'refuted',
        validationScope: scope, evidence: result.evidence,
      });
    }
  } catch (e: any) {
    return NextResponse.json({ error: String(e).slice(0, 300) }, { status: 500 });
  }
}
