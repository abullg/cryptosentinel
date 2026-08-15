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
    
    // Update vulnerability based on validation result
    if (result.confirmed) {
      const newConfidence = Math.min(vuln.confidence + 0.05, 0.99);
      await db.vulnerability.update({
        where: { id: vulnerabilityId },
        data: {
          confidence: newConfidence,
          status: 'confirmed',
          description: vuln.description + `\n\n[ACTIVE VALIDATION PASSED] ${result.evidence}`,
        },
      }).catch(() => {});
      return NextResponse.json({
        valid: true,
        confidence: newConfidence,
        status: 'confirmed',
        evidence: result.evidence,
        testOutput: result.testOutput,
      });
    } else {
      // Failed validation — drop below 90% to remove from results
      const newConfidence = Math.max(vuln.confidence - 0.20, 0);
      await db.vulnerability.update({
        where: { id: vulnerabilityId },
        data: {
          confidence: newConfidence,
          status: 'candidate',
          description: vuln.description + `\n\n[ACTIVE VALIDATION FAILED] ${result.evidence}`,
        },
      }).catch(() => {});
      return NextResponse.json({
        valid: false,
        confidence: newConfidence,
        status: 'candidate',
        evidence: result.evidence,
      });
    }
  } catch (e: any) {
    return NextResponse.json({ error: String(e).slice(0, 300) }, { status: 500 });
  }
}
