import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { generateVulnerabilityReport } from '@/lib/report-generator';

export const dynamic = 'force-dynamic';

/** GET /api/report?id=<vuln_id> — Download professional .txt report for a vulnerability */
export async function GET(req: NextRequest) {
  const id = req.nextUrl.searchParams.get('id');
  if (!id) {
    return NextResponse.json({ error: 'Missing vulnerability ID' }, { status: 400 });
  }
  
  const vuln = await db.vulnerability.findUnique({
    where: { id },
    include: { contract: { include: { project: true } } },
  }).catch(() => null);
  
  if (!vuln) {
    return NextResponse.json({ error: 'Vulnerability not found' }, { status: 404 });
  }
  
  // Only generate reports for >= 90% confidence
  if ((vuln.confidence || 0) < 0.90) {
    return NextResponse.json({ error: 'Vulnerability below 90% confidence threshold' }, { status: 403 });
  }
  
  const report = generateVulnerabilityReport(vuln, vuln.contract?.name);
  
  return new NextResponse(report.content, {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Disposition': `attachment; filename="${report.filename}"`,
    },
  });
}

/** POST /api/report — Generate report for all vulnerabilities (ZIP) */
export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => ({}));
  const { vulnerabilityId } = body;
  
  if (vulnerabilityId) {
    // Single report
    const vuln = await db.vulnerability.findUnique({
      where: { id: vulnerabilityId },
      include: { contract: { include: { project: true } } },
    }).catch(() => null);
    
    if (!vuln) return NextResponse.json({ error: 'Not found' }, { status: 404 });
    if ((vuln.confidence || 0) < 0.90) return NextResponse.json({ error: 'Below threshold' }, { status: 403 });
    
    const report = generateVulnerabilityReport(vuln, vuln.contract?.name);
    return NextResponse.json({ filename: report.filename, content: report.content });
  }
  
  // All reports
  const vulns = await db.vulnerability.findMany({
    where: { confidence: { gte: 0.90 } },
    include: { contract: { include: { project: true } } },
  }).catch(() => []);
  
  const reports = vulns.map(v => generateVulnerabilityReport(v, v.contract?.name));
  return NextResponse.json({ reports });
}
