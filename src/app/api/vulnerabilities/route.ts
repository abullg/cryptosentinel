import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { checkStandardRateLimit } from '@/lib/rate-limit';

export async function GET(req: Request) {
  const rl = checkStandardRateLimit(req);
  if (!rl.allowed) return NextResponse.json({ error: 'Rate limited', retryAfter: Math.ceil(rl.retryAfterMs / 1000) }, { status: 429 });
  try {
    const vulns = await db.vulnerability.findMany({
      include: { contract: { include: { project: true } } },
      orderBy: { confidence: 'desc' },
    });
    return NextResponse.json(vulns);
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 500 });
  }
}

export async function POST(req: Request) {
  const rl = checkStandardRateLimit(req);
  if (!rl.allowed) return NextResponse.json({ error: 'Rate limited', retryAfter: Math.ceil(rl.retryAfterMs / 1000) }, { status: 429 });
  try {
    const body = await req.json();

    // === ACTION: clear-all — delete all vulnerabilities, contracts, audits ===
    if (body.action === 'clear-all') {
      const deletedVulns = await db.vulnerability.deleteMany({});
      const deletedContracts = await db.contract.deleteMany({});
      const deletedAudits = await db.audit.deleteMany({});
      return NextResponse.json({
        cleared: true,
        vulnerabilities: deletedVulns.count,
        contracts: deletedContracts.count,
        audits: deletedAudits.count,
      });
    }

    // === ACTION: mark-duplicate — mark a vulnerability as duplicate ===
    if (body.action === 'mark-duplicate' && body.id && body.duplicateOf) {
      const updated = await db.vulnerability.update({
        where: { id: body.id },
        data: { isDuplicate: true, duplicateOf: body.duplicateOf, status: 'duplicate' },
      });
      return NextResponse.json(updated);
    }

    // === Anti-duplicate: check hash signature ===
    if (body.hashSignature) {
      const existing = await db.vulnerability.findFirst({
        where: { hashSignature: body.hashSignature },
      });
      if (existing) {
        return NextResponse.json({
          ...existing,
          _duplicate: true,
          _message: 'Duplicate detected — exact hash match',
        });
      }
    }

    // === Semantic duplicate check ===
    // Check for same type + title on the same contract
    const semanticMatch = await db.vulnerability.findFirst({
      where: {
        contractId: body.contractId,
        type: body.type,
        title: body.title,
      },
    });
    if (semanticMatch) {
      return NextResponse.json({
        ...semanticMatch,
        _duplicate: true,
        _message: 'Semantic duplicate — same type and title on this contract',
      });
    }

    // Count similar vulns for info (not blocking)
    const similar = await db.vulnerability.findMany({
      where: {
        type: body.type,
        contract: { projectId: body.projectId },
      },
      take: 5,
    });

    const vuln = await db.vulnerability.create({
      data: {
        contractId: body.contractId,
        type: body.type,
        severity: body.severity || 'medium',
        title: body.title,
        description: body.description,
        location: body.location,
        codeSnippet: body.codeSnippet,
        poc: body.poc,
        confidence: 0.0,
        status: 'candidate',
        hashSignature: body.hashSignature,
        patternTag: body.patternTag,
        isDuplicate: false,
      },
    });

    return NextResponse.json({
      ...vuln,
      _similarCount: similar.length,
    }, { status: 201 });
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 500 });
  }
}

export async function DELETE(req: Request) {
  try {
    const { searchParams } = new URL(req.url);
    const id = searchParams.get('id');

    if (id) {
      // Delete a single vulnerability
      const deleted = await db.vulnerability.delete({ where: { id } });
      return NextResponse.json({ deleted: true, id: deleted.id });
    }

    // If no id, delete all
    const result = await db.vulnerability.deleteMany({});
    return NextResponse.json({ deleted: true, count: result.count });
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 500 });
  }
}
