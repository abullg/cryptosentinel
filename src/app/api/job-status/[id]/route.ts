import { NextRequest, NextResponse } from 'next/server';
export const dynamic = 'force-dynamic';

import { db } from '@/lib/db';

/** GET /api/job-status/{id} — Poll analysis job status. */
export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const job = await db.analysisJob.findUnique({ where: { id } }).catch(() => null);
    if (!job) return NextResponse.json({ error: 'Job not found' }, { status: 404 });
    return NextResponse.json({
      jobId: job.id, status: job.status, progress: job.progress,
      message: job.message, resultCount: job.resultCount, error: job.error,
      contractId: job.contractId, projectId: job.projectId,
    });
  } catch (e: any) {
    return NextResponse.json({ error: String(e).slice(0, 300) }, { status: 500 });
  }
}
