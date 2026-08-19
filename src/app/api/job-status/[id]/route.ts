import { NextRequest, NextResponse } from 'next/server';
export const dynamic = 'force-dynamic';

import { db } from '@/lib/db';
import { readProgressFile } from '@/lib/progress-file';

/** GET /api/job-status/{id} — Poll analysis job status.
 *  Reads from JSON FILE FIRST (instant, non-blocking) — falls back to
 *  SQLite DB only if file is missing. This bypasses the Prisma SQLite
 *  single-writer bottleneck that caused the user's "stuck for 4 min"
 *  reports.
 */
export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const cacheBustHeaders = {
    'Cache-Control': 'no-store, no-cache, must-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0',
  };

  try {
    const { id } = await params;

    // ─── READ FROM FILE FIRST ───
    // The background job writes progress to /tmp/cs-progress/{jobId}.json
    // every 1s using writeFileSync (fast, non-blocking kernel I/O).
    // Reading this file is instant — no Prisma, no SQLite.
    const fileState = readProgressFile(id);
    if (fileState) {
      // ─── WATCHDOG ───
      // If file hasn't been updated in 2 min, the background process is dead.
      // Mark as failed so UI can show an error instead of spinning.
      const ageMs = Date.now() - (fileState.updatedAt || 0);
      const STALE_THRESHOLD = 2 * 60 * 1000;
      if ((fileState.status === 'running' || fileState.status === 'pending') && ageMs > STALE_THRESHOLD) {
        return NextResponse.json({
          jobId: id, status: 'failed', progress: 100,
          message: 'Failed (watchdog timeout)',
          error: `Job hasn't been updated in ${Math.round(ageMs / 1000)}s — server likely restarted (deploy/crash/OOM). Please retry.`,
        }, { headers: cacheBustHeaders });
      }
      // Try DB for additional fields (resultCount, contractId, projectId) —
      // but don't block if DB is slow
      let dbData: any = null;
      try {
        dbData = await db.analysisJob.findUnique({
          where: { id },
          select: { resultCount: true, contractId: true, projectId: true, error: true },
        });
      } catch {}

      return NextResponse.json({
        jobId: id,
        status: fileState.status,
        progress: fileState.progress,
        message: fileState.message,
        resultCount: dbData?.resultCount ?? 0,
        error: dbData?.error ?? null,
        contractId: dbData?.contractId ?? null,
        projectId: dbData?.projectId ?? null,
        _source: 'file',  // for debugging
      }, { headers: cacheBustHeaders });
    }

    // ─── FALLBACK: file missing, read from DB ───
    const job = await db.analysisJob.findUnique({ where: { id } }).catch(() => null);
    if (!job) return NextResponse.json({ error: 'Job not found' }, { status: 404 });

    // ─── WATCHDOG (DB fallback path) ───
    if (job.status === 'running' || job.status === 'pending') {
      const ageMs = Date.now() - job.updatedAt.getTime();
      const STALE_THRESHOLD = 2 * 60 * 1000;
      if (ageMs > STALE_THRESHOLD) {
        await db.analysisJob.update({
          where: { id: job.id },
          data: {
            status: 'failed',
            error: `Watchdog: job hasn't been updated in ${Math.round(ageMs / 1000)}s. The server likely restarted (deploy/crash/OOM) and killed the in-memory background job. Please retry the analysis.`,
            progress: 100,
            message: 'Failed (watchdog timeout)',
          },
        }).catch(() => {});
        return NextResponse.json({
          jobId: job.id, status: 'failed', progress: 100,
          message: 'Failed (watchdog timeout)',
          error: `Job hasn't been updated in ${Math.round(ageMs / 1000)}s — server likely restarted. Please retry.`,
          contractId: job.contractId, projectId: job.projectId,
        }, { headers: cacheBustHeaders });
      }
    }

    return NextResponse.json({
      jobId: job.id, status: job.status, progress: job.progress,
      message: job.message, resultCount: job.resultCount, error: job.error,
      contractId: job.contractId, projectId: job.projectId,
      _source: 'db',
    }, { headers: cacheBustHeaders });
  } catch (e: any) {
    return NextResponse.json({ error: String(e).slice(0, 300) }, { status: 500 });
  }
}
