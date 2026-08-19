import { NextRequest, NextResponse } from 'next/server';
export const dynamic = 'force-dynamic';

import { db } from '@/lib/db';

/** GET /api/job-status/{id} — Poll analysis job status.
 *  Includes a WATCHDOG: if a job is "running" but hasn't been updated in > 2
 *  minutes, it's marked as failed. This handles the case where the server
 *  restarts (deploy, crash, OOM) and kills the in-memory background Promise
 *  — without the watchdog, the job would stay "running" forever.
 *
 *  Watchdog reduced from 5 min to 2 min: user reported "stuck at 30s for
 *  4 min" — with the new in-memory progress state + periodic flush,
 *  legitimate jobs update every 3s. If 2 min pass without update, the job
 *  is definitely dead. Fail fast so user can retry.
 */
export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const job = await db.analysisJob.findUnique({ where: { id } }).catch(() => null);
    if (!job) return NextResponse.json({ error: 'Job not found' }, { status: 404 });

    // ─── WATCHDOG ─────────────────────────────────────────────
    // If the job is "running" or "pending" but hasn't been updated in > 2 min,
    // the background process is dead (server restart, crash, OOM kill).
    // Mark it as failed so the UI can show an error instead of spinning forever.
    if (job.status === 'running' || job.status === 'pending') {
      const ageMs = Date.now() - job.updatedAt.getTime();
      const STALE_THRESHOLD = 2 * 60 * 1000; // 2 minutes (was 5 min)
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
        }, {
          headers: {
            'Cache-Control': 'no-store, no-cache, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0',
          },
        });
      }
    }

    return NextResponse.json({
      jobId: job.id, status: job.status, progress: job.progress,
      message: job.message, resultCount: job.resultCount, error: job.error,
      contractId: job.contractId, projectId: job.projectId,
    }, {
      headers: {
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0',
      },
    });
  } catch (e: any) {
    return NextResponse.json({ error: String(e).slice(0, 300) }, { status: 500 });
  }
}
