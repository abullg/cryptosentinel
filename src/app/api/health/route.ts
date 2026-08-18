import { NextResponse } from 'next/server';

/**
 * GET /api/health — Lightweight readiness probe for PM2/Caddy/k8s.
 * Does NOT require auth (excluded from middleware).
 * Returns 503 if Prisma can't connect, 200 otherwise.
 */
export async function GET() {
  const start = Date.now();
  try {
    const { db } = await import('@/lib/db');
    // Run a trivial query to verify DB is reachable
    await db.$queryRaw`SELECT 1`;
    return NextResponse.json({
      status: 'ok',
      uptime: process.uptime(),
      db: 'ok',
      ms: Date.now() - start,
      ts: new Date().toISOString(),
    });
  } catch (e) {
    return NextResponse.json(
      {
        status: 'degraded',
        db: 'error',
        error: String(e).slice(0, 200),
        ms: Date.now() - start,
        ts: new Date().toISOString(),
      },
      { status: 503 },
    );
  }
}
