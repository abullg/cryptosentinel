import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { checkStandardRateLimit } from '@/lib/rate-limit';

export async function GET(req: Request) {
  const rl = checkStandardRateLimit(req);
  if (!rl.allowed) return NextResponse.json({ error: 'Rate limited', retryAfter: Math.ceil(rl.retryAfterMs / 1000) }, { status: 429 });
  try {
    const patterns = await db.memoryPattern.findMany({
      orderBy: { frequency: 'desc' },
    });
    return NextResponse.json(patterns);
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 500 });
  }
}

export async function POST(req: Request) {
  const rl = checkStandardRateLimit(req);
  if (!rl.allowed) return NextResponse.json({ error: 'Rate limited', retryAfter: Math.ceil(rl.retryAfterMs / 1000) }, { status: 429 });
  try {
    const body = await req.json();

    // Check if pattern already exists (anti-duplicate for patterns)
    const existing = await db.memoryPattern.findFirst({
      where: { name: body.name, type: body.type },
    });

    if (existing) {
      const updated = await db.memoryPattern.update({
        where: { id: existing.id },
        data: { frequency: { increment: 1 } },
      });
      return NextResponse.json({ ...updated, _existed: true });
    }

    const pattern = await db.memoryPattern.create({
      data: {
        type: body.type,
        name: body.name,
        description: body.description,
        tags: body.tags || '',
        chain: body.chain,
        severity: body.severity || 'medium',
      },
    });
    return NextResponse.json(pattern, { status: 201 });
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 500 });
  }
}
