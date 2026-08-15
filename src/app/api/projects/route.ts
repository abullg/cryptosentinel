import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { checkStandardRateLimit } from '@/lib/rate-limit';

export async function GET(req: Request) {
  const rl = checkStandardRateLimit(req);
  if (!rl.allowed) return NextResponse.json({ error: 'Rate limited', retryAfter: Math.ceil(rl.retryAfterMs / 1000) }, { status: 429 });
  try {
    const projects = await db.project.findMany({
      include: { contracts: true, audits: true },
      orderBy: { updatedAt: 'desc' },
    });
    return NextResponse.json(projects);
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 500 });
  }
}

export async function POST(req: Request) {
  const rl = checkStandardRateLimit(req);
  if (!rl.allowed) return NextResponse.json({ error: 'Rate limited', retryAfter: Math.ceil(rl.retryAfterMs / 1000) }, { status: 429 });
  try {
    const body = await req.json();
    const project = await db.project.create({
      data: {
        name: body.name,
        chain: body.chain || 'ethereum',
        language: body.language || 'solidity',
        address: body.address,
      },
    });
    return NextResponse.json(project, { status: 201 });
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 500 });
  }
}
