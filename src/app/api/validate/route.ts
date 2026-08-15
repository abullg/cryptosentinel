import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { checkStandardRateLimit } from '@/lib/rate-limit';

// Validation Pipeline: calculate confidence from V1-V4
export async function POST(req: Request) {
  const rl = checkStandardRateLimit(req);
  if (!rl.allowed) return NextResponse.json({ error: 'Rate limited', retryAfter: Math.ceil(rl.retryAfterMs / 1000) }, { status: 429 });
  try {
    const body = await req.json();
    const { vulnerabilityId, v1, v2, v3, v4 } = body;

    // Weights: V1=0.30, V2=0.25, V3=0.25, V4=0.20
    const w1 = 0.30, w2 = 0.25, w3 = 0.25, w4 = 0.20;

    const rawConfidence = w1 * (v1 ?? 0) + w2 * (v2 ?? 0) + w3 * (v3 ?? 0) + w4 * (v4 ?? 0);

    // Orthogonality bonus: +0.05 for each additional validator category confirming
    const confirmedCount = [v1, v2, v3, v4].filter(v => v && v > 0.5).length;
    const bonus = confirmedCount >= 3 ? (confirmedCount - 2) * 0.05 : 0;

    const confidence = Math.min(rawConfidence + bonus, 0.99);

    // Determine status
    let status = 'candidate';
    if (confidence >= 0.95) status = 'confirmed';
    else if (confidence >= 0.80) status = 'validated';
    else if (confidence >= 0.60) status = 'candidate';

    const updated = await db.vulnerability.update({
      where: { id: vulnerabilityId },
      data: {
        v1Symbolic: v1,
        v2Fuzzing: v2,
        v3Formal: v3,
        v4Economic: v4,
        confidence,
        status,
      },
    });

    return NextResponse.json({
      ...updated,
      _calculation: {
        raw: rawConfidence,
        bonus,
        final: confidence,
        confirmedValidators: confirmedCount,
      },
    });
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 500 });
  }
}
