import { NextRequest, NextResponse } from 'next/server';
import { timingSafeEqual } from 'crypto';

const AUTH_COOKIE_NAME = 'cryptosentinel-token';
const COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 7; // 7 days

function safeEqual(a: string, b: string): boolean {
  const aBuf = Buffer.from(a);
  const bBuf = Buffer.from(b);
  if (aBuf.length !== bBuf.length) return false;
  try {
    return timingSafeEqual(aBuf, bBuf);
  } catch {
    return false;
  }
}

/**
 * POST /api/login
 * Body: { password: string }
 *   - The password is compared to the env var CRYPTOSENTINEL_AUTH_TOKEN
 *
 * On success: 200 with Set-Cookie: cryptosentinel-token=<value>; HttpOnly; SameSite=Strict
 * On failure: 401
 *
 * On missing CRYPTOSENTINEL_AUTH_TOKEN env var: 503 (auth not configured).
 */
export async function POST(req: NextRequest) {
  const authToken = process.env.CRYPTOSENTINEL_AUTH_TOKEN;

  if (!authToken || authToken.length < 8) {
    return NextResponse.json(
      {
        error:
          'Authentication is not configured on the server. Set CRYPTOSENTINEL_AUTH_TOKEN env var (min 8 chars) to enable login.',
        authConfigured: false,
      },
      { status: 503 },
    );
  }

  let body: { password?: string } = {};
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  const password = body.password;
  if (!password || typeof password !== 'string') {
    return NextResponse.json({ error: 'Password is required' }, { status: 400 });
  }

  if (!safeEqual(password, authToken)) {
    return NextResponse.json({ error: 'Invalid password' }, { status: 401 });
  }

  // Success: set HttpOnly cookie. Value IS the env token (single-admin app).
  const res = NextResponse.json({ authenticated: true });
  res.cookies.set({
    name: AUTH_COOKIE_NAME,
    value: authToken,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
    maxAge: COOKIE_MAX_AGE_SECONDS,
  });
  return res;
}

/** POST /api/logout — clear the cookie. */
export async function DELETE() {
  const res = NextResponse.json({ authenticated: false });
  res.cookies.delete(AUTH_COOKIE_NAME);
  return res;
}

/** GET /api/login — check if auth is configured. */
export async function GET() {
  const configured =
    !!process.env.CRYPTOSENTINEL_AUTH_TOKEN &&
    process.env.CRYPTOSENTINEL_AUTH_TOKEN.length >= 8;
  return NextResponse.json({ authConfigured: configured });
}
