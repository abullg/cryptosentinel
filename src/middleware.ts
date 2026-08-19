/**
 * CryptoSentinel authentication middleware.
 *
 * Audit fix CRIT-1: previously NO /api route required auth. Anyone on the
 * internet could: wipe all data (`POST /api/vulnerabilities {action:'clear-all'}`),
 * delete vulnerabilities, change the API key, run Foundry (RCE risk), burn
 * the user's OpenRouter credits, read all project data.
 *
 * This middleware is OPT-IN: if the env var `CRYPTOSENTINEL_AUTH_TOKEN` is
 * not set, no auth is enforced (suitable for localhost development).
 *
 * When the env var IS set, all requests to /api/* (except /api/login and
 * /api/health) must include either:
 *   - Cookie: `cryptosentinel-token=<value>`
 *   - Header: `Authorization: Bearer <value>`
 *   - Query:  `?token=<value>` (for SSE/EventSource which can't easily set headers)
 *
 * Comparison uses `crypto.timingSafeEqual` to prevent timing attacks.
 */

import { NextRequest, NextResponse } from 'next/server';
import { timingSafeEqual } from 'crypto';

const AUTH_COOKIE_NAME = 'cryptosentinel-token';
const AUTH_QUERY_PARAM = 'token';

// Routes that are ALWAYS public (no auth needed even when AUTH_TOKEN is set).
const PUBLIC_PATHS = [
  '/api/login',
  '/api/health',
  '/api/test-key',     // testing API key validity is part of onboarding
];

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

export function middleware(req: NextRequest) {
  const authToken = process.env.CRYPTOSENTINEL_AUTH_TOKEN;

  // No env var → no auth (dev mode / localhost). Allow.
  if (!authToken || authToken.length < 8) {
    return NextResponse.next();
  }

  const { pathname } = req.nextUrl;

  // Public routes — always allow
  if (PUBLIC_PATHS.some((p) => pathname === p || pathname.startsWith(p + '/'))) {
    return NextResponse.next();
  }

  // Only protect /api/* — pages served from / are protected by login redirect below.
  const isApi = pathname.startsWith('/api/');

  // ─── Extract token from request ────────────────────────────────────
  // 1. Cookie (preferred — works for XHR/fetch automatically)
  const cookieToken = req.cookies.get(AUTH_COOKIE_NAME)?.value;
  // 2. Authorization: Bearer <token>
  const authHeader = req.headers.get('authorization') || '';
  const bearerToken = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7).trim()
    : '';
  // 3. ?token=<value> (for SSE/EventSource which can't set headers)
  const queryToken = req.nextUrl.searchParams.get(AUTH_QUERY_PARAM) || '';

  const providedToken = cookieToken || bearerToken || queryToken;

  if (providedToken && safeEqual(providedToken, authToken)) {
    return NextResponse.next();
  }

  // ─── Not authenticated ──────────────────────────────────────────────
  if (isApi) {
    // For API routes, return 401 JSON
    return NextResponse.json(
      {
        error: 'Unauthorized. Set CRYPTOSENTINEL_AUTH_TOKEN env var on the server and authenticate via /api/login.',
        authenticated: false,
      },
      { status: 401 },
    );
  }

  // For non-API routes, redirect to /login
  const loginUrl = new URL('/login', req.url);
  loginUrl.searchParams.set('next', pathname);
  return NextResponse.redirect(loginUrl);
}

// Run middleware on Node.js runtime (not Edge) — `crypto.timingSafeEqual`
// is a Node-only API. Edge Runtime doesn't support it.
// Run on /api/* and root page (not on /_next/* static assets)
export const config = {
  runtime: 'nodejs',
  matcher: [
    // Match all API routes
    '/api/:path*',
    // Match root and any non-API pages (login flow)
    '/((?!_next/static|_next/image|favicon.ico|fonts|robots.txt|login).*)',
  ],
};
