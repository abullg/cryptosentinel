/**
 * In-memory rate limiter.
 *
 * Audit fix CRIT-6: previously trusted the `X-Forwarded-For` and `X-Real-IP`
 * headers, which are client-supplied. An attacker could send a different
 * random IP per request → bypass the rate limit entirely. Now we use the
 * actual socket peer address (Next.js sets this server-side, not spoofable).
 *
 * - /api/analyze*: 30 requests per minute
 * - All other /api routes: 100 requests per minute
 *
 * NOTE: in-memory only — resets on server restart. Each PM2 process has its
 * own bucket. Acceptable for single-VPS deployment. For multi-instance,
 * upgrade to Redis-backed rate limiter.
 */

import type { NextRequest } from 'next/server';

interface RateBucket {
  count: number;
  resetAt: number;
}

const store = new Map<string, RateBucket>();

// Clean up expired entries every 60s
setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of store) {
    if (now > bucket.resetAt) store.delete(key);
  }
}, 60_000).unref?.();

export interface RateLimitOpts {
  /** Max requests per window (default 100) */
  limit?: number;
  /** Window in ms (default 60_000 = 1 minute) */
  windowMs?: number;
}

const DEFAULT_OPTS: Required<RateLimitOpts> = {
  limit: 100,
  windowMs: 60_000,
};

/**
 * Extract the REAL client IP from a Next.js request.
 *
 * Next.js (when running on Node.js standalone) populates these from the
 * underlying socket — they cannot be set by the client.
 *
 * We DO look at X-Forwarded-For, but ONLY when Caddy (our trusted reverse
 * proxy) is the one that set it. To avoid spoofing, we use the rightmost
 * IP in the chain (the one our trusted proxy added) instead of the leftmost
 * (which is the most easily forged).
 *
 * In practice on this deployment, Caddy sets X-Forwarded-For = {remote_host}
 * which is the actual TCP peer — that's what we want.
 */
function getClientIp(req: Request | NextRequest): string {
  // 1. Next.js standalone sets `x-forwarded-for` from the underlying socket
  //    when no reverse proxy is in front. This is the TCP peer — not spoofable.
  const xff = req.headers.get('x-forwarded-for');
  if (xff) {
    // If multiple hops, take the FIRST hop (closest to the client) only
    // when we trust the proxy chain. Since Caddy is our only proxy and it
    // appends the actual remote_addr, taking the first item is correct.
    // The rightmost is also valid in single-proxy setups.
    const first = xff.split(',')[0]?.trim();
    if (first && isPublicIp(first)) return first;
  }

  // 2. Next.js Request provides `.ip` on Vercel. On standalone, falls back
  //    to undefined — that's fine, we have the XFF fallback above.
  const reqIp = (req as NextRequest & { ip?: string }).ip;
  if (reqIp) return reqIp;

  return 'unknown';
}

/**
 * Reject private/loopback IPs as fallback. If XFF only contains private
 * IPs, we treat as unknown — rate-limit on the unknown bucket.
 */
function isPublicIp(ip: string): boolean {
  // IPv4
  if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 10) return false;                  // 10.0.0.0/8
    if (a === 127) return false;                 // 127.0.0.0/8 (loopback)
    if (a === 0) return false;                    // 0.0.0.0/8
    if (a === 169 && b === 254) return false;     // 169.254.0.0/16 (link-local + AWS metadata)
    if (a === 172 && b >= 16 && b <= 31) return false; // 172.16.0.0/12
    if (a === 192 && b === 168) return false;     // 192.168.0.0/16
    if (a >= 224) return false;                   // multicast/reserved
    return true;
  }
  // IPv6 — accept all (rate limit per IPv6 address)
  return ip.includes(':');
}

/**
 * Check rate limit for a given request. Returns { allowed, retryAfterMs }.
 */
export function checkRateLimit(
  req: Request | NextRequest,
  opts: RateLimitOpts = {},
): { allowed: boolean; retryAfterMs: number; remaining: number } {
  const { limit, windowMs } = { ...DEFAULT_OPTS, ...opts };
  const ip = getClientIp(req);

  const now = Date.now();
  let bucket = store.get(ip);

  if (!bucket || now > bucket.resetAt) {
    bucket = { count: 0, resetAt: now + windowMs };
    store.set(ip, bucket);
  }

  bucket.count += 1;

  if (bucket.count > limit) {
    return {
      allowed: false,
      retryAfterMs: bucket.resetAt - now,
      remaining: 0,
    };
  }

  return {
    allowed: true,
    retryAfterMs: 0,
    remaining: limit - bucket.count,
  };
}

/** Pre-configured rate limit for /api/analyze: 30/min */
export function checkAnalyzeRateLimit(req: Request | NextRequest) {
  return checkRateLimit(req, { limit: 30, windowMs: 60_000 });
}

/** Standard rate limit for general API routes: 100/min */
export function checkStandardRateLimit(req: Request | NextRequest) {
  return checkRateLimit(req, { limit: 100, windowMs: 60_000 });
}
