/**
 * In-memory rate limiter (per-IP).
 * - /api/analyze: 30 requests per minute
 * - All other /api routes: 100 requests per minute
 */

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
}, 60_000);

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
 * Check rate limit for a given request. Returns { allowed, retryAfterMs }.
 */
export function checkRateLimit(
  req: Request,
  opts: RateLimitOpts = {},
): { allowed: boolean; retryAfterMs: number; remaining: number } {
  const { limit, windowMs } = { ...DEFAULT_OPTS, ...opts };

  // Derive IP from headers or fallback
  const forwarded = req.headers.get('x-forwarded-for');
  const realIp = req.headers.get('x-real-ip');
  const ip = forwarded?.split(',')[0]?.trim() || realIp || 'unknown';

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
export function checkAnalyzeRateLimit(req: Request) {
  return checkRateLimit(req, { limit: 30, windowMs: 60_000 });
}

/** Standard rate limit for general API routes: 100/min */
export function checkStandardRateLimit(req: Request) {
  return checkRateLimit(req, { limit: 100, windowMs: 60_000 });
}
