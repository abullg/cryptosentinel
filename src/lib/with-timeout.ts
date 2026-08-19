/**
 * CryptoSentinel — Promise Timeout Helper
 *
 * Wraps any Promise with a hard timeout. If the promise doesn't resolve
 * within `timeoutMs`, the wrapper resolves with `null` (or a custom
 * fallback) and logs an error.
 *
 * This is CRITICAL for the analyze-job pipeline. Without it, ANY Prisma
 * SQLite call can hang forever (SQLite single-writer lock contention,
 * disk I/O issue, transaction deadlock). One hung Prisma call = entire
 * pipeline frozen = user sees "stuck at N%" forever.
 *
 * Usage:
 *   const result = await withTimeout(
 *     db.vulnerability.create({...}),
 *     10_000, // 10s timeout
 *     null,   // fallback value
 *     'create vulnerability'  // operation name for logging
 *   );
 */

export async function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number = 10_000,
  fallback: T | null = null,
  opName: string = 'unknown'
): Promise<T | null> {
  try {
    const result = await Promise.race([
      promise,
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error(`${opName} timed out after ${timeoutMs}ms`)), timeoutMs)
      ),
    ]);
    return result;
  } catch (e: any) {
    // Only log if it's a timeout (real errors should be logged by caller)
    if (e?.message?.includes?.('timed out')) {
      console.error(`[with-timeout] ${opName} TIMED OUT after ${timeoutMs}ms — Prisma likely hung, continuing with fallback`);
    }
    return fallback;
  }
}

/**
 * Fire-and-forget wrapper: runs the promise but doesn't await it.
 * Returns immediately. Errors are logged but don't propagate.
 *
 * Use for non-critical writes (like audit updates) where we don't
 * need to wait for the write to complete before continuing.
 */
export function fireAndForget<T>(promise: Promise<T>, opName: string = 'unknown'): void {
  promise.catch(e => {
    console.error(`[fire-and-forget] ${opName} failed: ${String(e).slice(0, 100)}`);
  });
}
