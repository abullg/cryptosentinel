import { NextRequest, NextResponse } from 'next/server';

/**
 * Test if an OpenRouter API key actually works against the OpenRouter API.
 *
 * Two modes:
 *   1. body.testKey provided → test that key
 *   2. no testKey → test the currently-configured key (env var or DB)
 *
 * Hits the lightweight /api/v1/key endpoint, not /chat/completions, to:
 *   - Avoid burning credits
 *   - Stay well under the Vercel function timeout (15s limit)
 *   - Get rich metadata: free_tier status, usage, rate_limit
 */
export const maxDuration = 15;
export const dynamic = 'force-dynamic';

interface OpenRouterKeyResponse {
  data?: {
    label?: string;
    is_free_tier?: boolean;
    usage?: number;
    limit?: number | null;
    limit_remaining?: number | null;
    rate_limit?: { requests: number; interval: string };
    expires_at?: string | null;
  };
  error?: { message?: string; code?: number };
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const testKey = body.testKey as string | undefined;

    // If a test key was provided, validate format first
    if (testKey) {
      if (testKey.startsWith('vcp_')) {
        return NextResponse.json({
          valid: false,
          reason: 'This looks like a Vercel API token, not an OpenRouter key. OpenRouter keys start with "sk-or-v1-".',
        });
      }
      if (testKey.startsWith('sk-') && !testKey.startsWith('sk-or-')) {
        return NextResponse.json({
          valid: false,
          reason: 'This looks like an OpenAI key, not an OpenRouter key. OpenRouter keys start with "sk-or-v1-".',
        });
      }
      if (!testKey.startsWith('sk-or-v1-') || testKey.length < 30) {
        return NextResponse.json({
          valid: false,
          reason: 'Invalid OpenRouter key format. Keys start with "sk-or-v1-" and are 30+ characters.',
        });
      }
    }

    // Resolve the key to test (provided test key OR currently configured one)
    let keyToTest = testKey;
    let source = 'provided';
    if (!keyToTest) {
      // Fetch from settings DB
      try {
        const { db } = await import('@/lib/db');
        const settings = await db.settings.findFirst();
        keyToTest = settings?.apiKey || undefined;
        source = settings?.apiKey ? 'db' : 'none';
      } catch {}
      // Env var has precedence (mirrors analyze-ai/route.ts logic)
      if (process.env.OPENROUTER_API_KEY) {
        keyToTest = process.env.OPENROUTER_API_KEY;
        source = 'env';
      }
    }

    if (!keyToTest) {
      return NextResponse.json({
        valid: false,
        reason: 'No API key configured. Set one in Settings dialog or as OPENROUTER_API_KEY env var.',
        source,
      });
    }

    // Hit OpenRouter's lightweight /api/v1/key endpoint
    // Returns key metadata + free_tier status + usage stats
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000); // 10s max
    let resp: Response;
    try {
      resp = await fetch('https://openrouter.ai/api/v1/key', {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${keyToTest}`,
          'HTTP-Referer': 'https://cryptosentinel.app',
          'X-Title': 'CryptoSentinel',
        },
        signal: controller.signal,
      });
    } catch (fetchErr) {
      clearTimeout(timeout);
      const msg = fetchErr instanceof Error ? fetchErr.message : String(fetchErr);
      if (msg.includes('abort') || msg.includes('AbortError')) {
        return NextResponse.json({
          valid: false,
          reason: 'OpenRouter request timed out after 10s. The service may be slow — try again.',
          source,
        });
      }
      return NextResponse.json({
        valid: false,
        reason: `Network error: ${msg.slice(0, 200)}`,
        source,
      });
    }
    clearTimeout(timeout);

    const data: OpenRouterKeyResponse = await resp.json().catch(() => ({}));

    if (resp.status === 401) {
      return NextResponse.json({
        valid: false,
        reason: 'OpenRouter rejected this key (401 Unauthorized). The key may be revoked, expired, or incorrectly copied.',
        source,
      });
    }
    if (resp.status === 403) {
      return NextResponse.json({
        valid: false,
        reason: 'OpenRouter denied access (403 Forbidden). The key may not have permission to query its own metadata.',
        source,
      });
    }
    if (resp.status === 429) {
      return NextResponse.json({
        valid: false,
        reason: 'OpenRouter rate limit reached (429). Wait a moment and try again.',
        source,
      });
    }
    if (!resp.ok) {
      const errMsg = data?.error?.message || `HTTP ${resp.status}`;
      return NextResponse.json({
        valid: false,
        reason: `OpenRouter error: ${errMsg.slice(0, 200)}`,
        source,
      });
    }

    // Success — return rich metadata so the UI can show the user what they have
    const d = data.data || {};
    return NextResponse.json({
      valid: true,
      reason: 'OpenRouter API key is valid and working.',
      source,
      key_info: {
        label: d.label,
        is_free_tier: d.is_free_tier,
        usage: d.usage,
        limit: d.limit,
        limit_remaining: d.limit_remaining,
        rate_limit: d.rate_limit,
        expires_at: d.expires_at,
      },
    });
  } catch (e) {
    return NextResponse.json({
      valid: false,
      reason: `Internal error: ${String(e).slice(0, 200)}`,
    }, { status: 500 });
  }
}
