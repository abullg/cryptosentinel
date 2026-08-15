import { NextResponse } from 'next/server';
import { db } from '@/lib/db';

const DEFAULT_MODEL = 'z-ai/glm-5.2'; // GLM 5.2 with unlimited reasoning — primary analysis engine

// OpenRouter keys are always `sk-or-v1-...` (30+ chars after the prefix).
// Other prefixes (sk-, vcp_, etc.) are keys for different platforms and will
// NOT work with this app. Validating here saves the user a 60-200s timeout
// when they try to run analysis with a wrong-platform key.
const OPENROUTER_KEY_RE = /^sk-or-v1-[A-Za-z0-9_-]{20,}$/;

/** Validate the API key. Returns the reason if invalid (or null when valid). */
function validateApiKey(key: string | null | undefined): string | null {
  if (!key) return null; // Empty is OK — means "clear the key"
  if (key.includes('***')) return null; // Masked value from GET — don't update
  if (key.startsWith('vcp_')) return 'This looks like a Vercel API token, not an OpenRouter key. OpenRouter keys start with "sk-or-v1-".';
  if (key.startsWith('sk-') && !key.startsWith('sk-or-')) return 'This looks like an OpenAI key, not an OpenRouter key. OpenRouter keys start with "sk-or-v1-".';
  if (!OPENROUTER_KEY_RE.test(key)) return 'Invalid OpenRouter key format. Keys start with "sk-or-v1-" and are 30+ characters.';
  return null;
}

function maskKey(key: string | null | undefined): string | null {
  if (!key || key.length < 12) return key || null;
  return key.slice(0, 8) + '***' + key.slice(-4);
}

function githubStatus() {
  const ghToken = process.env.GITHUB_TOKEN;
  return ghToken
    ? { configured: true, masked: `ghp_${ghToken.slice(0, 4)}***${ghToken.slice(-4)}` }
    : { configured: false, masked: null };
}

/**
 * Determine the "effective" API key — env var takes precedence over DB.
 *
 * Why: Vercel serverless functions run on many instances, each with its own
 * /tmp/ filesystem. The SQLite database we use to persist settings lives in
 * /tmp/ and is bootstrapped from a baked-in copy at cold start. This means
 * updates to settings.apiKey via POST are visible ONLY on the instance that
 * received the POST — a different instance on the next request will start
 * fresh and read the OLD baked-in key.
 *
 * The fix: store the real key as the OPENROUTER_API_KEY environment variable
 * (set via Vercel dashboard or API). Env vars are part of the deployment
 * and visible on every instance. So we use env var FIRST, DB second.
 */
function getEffectiveApiKey(dbKey: string | null | undefined): { apiKey: string | null; source: 'env' | 'db' | null } {
  if (process.env.OPENROUTER_API_KEY) {
    return { apiKey: process.env.OPENROUTER_API_KEY, source: 'env' };
  }
  if (dbKey) {
    return { apiKey: dbKey, source: 'db' };
  }
  return { apiKey: null, source: null };
}

export async function GET() {
  try {
    let settings = await db.settings.findFirst();
    if (!settings) {
      settings = await db.settings.create({ data: { model: DEFAULT_MODEL } });
    }
    const effective = getEffectiveApiKey(settings.apiKey);
    // Never expose full API key — mask it
    return NextResponse.json({
      ...settings,
      apiKey: maskKey(effective.apiKey),
      _hasKey: !!effective.apiKey,
      _source: effective.source, // 'env' | 'db' | null — tells UI which key is in use
      github: githubStatus(),
    });
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 500 });
  }
}

/** Shared body for POST and PUT — both create-or-update settings. */
async function updateSettings(req: Request) {
  try {
    const body = await req.json();
    const { apiKey: rawApiKey, model: rawModel } = body;

    // ─── Validate API key format BEFORE persisting ───────────────
    // Old code accepted any string, which meant a wrong-platform key
    // (e.g. a Z.ai token starting with "vcp_") would be saved without
    // complaint — and every subsequent analysis would 401 from OpenRouter
    // after a 60-200s timeout. Validate here, return 400 if invalid.
    const keyError = validateApiKey(rawApiKey);
    if (keyError) {
      return NextResponse.json({ error: keyError }, { status: 400 });
    }

    const newModel = rawModel || DEFAULT_MODEL;
    let settings = await db.settings.findFirst();
    if (!settings) {
      settings = await db.settings.create({
        data: { apiKey: rawApiKey || null, model: newModel },
      });
    } else {
      const updateData: Record<string, unknown> = { model: newModel };
      // Only update apiKey if a real (non-masked) value was provided
      if (rawApiKey && !rawApiKey.includes('***')) {
        updateData.apiKey = rawApiKey;
      }
      settings = await db.settings.update({
        where: { id: settings.id },
        data: updateData,
      });
    }
    // Compute the effective key the same way GET does (env var wins)
    const effective = getEffectiveApiKey(settings.apiKey);
    return NextResponse.json({
      ...settings,
      apiKey: maskKey(effective.apiKey),
      _hasKey: !!effective.apiKey,
      _source: effective.source,
      github: githubStatus(),
      // Helpful hint when user just saved a key but env var still wins
      _note: process.env.OPENROUTER_API_KEY && rawApiKey && !rawApiKey.includes('***')
        ? 'Saved to DB, but OPENROUTER_API_KEY env var is set and takes precedence. To use this key, remove the env var.'
        : undefined,
    });
  } catch (e) {
    return NextResponse.json({ error: String(e) }, { status: 500 });
  }
}

// POST is the canonical method used by the UI today (see page-content.tsx saveApiKey).
export async function POST(req: Request) {
  return updateSettings(req);
}

// PUT is supported for backward compatibility — older clients and external
// integrations may have used PUT. Without this, they'd get a silent 405.
export async function PUT(req: Request) {
  return updateSettings(req);
}
