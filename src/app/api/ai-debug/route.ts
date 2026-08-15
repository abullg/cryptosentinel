import { NextResponse } from 'next/server';
export const maxDuration = 60; // Vercel Hobby plan limit

export async function POST(req: Request) {
  const startTime = Date.now();
  const logs: string[] = [];
  const log = (msg: string) => { logs.push(`[${Date.now() - startTime}ms] ${msg}`); };

  try {
    const body = await req.json();
    const { sourceCode, contractName } = body;
    log('Start');

    const { db } = await import('@/lib/db');
    const settings = await db.settings.findFirst();
    const apiKey = settings?.apiKey || '';
    const model = settings?.model || 'z-ai/glm-5.2';
    log(`DB OK. Model: ${model}`);

    if (!apiKey || apiKey.length <= 10) {
      return NextResponse.json({ logs, error: 'No API key (key must be > 10 chars and a valid OpenRouter sk-or-v1-... token)' });
    }
    // Validate key format — refuse to even attempt a call with a wrong-platform key
    const OPENROUTER_KEY_RE = /^sk-or-v1-[A-Za-z0-9_-]{20,}$/;
    if (!OPENROUTER_KEY_RE.test(apiKey)) {
      let hint = 'Invalid OpenRouter key format.';
      if (apiKey.startsWith('vcp_')) hint = 'This looks like a Vercel API token, not an OpenRouter key.';
      else if (apiKey.startsWith('sk-') && !apiKey.startsWith('sk-or-')) hint = 'This looks like an OpenAI key, not an OpenRouter key.';
      return NextResponse.json({ logs, error: `${hint} Keys start with "sk-or-v1-".` });
    }

    log('Importing blockchain-verifier...');
    const { runBlockchainVerification } = await import('@/lib/blockchain-verifier');
    log('Starting blockchain verification (10s timeout)...');

    const blockchainPromise = runBlockchainVerification(
      sourceCode || 'contract Test {}', contractName || 'Test', undefined
    ).catch(err => { log(`BC error: ${String(err).slice(0, 80)}`); return ''; });

    const blockchainData = await Promise.race([
      blockchainPromise,
      new Promise<string>(resolve => setTimeout(() => { log('BC timeout'); resolve(''); }, 10_000)),
    ]);
    log(`BC done: ${blockchainData ? `${blockchainData.length}c` : 'empty'}`);

    log('Importing GLM...');
    const { analyzeWithGLM } = await import('@/lib/glm');
    log(`Calling analyzeWithGLM...`);

    const aiVulns = await analyzeWithGLM(
      sourceCode || 'contract Test {}', contractName || 'Test',
      { apiKey, model }, blockchainData || undefined
    );
    log(`GLM done! ${aiVulns.length} vulns`);

    return NextResponse.json({ logs, findings: aiVulns.length, success: true });
  } catch (e) {
    log(`ERROR: ${String(e).slice(0, 200)}`);
    return NextResponse.json({ logs, error: String(e) });
  }
}
