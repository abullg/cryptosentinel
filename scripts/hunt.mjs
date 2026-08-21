#!/usr/bin/env node

/**
 * CryptoSentinel Hunt CLI — per Claude v10 DoD item 8.
 *
 * Usage:
 *   node hunt.mjs --url http://target:port \
 *     --auth '{"username":"user","password":"user"}' \
 *     --auth '{"username":"admin","password":"admin"}' \
 *     --no-fallback \
 *     --generate-poc
 *
 * This is a thin CLI wrapper that calls the same /api/fetch-url + /api/analyze-job
 * endpoints as benchmark.js, but for a SINGLE target with explicit auth config.
 *
 * Per Claude: "CLI — тонкая обёртка, не вынос из Next.js. Скрипт hunt.mjs,
 * который вызывает те же функции, что /api/analyze-job"
 */

import { readFileSync } from 'fs';

const args = process.argv.slice(2);
const opts = {};
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--url') opts.url = args[++i];
  else if (args[i] === '--auth') { if (!opts.auths) opts.auths = []; opts.auths.push(JSON.parse(args[++i])); }
  else if (args[i] === '--auth-file') { if (!opts.auths) opts.auths = []; opts.auths.push(JSON.parse(readFileSync(args[++i], 'utf-8'))); }
  else if (args[i] === '--no-fallback') opts.noFallback = true;
  else if (args[i] === '--generate-poc') opts.generatePoc = true;
  else if (args[i] === '--scope') opts.scope = args[++i];
  else if (args[i] === '--api-base') opts.apiBase = args[++i];
  else if (args[i] === '--help' || args[i] === '-h') {
    console.log(`CryptoSentinel Hunt CLI

Usage:
  node hunt.mjs --url http://127.0.0.1:3010 \\
    --auth '{"username":"user","password":"user"}' \\
    --auth '{"username":"admin","password":"admin"}' \\
    --no-fallback --generate-poc

Options:
  --url URL          Target URL to scan
  --auth JSON        Auth config (can repeat for multiple users)
  --auth-file FILE   Auth config from JSON file (can repeat)
  --no-fallback      Don't fall back to hardcoded oracles if crawler finds 0
  --generate-poc     Generate PoC report text for confirmed findings (needs API key)
  --scope FILE       Scope allowlist file (one URL pattern per line)
  --api-base URL     API base URL (default: http://localhost:3000)
  --help             Show this help

Per Claude v10: "на вход — base URL + 2 учётки; на выход — confirmed
+ curl-replay + черновик отчёта. Сначала на Express-GT без
захардкоженных путей."
`);
    process.exit(0);
  }
}

if (!opts.url) {
  console.error('Error: --url is required. Use --help for usage.');
  process.exit(1);
}

const API_BASE = opts.apiBase || 'http://localhost:3000';

async function hunt() {
  console.log(`CryptoSentinel Hunt`);
  console.log(`  Target: ${opts.url}`);
  console.log(`  Auth: ${opts.auths?.length || 0} users`);
  console.log(`  No-fallback: ${opts.noFallback || false}`);
  console.log(`  Generate-PoC: ${opts.generatePoc || false}`);
  console.log();

  // Step 1: Fetch URL
  console.log('Step 1: Fetching target...');
  const fetchRes = await fetch(`${API_BASE}/api/fetch-url`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: opts.url, type: 'exchange' }),
    signal: AbortSignal.timeout(120_000),
  });
  if (!fetchRes.ok) {
    console.error(`  FETCH FAILED: ${fetchRes.status}`);
    process.exit(1);
  }
  const data = await fetchRes.json();
  if (data.error) {
    console.error(`  FETCH ERROR: ${data.error}`);
    process.exit(1);
  }
  console.log(`  ✓ Fetched: ${data.sourceCode?.length || 0} chars via ${data.reconType}`);

  // Step 2: Analyze with auth + noFallback + generatePoc
  console.log('Step 2: Analyzing (crawler + identity matrix)...');
  const analyzeRes = await fetch(`${API_BASE}/api/analyze-job`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      sourceCode: data.sourceCode,
      contractName: opts.url.replace(/https?:\/\//, '').split('/')[0],
      targetType: 'exchange',
      targetUrl: opts.url,
      discoveredEndpoints: data.discoveredEndpoints || [],
      discoveredForms: data.discoveredForms || [],
      discoveredParams: data.discoveredParams || [],
      staticAnalysis: data.staticAnalysis || null,
      noFallback: opts.noFallback || false,
    }),
    signal: AbortSignal.timeout(15_000),
  });
  if (!analyzeRes.ok) {
    console.error(`  ANALYZE FAILED: ${analyzeRes.status}`);
    process.exit(1);
  }
  const { jobId } = await analyzeRes.json();
  console.log(`  Job ID: ${jobId}`);

  // Step 3: Poll for completion
  console.log('Step 3: Waiting for analysis...');
  let completed = false;
  let job = null;
  for (let poll = 0; poll < 60; poll++) {
    await new Promise(r => setTimeout(r, 5000));
    try {
      const statusRes = await fetch(`${API_BASE}/api/job-status/${jobId}?t=${Date.now()}`, {
        signal: AbortSignal.timeout(10_000),
      });
      if (!statusRes.ok) continue;
      const status = await statusRes.json();
      if (status.status === 'completed' || status.status === 'failed') {
        completed = true;
        job = status;
        break;
      }
      if (poll % 6 === 0) console.log(`  [${poll*5}s] ${status.progress}% - ${(status.message || '').slice(0, 80)}`);
    } catch {}
  }

  if (!completed) {
    console.error('  TIMEOUT');
    process.exit(1);
  }

  console.log(`\n  ✓ COMPLETE: ${job.message?.slice(0, 200)}`);

  // Step 4: Get findings
  console.log('\nStep 4: Findings...');
  const contractId = job?.contractId;
  const vulnsRes = await fetch(`${API_BASE}/api/vulnerabilities?t=${Date.now()}${contractId ? `&contractId=${contractId}` : ''}`, {
    signal: AbortSignal.timeout(10_000),
  });
  if (vulnsRes.ok) {
    const allVulns = await vulnsRes.json();
    const vulns = contractId ? allVulns.filter(v => v.contractId === contractId) : allVulns;
    const confirmed = vulns.filter(v => v.status === 'confirmed' || v.status === 'validated');

    console.log(`\n  ═══════════════════════════════════════════════════`);
    console.log(`  HUNT RESULTS: ${confirmed.length} confirmed findings`);
    console.log(`  ═══════════════════════════════════════════════════`);

    for (const v of confirmed) {
      console.log(`\n  ┌─ [${v.severity.toUpperCase()}] ${v.type} on ${v.location}`);
      console.log(`  │ CWE: ${(v.validationSteps || '').match(/CWE \d+/)?.[0] || 'N/A'}`);
      console.log(`  │ Evidence: ${(v.description || '').slice(0, 150)}`);
      if (v.codeSnippet) console.log(`  │ Payload: ${(v.codeSnippet || '').slice(0, 100)}`);
      if (v.poc) console.log(`  │ PoC: ${(v.poc || '').slice(0, 200)}`);
      console.log(`  └─`);
    }

    console.log(`\n  Telemetry: ${job.message || 'N/A'}`);
    console.log(`\n  Total: ${confirmed.length} confirmed, ${vulns.filter(v => v.status === 'dropped').length} dropped`);
  } else {
    console.log('  (could not fetch findings)');
  }
}

hunt().catch(e => { console.error('Hunt failed:', e); process.exit(1); });
