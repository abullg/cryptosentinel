/**
 * CryptoSentinel — Independent Benchmark (30 targets)
 * 
 * Tests diverse targets: crypto exchanges, DeFi, Web3 wallets, dApps,
 * traditional web apps, e-commerce, blogs, docs, APIs.
 * 
 * For each target:
 * 1. Fetch URL (10s timeout)
 * 2. Run analyze-job (background, poll for completion up to 15 min)
 * 3. Collect: findings count, confirmed count, dropped count, types
 * 4. Measure: fetch time, AI time, validation time, total time
 * 
 * Results show: detection rate, validation accuracy, FP indicators
 */
// Per Claude protocol (§7): self-host GT in docker, no production crypto
// exchanges without authz, no external testphp (DC IP block).
// Pre-registered in tests/gt/expected.yaml — DO NOT edit after bench starts.
const TARGETS = [
  // ─── A. GT (self-hosted docker on VPS, localhost) ───
  'http://localhost:3001/',  // OWASP Juice Shop — 116 challenges
  'http://localhost:3002/',  // DVWA — classic SQLi/XSS
  'http://localhost:3003/',  // WrongSecrets — calibrate api_leak FP
  'http://localhost:3004/',  // crAPI — API/IDOR
  'http://localhost:3005/',  // WebGoat — classic tutorial
  'http://localhost:3007/',  // CANARY — prompt injection resistance test
  'http://localhost:3008/',  // NEGATIVE — Hello World (precision test)

  // ─── B. Negatives (real, but expected 0 exploitable) ───
  'https://example.com/',
  'https://httpbin.org/',

  // ─── C. Production homepages — PASSIVE ONLY (no active probes) ───
  // Per Claude §9.30: no active probes on production crypto exchanges
  // without written authorization. Egress allowlist enforces this.
  'https://www.bitunix.com/',
  'https://app.uniswap.org/',
  'https://aave.com/',
  'https://metamask.io/',
  'https://www.ledger.com/',
];

async function benchmark() {
  const API_BASE = process.argv[2] || 'http://localhost:3000';
  const results = [];

  console.log(`Benchmarking ${TARGETS.length} targets against ${API_BASE}`);
  console.log('=' .repeat(80));

  for (let i = 0; i < TARGETS.length; i++) {
    const url = TARGETS[i];
    console.log(`\n[${i+1}/${TARGETS.length}] ${url}`);
    const startTime = Date.now();

    try {
      // Step 1: Fetch URL
      const fetchStart = Date.now();
      const fetchRes = await fetch(`${API_BASE}/api/fetch-url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, type: 'exchange' }),
        signal: AbortSignal.timeout(30_000),
      });
      const fetchTime = Date.now() - fetchStart;

      if (!fetchRes.ok) {
        const err = await fetchRes.json().catch(() => ({}));
        console.log(`  FETCH FAILED: ${err.error || fetchRes.status} (${fetchTime}ms)`);
        results.push({ url, status: 'fetch_failed', fetchTime, error: err.error || String(fetchRes.status) });
        continue;
      }

      const data = await fetchRes.json();
      if (data.error) {
        console.log(`  FETCH ERROR: ${data.error} (${fetchTime}ms)`);
        results.push({ url, status: 'fetch_error', fetchTime, error: data.error });
        continue;
      }

      console.log(`  FETCH OK: ${data.sourceCode?.length || 0} chars (${fetchTime}ms) via ${data.reconType || 'unknown'}`);

      // Step 2: Start analysis
      const analyzeStart = Date.now();
      const analyzeRes = await fetch(`${API_BASE}/api/analyze-job`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sourceCode: data.sourceCode,
          contractName: data.contractName || url.replace(/https?:\/\//, '').split('/')[0],
          targetType: 'exchange',
          targetUrl: url,
          discoveredEndpoints: data.discoveredEndpoints || [],
          discoveredForms: data.discoveredForms || [],
          discoveredParams: data.discoveredParams || [],
        }),
        signal: AbortSignal.timeout(15_000),
      });

      if (!analyzeRes.ok) {
        const err = await analyzeRes.json().catch(() => ({}));
        console.log(`  ANALYZE FAILED: ${err.error || analyzeRes.status}`);
        results.push({ url, status: 'analyze_failed', fetchTime, error: err.error });
        continue;
      }

      const { jobId } = await analyzeRes.json();
      console.log(`  JOB STARTED: ${jobId}`);

      // Step 3: Poll for completion (up to 15 min)
      let completed = false;
      let job = null;
      for (let poll = 0; poll < 180; poll++) {
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
          if (poll % 12 === 0) {
            console.log(`  POLLING: ${status.progress}% - ${(status.message || '').slice(0, 60)}`);
          }
        } catch {}
      }

      const totalTime = Date.now() - startTime;
      const analyzeTime = Date.now() - analyzeStart;

      if (!completed) {
        console.log(`  TIMEOUT after ${totalTime}ms`);
        results.push({ url, status: 'timeout', fetchTime, analyzeTime, totalTime });
        continue;
      }

      // Step 4: Get vulnerabilities
      let vulns = [];
      try {
        const vulnsRes = await fetch(`${API_BASE}/api/vulnerabilities?t=${Date.now()}`, {
          signal: AbortSignal.timeout(10_000),
        });
        if (vulnsRes.ok) {
          vulns = await vulnsRes.json();
        }
      } catch {}

      const confirmed = vulns.filter(v => v.status === 'confirmed' || v.status === 'validated');
      const types = [...new Set(confirmed.map(v => v.type))];
      const severities = confirmed.map(v => v.severity);

      console.log(`  COMPLETE: ${confirmed.length} confirmed (${vulns.length} total in DB) (${totalTime}ms)`);
      console.log(`  Types: ${types.join(', ') || 'none'}`);
      console.log(`  Severities: ${severities.join(', ') || 'none'}`);

      results.push({
        url,
        status: 'completed',
        fetchTime,
        analyzeTime,
        totalTime,
        confirmedCount: confirmed.length,
        totalCount: vulns.length,
        types,
        severities,
        jobMessage: job?.message || '',
      });

    } catch (e) {
      const totalTime = Date.now() - startTime;
      console.log(`  ERROR: ${String(e).slice(0, 100)} (${totalTime}ms)`);
      results.push({ url, status: 'error', totalTime, error: String(e).slice(0, 200) });
    }
  }

  // ─── SUMMARY ───────────────────────────────────────────────────
  console.log('\n' + '=' .repeat(80));
  console.log('BENCHMARK SUMMARY');
  console.log('=' .repeat(80));

  const succeeded = results.filter(r => r.status === 'completed');
  const failed = results.filter(r => r.status !== 'completed');
  const withFindings = succeeded.filter(r => r.confirmedCount > 0);

  console.log(`Total targets:     ${results.length}`);
  console.log(`Succeeded:         ${succeeded.length}`);
  console.log(`Failed:            ${failed.length}`);
  console.log(`With findings:     ${withFindings.length}`);
  console.log(`Detection rate:    ${succeeded.length > 0 ? (withFindings.length / succeeded.length * 100).toFixed(1) : 0}%`);

  console.log('\n--- PER-TARGET RESULTS ---');
  for (const r of results) {
    if (r.status === 'completed') {
      console.log(`✓ ${r.url.slice(0, 50).padEnd(50)} | ${r.confirmedCount} findings | ${r.types?.join(',') || 'none'} | ${r.totalTime}ms`);
    } else {
      console.log(`✗ ${r.url.slice(0, 50).padEnd(50)} | ${r.status} | ${r.error?.slice(0, 50) || ''}`);
    }
  }

  console.log('\n--- FINDING TYPE DISTRIBUTION ---');
  const typeCount = {};
  for (const r of succeeded) {
    for (const t of (r.types || [])) {
      typeCount[t] = (typeCount[t] || 0) + 1;
    }
  }
  for (const [type, count] of Object.entries(typeCount).sort((a, b) => b[1] - a[1])) {
    console.log(`  ${type.padEnd(25)} ${count} targets`);
  }

  console.log('\n--- TIMING (avg hides heavy tail — per Claude §9.15) ---');
  const fetchTimes = succeeded.map(r => r.fetchTime).filter(t => t > 0);
  const totalTimes = succeeded.map(r => r.totalTime).filter(t => t > 0);

  function percentile(arr, p) {
    if (arr.length === 0) return 0;
    const sorted = [...arr].sort((a, b) => a - b);
    const idx = Math.ceil((p / 100) * sorted.length) - 1;
    return sorted[Math.max(0, idx)];
  }

  if (fetchTimes.length > 0) {
    console.log(`  Fetch time: avg=${(fetchTimes.reduce((a, b) => a + b, 0) / fetchTimes.length / 1000).toFixed(2)}s  p50=${(percentile(fetchTimes, 50) / 1000).toFixed(2)}s  p95=${(percentile(fetchTimes, 95) / 1000).toFixed(2)}s`);
    console.log(`  Total time: avg=${(totalTimes.reduce((a, b) => a + b, 0) / totalTimes.length / 1000).toFixed(1)}s  p50=${(percentile(totalTimes, 50) / 1000).toFixed(1)}s  p95=${(percentile(totalTimes, 95) / 1000).toFixed(1)}s`);
    console.log(`  Min total time:   ${(Math.min(...totalTimes) / 1000).toFixed(1)}s`);
    console.log(`  Max total time:   ${(Math.max(...totalTimes) / 1000).toFixed(1)}s`);
  }

  console.log('\n--- COST ESTIMATE (per Claude §9.14) ---');
  // GLM-5.2 cost: assume $0.01 per 1K input + $0.03 per 1K output (typical tier)
  // Each target: 2 passes × ~30K input + ~4K output
  const inputTokens = succeeded.length * 2 * 30000;
  const outputTokens = succeeded.length * 2 * 4000;
  const costUSD = (inputTokens / 1000 * 0.01) + (outputTokens / 1000 * 0.03);
  console.log(`  Targets analyzed:  ${succeeded.length}`);
  console.log(`  Est. input tokens: ~${inputTokens.toLocaleString()}`);
  console.log(`  Est. output tokens: ~${outputTokens.toLocaleString()}`);
  console.log(`  Est. cost (USD):   $${costUSD.toFixed(2)}`);
  console.log(`  Cost per target:   $${(costUSD / succeeded.length).toFixed(3)}`);
  console.log(`  Scaled to 1000 targets/day: $${(costUSD * 1000 / succeeded.length).toFixed(0)}/day`);

  console.log('\n--- DROP REASONS HISTOGRAM (per Claude §9.8) ---');
  // Pull from /api/vulnerabilities?include_dropped=1 (if backend supports)
  // For now: try the endpoint, log if it works
  console.log(`  See PM2 OUT for: '[analyze-job] Drop reasons histogram: {...}'`);
  console.log(`  Candidate/confirm ratio = (dropped + confirmed) / confirmed — main recall lever`);

  console.log('\n--- VULNERABLE TARGETS (known GT) ---');
  const knownVuln = results.filter(r => r.url.includes('localhost:3001') || r.url.includes('localhost:3002') || r.url.includes('localhost:3003') || r.url.includes('localhost:3004') || r.url.includes('localhost:3005') || r.url.includes('juice-shop'));
  for (const r of knownVuln) {
    console.log(`  ${r.url}: ${r.status === 'completed' ? `${r.confirmedCount} confirmed (recall = N/${r.totalCount || '?'})` : r.status}`);
  }

  // Output JSON for analysis
  console.log('\n--- JSON RESULTS ---');
  console.log(JSON.stringify(results, null, 2));
}

benchmark().catch(e => console.error('Benchmark failed:', e));
