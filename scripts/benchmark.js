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
      if (data.staticAnalysis) {
        const sa = data.staticAnalysis;
        console.log(`  STATIC: ${sa.findings?.length || 0} findings, ${sa.sinkHints?.length || 0} sink-hints, ${sa.stats?.totalMs || 'N/A'}ms, skipLLM=${sa.skipLLM}`);
        if (sa.findings && sa.findings.length > 0) {
          for (const f of sa.findings.slice(0, 3)) {
            console.log(`    - [${f.severity}] ${f.type}: ${f.title.slice(0, 70)}`);
          }
        }
      }

      // Step 2: Start analysis (pass staticAnalysis from fetch-url per Claude §8)
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
          // Pass static analysis results from /api/fetch-url
          // If skipLLM=true, LLM is not invoked — saves ~$0.84/target + 250s
          staticAnalysis: data.staticAnalysis || null,
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

      // Step 4: Get vulnerabilities FOR THIS JOB ONLY (filter by contractId)
      // Previous version fetched ALL findings in DB (cumulative across benches)
      // — that's why "confirmedCount" was 2 for every target even when per-job
      // message said "0 confirmed exploits". Now we filter by contractId.
      let vulns = [];
      try {
        const contractId = job?.contractId;
        const vulnsRes = await fetch(`${API_BASE}/api/vulnerabilities?t=${Date.now()}${contractId ? `&contractId=${contractId}` : ''}`, {
          signal: AbortSignal.timeout(10_000),
        });
        if (vulnsRes.ok) {
          const allVulns = await vulnsRes.json();
          // Filter client-side by contractId (in case API doesn't support query param)
          vulns = contractId
            ? allVulns.filter(v => v.contractId === contractId)
            : allVulns;
        }
      } catch {}

      const confirmed = vulns.filter(v => v.status === 'confirmed' || v.status === 'validated');
      const dropped = vulns.filter(v => v.status === 'dropped');
      const candidates = vulns.filter(v => v.status === 'candidate');
      const types = [...new Set(confirmed.map(v => v.type))];
      const severities = confirmed.map(v => v.severity);
      const dropReasons = dropped.map(v => v.dropReason || 'unknown');

      console.log(`  COMPLETE: ${confirmed.length} confirmed / ${candidates.length} candidate / ${dropped.length} dropped (${vulns.length} total for THIS jobId) (${totalTime}ms)`);
      console.log(`  Types: ${types.join(', ') || 'none'}`);
      console.log(`  Severities: ${severities.join(', ') || 'none'}`);
      if (dropped.length > 0) {
        const reasonHist = {};
        for (const r of dropReasons) reasonHist[r] = (reasonHist[r] || 0) + 1;
        console.log(`  Drop reasons: ${JSON.stringify(reasonHist)}`);
        console.log(`  Candidate/confirm ratio: ${(dropped.length + candidates.length)}/${confirmed.length} = ${confirmed.length > 0 ? ((dropped.length + candidates.length) / confirmed.length).toFixed(1) : '∞'}`);
      }

      results.push({
        url,
        status: 'completed',
        fetchTime,
        analyzeTime,
        totalTime,
        confirmedCount: confirmed.length,
        candidateCount: candidates.length,
        droppedCount: dropped.length,
        totalCount: vulns.length,
        types,
        severities,
        dropReasons,
        staticFindingsCount: data.staticAnalysis?.findings?.length || 0,
        staticSinkHintsCount: data.staticAnalysis?.sinkHints?.length || 0,
        staticSkipLLM: data.staticAnalysis?.skipLLM || false,
        staticTimeMs: data.staticAnalysis?.stats?.totalMs || 0,
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
  console.log(`Failed:           ${failed.length}`);
  console.log(`With findings:     ${withFindings.length}`);
  console.log(`Detection rate:    ${succeeded.length > 0 ? (withFindings.length / succeeded.length * 100).toFixed(1) : 0}% (PER-JOB, filtered by contractId — not cumulative DB count)`);

  // Per-job totals (NOT cumulative DB)
  const totalConfirmedPerJob = succeeded.reduce((sum, r) => sum + (r.confirmedCount || 0), 0);
  const totalDroppedPerJob = succeeded.reduce((sum, r) => sum + (r.droppedCount || 0), 0);
  const totalCandidatesPerJob = succeeded.reduce((sum, r) => sum + (r.candidateCount || 0), 0);
  console.log(`\nPer-job totals (post Claude audit — HONEST numbers):`);
  console.log(`  Total confirmed (per-job sum):  ${totalConfirmedPerJob}`);
  console.log(`  Total dropped (per-job sum):     ${totalDroppedPerJob} ← now preserved for FN analysis`);
  console.log(`  Total candidates (per-job sum):  ${totalCandidatesPerJob}`);
  console.log(`  Candidate+dropped / confirmed:    ${totalConfirmedPerJob > 0 ? ((totalCandidatesPerJob + totalDroppedPerJob) / totalConfirmedPerJob).toFixed(1) : '∞'} ← recall lever (Claude §9.8)`);

  // Static analysis layer stats (Claude §8)
  const staticStats = succeeded.map(r => ({
    url: r.url,
    findings: r.staticFindingsCount || 0,
    sinkHints: r.staticSinkHintsCount || 0,
    skipLLM: r.staticSkipLLM,
    timeMs: r.staticTimeMs || 0,
    analyzeTime: r.analyzeTime || 0,
  }));
  console.log(`\n--- STATIC-FIRST PIPELINE (Claude §8) ---`);
  const totalStaticFindings = staticStats.reduce((s, r) => s + r.findings, 0);
  const totalSinkHints = staticStats.reduce((s, r) => s + r.sinkHints, 0);
  const skipLLMCount = staticStats.filter(r => r.skipLLM).length;
  const avgStaticTime = staticStats.length > 0 ? staticStats.reduce((s, r) => s + r.timeMs, 0) / staticStats.length : 0;
  console.log(`  Static findings (gitleaks + sink-hints secrets): ${totalStaticFindings}`);
  console.log(`  Sink-hints found:                                ${totalSinkHints}`);
  console.log(`  LLM SKIPPED on:                                  ${skipLLMCount}/${staticStats.length} targets (no sink-hints)`);
  console.log(`  Avg static analysis time:                        ${avgStaticTime.toFixed(0)}ms (vs LLM ~250s)`);
  if (skipLLMCount > 0) {
    const savedCost = skipLLMCount * 0.84;
    const savedTime = skipLLMCount * 250;
    console.log(`  Cost saved by skipping LLM:                      $${savedCost.toFixed(2)}`);
    console.log(`  Time saved by skipping LLM:                      ${savedTime}s`);
  }

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
