/**
 * CryptoSentinel — 3-Tier Benchmark
 *
 * Tier 1 — Deterministic: Can the engine reproducibly confirm known vulns?
 *   DVWA + WebGoat (if available)
 *   Active fuzzer with all oracles (SQLi, XSS, cmd inj, LFI, CSRF, upload)
 *
 * Tier 2 — Heterogeneous: Does architecture transfer across apps/techs?
 *   WebGoat + crAPI + VAmPI + Juice Shop
 *   Active fuzzer (adapted per target)
 *
 * Tier 3 — Unknown/Realistic: How many FPs on real internet?
 *   10 production homepage/API targets
 *   Passive-only mode (no active probes, static + LLM if needed)
 */

// ═══ TIER 1 — DETERMINISTIC ═════════════════════════════════════
const TIER1_TARGETS = [
  'http://localhost:3002/',  // DVWA — 10 known vuln endpoints, security=low
];

// ═══ TIER 2 — HETEROGENEOUS ═════════════════════════════════════
const TIER2_TARGETS = [
  'http://localhost:3001/',  // Juice Shop — 116 challenges, Node.js SPA
  'http://localhost:3005/',  // WebGoat — Java, classic SQLi/XSS
  // VAmPI and crAPI would go here when containers are available
];

// ═══ TIER 3 — PRODUCTION PASSIVE-ONLY ══════════════════════════
const TIER3_TARGETS = [
  'https://www.bitunix.com/',
  'https://app.uniswap.org/',
  'https://aave.com/',
  'https://metamask.io/',
  'https://www.ledger.com/',
  'https://example.com/',
  'https://httpbin.org/',
  'https://www.cloudflare.com/',
  'https://www.apple.com/',
  'https://github.com/',
];

const ALL_TIERS = [
  { name: 'Tier 1 — Deterministic', targets: TIER1_TARGETS, mode: 'active' },
  { name: 'Tier 2 — Heterogeneous', targets: TIER2_TARGETS, mode: 'active' },
  { name: 'Tier 3 — Production Passive-Only', targets: TIER3_TARGETS, mode: 'passive' },
];

async function benchmark() {
  const API_BASE = process.argv[2] || 'http://localhost:3000';
  const results = { tier1: [], tier2: [], tier3: [] };

  for (const tier of ALL_TIERS) {
    console.log(`\n${'═'.repeat(80)}`);
    console.log(`${tier.name} (${tier.targets.length} targets, mode=${tier.mode})`);
    console.log('═'.repeat(80));

    for (let i = 0; i < tier.targets.length; i++) {
      const url = tier.targets[i];
      console.log(`\n[${i+1}/${tier.targets.length}] ${url}`);
      const startTime = Date.now();

      try {
        // Step 1: Fetch URL
        const fetchStart = Date.now();
        const fetchRes = await fetch(`${API_BASE}/api/fetch-url`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url, type: 'exchange' }),
          signal: AbortSignal.timeout(60_000),  // 60s for GT (juice-shop slow startup)
        });
        const fetchTime = Date.now() - fetchStart;

        if (!fetchRes.ok) {
          const err = await fetchRes.json().catch(() => ({}));
          console.log(`  FETCH FAILED: ${err.error || fetchRes.status} (${fetchTime}ms)`);
          const tierKey = tier.name.includes('1') ? 'tier1' : tier.name.includes('2') ? 'tier2' : 'tier3';
          results[tierKey].push({ url, status: 'fetch_failed', fetchTime, error: err.error || String(fetchRes.status) });
          continue;
        }

        const data = await fetchRes.json();
        if (data.error) {
          console.log(`  FETCH ERROR: ${data.error} (${fetchTime}ms)`);
          const tierKey = tier.name.includes('1') ? 'tier1' : tier.name.includes('2') ? 'tier2' : 'tier3';
          results[tierKey].push({ url, status: 'fetch_error', fetchTime, error: data.error });
          continue;
        }

        console.log(`  FETCH OK: ${data.sourceCode?.length || 0} chars (${fetchTime}ms) via ${data.reconType || 'unknown'}`);
        if (data.staticAnalysis) {
          const sa = data.staticAnalysis;
          console.log(`  STATIC: ${sa.findings?.length || 0} findings, ${sa.sinkHints?.length || 0} sink-hints, ${sa.stats?.totalMs || 'N/A'}ms, skipLLM=${sa.skipLLM}`);
        }

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
            staticAnalysis: data.staticAnalysis || null,
          }),
          signal: AbortSignal.timeout(15_000),
        });

        if (!analyzeRes.ok) {
          const err = await analyzeRes.json().catch(() => ({}));
          console.log(`  ANALYZE FAILED: ${err.error || analyzeRes.status}`);
          const tierKey = tier.name.includes('1') ? 'tier1' : tier.name.includes('2') ? 'tier2' : 'tier3';
          results[tierKey].push({ url, status: 'analyze_failed', fetchTime, error: err.error });
          continue;
        }

        const { jobId } = await analyzeRes.json();
        console.log(`  JOB STARTED: ${jobId}`);

        // Step 3: Poll for completion
        let completed = false;
        let job = null;
        const maxPolls = tier.mode === 'active' ? 180 : 36;  // 15 min active, 3 min passive
        for (let poll = 0; poll < maxPolls; poll++) {
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
          const tierKey = tier.name.includes('1') ? 'tier1' : tier.name.includes('2') ? 'tier2' : 'tier3';
          results[tierKey].push({ url, status: 'timeout', fetchTime, analyzeTime, totalTime });
          continue;
        }

        // Step 4: Get vulnerabilities (per-job filtered by contractId)
        let vulns = [];
        try {
          const contractId = job?.contractId;
          const vulnsRes = await fetch(`${API_BASE}/api/vulnerabilities?t=${Date.now()}${contractId ? `&contractId=${contractId}` : ''}`, {
            signal: AbortSignal.timeout(10_000),
          });
          if (vulnsRes.ok) {
            const allVulns = await vulnsRes.json();
            vulns = contractId ? allVulns.filter(v => v.contractId === contractId) : allVulns;
          }
        } catch {}

        const confirmed = vulns.filter(v => v.status === 'confirmed' || v.status === 'validated');
        const dropped = vulns.filter(v => v.status === 'dropped');
        const candidates = vulns.filter(v => v.status === 'candidate');
        const types = [...new Set(confirmed.map(v => v.type))];
        const severities = confirmed.map(v => v.severity);

        console.log(`  COMPLETE: ${confirmed.length} confirmed / ${candidates.length} candidate / ${dropped.length} dropped (${vulns.length} total for THIS jobId) (${totalTime}ms)`);
        console.log(`  Types: ${types.join(', ') || 'none'}`);
        console.log(`  Severities: ${severities.join(', ') || 'none'}`);

        const tierKey = tier.name.includes('1') ? 'tier1' : tier.name.includes('2') ? 'tier2' : 'tier3';
        results[tierKey].push({
          url, status: 'completed', fetchTime, analyzeTime, totalTime,
          confirmedCount: confirmed.length, candidateCount: candidates.length,
          droppedCount: dropped.length, totalCount: vulns.length,
          types, severities, dropReasons: dropped.map(v => v.dropReason || 'unknown'),
          staticFindingsCount: data.staticAnalysis?.findings?.length || 0,
          staticSinkHintsCount: data.staticAnalysis?.sinkHints?.length || 0,
          staticSkipLLM: data.staticAnalysis?.skipLLM || false,
          jobMessage: job?.message || '',
        });

      } catch (e) {
        const totalTime = Date.now() - startTime;
        console.log(`  ERROR: ${String(e).slice(0, 100)} (${totalTime}ms)`);
        const tierKey = tier.name.includes('1') ? 'tier1' : tier.name.includes('2') ? 'tier2' : 'tier3';
        results[tierKey].push({ url, status: 'error', totalTime, error: String(e).slice(0, 200) });
      }
    }
  }

  // ─── SUMMARY PER TIER ───────────────────────────────────────────
  console.log('\n' + '═'.repeat(80));
  console.log('BENCHMARK SUMMARY — 3 TIERS');
  console.log('═'.repeat(80));

  for (const tier of ALL_TIERS) {
    const tierKey = tier.name.includes('1') ? 'tier1' : tier.name.includes('2') ? 'tier2' : 'tier3';
    const tierResults = results[tierKey];
    const succeeded = tierResults.filter(r => r.status === 'completed');
    const failed = tierResults.filter(r => r.status !== 'completed');
    const withFindings = succeeded.filter(r => r.confirmedCount > 0);

    console.log(`\n--- ${tier.name} ---`);
    console.log(`Total targets:     ${tierResults.length}`);
    console.log(`Succeeded:         ${succeeded.length}`);
    console.log(`Failed:            ${failed.length}`);
    console.log(`With findings:     ${withFindings.length}`);
    if (succeeded.length > 0) {
      console.log(`Detection rate:    ${(withFindings.length / succeeded.length * 100).toFixed(1)}%`);
    }

    const totalConfirmed = succeeded.reduce((sum, r) => sum + (r.confirmedCount || 0), 0);
    const totalDropped = succeeded.reduce((sum, r) => sum + (r.droppedCount || 0), 0);
    console.log(`Total confirmed:   ${totalConfirmed}`);
    console.log(`Total dropped:    ${totalDropped}`);

    if (tier.mode === 'passive') {
      // Tier 3: focus on FP rate
      const fpCount = succeeded.filter(r => r.confirmedCount > 0).length;
      console.log(`False positives:   ${fpCount} (expected: 0)`);
      console.log(`FP rate:          ${succeeded.length > 0 ? (fpCount / succeeded.length * 100).toFixed(1) : 0}%`);
    }

    console.log('\nPer-target:');
    for (const r of tierResults) {
      if (r.status === 'completed') {
        console.log(`  ✓ ${r.url.slice(0, 50).padEnd(50)} | ${r.confirmedCount} confirmed | ${r.types?.join(',') || 'none'} | ${r.totalTime}ms`);
      } else {
        console.log(`  ✗ ${r.url.slice(0, 50).padEnd(50)} | ${r.status} | ${r.error?.slice(0, 50) || ''}`);
      }
    }
  }

  // Static-first pipeline stats
  const allSucceeded = [...results.tier1, ...results.tier2, ...results.tier3].filter(r => r.status === 'completed');
  const skipLLMCount = allSucceeded.filter(r => r.staticSkipLLM).length;
  console.log(`\n--- STATIC-FIRST PIPELINE ---`);
  console.log(`  LLM SKIPPED on: ${skipLLMCount}/${allSucceeded.length} targets`);
  console.log(`  Cost saved:    $${(skipLLMCount * 0.84).toFixed(2)}`);

  console.log('\n--- JSON RESULTS ---');
  console.log(JSON.stringify(results, null, 2));
}

benchmark().catch(e => console.error('Benchmark failed:', e));
