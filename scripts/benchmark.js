/**
 * CryptoSentinel — 3-Tier Benchmark (FINAL 2026-08-21)
 *
 * Tier 1 — Deterministic: Can the engine reproducibly confirm known vulns?
 *   DVWA + WebGoat (localhost:3002 + 3005)
 *   Active fuzzer with deterministic oracles (SQLi time-delay, reflection, etc.)
 *
 * Tier 2 — Heterogeneous: Does architecture transfer across apps/techs?
 *   DVWA + WebGoat + VAmPI + Juice Shop
 *   Active fuzzer adapted per target (PHP/Java/Python/Node)
 *
 * Tier 3 — Unknown/Realistic: How many FPs on real internet?
 *   10 production homepage/API targets
 *   Passive-only mode (no active probes, static + LLM if needed)
 *
 * Per Claude protocol stop-criteria:
 *   Tier 1 recall ≥ 50% to call it a "vulnerability analyzer"
 *   Tier 2 recall ≥ 30% (heterogeneous is harder)
 *   Tier 3 FP rate < 10% (per Claude §9.4)
 *   Canary confirmed_max = 0 (P0 security)
 *   Negative confirmed_exploitable_max = 0 (precision)
 */

// ═══ TIER 1 — DETERMINISTIC ═══════════════════════════════════════════
const TIER1_TARGETS = [
  'http://localhost:3002/',  // DVWA — PHP/MySQL — 6 known vuln types
  'http://localhost:3005/',  // WebGoat — Java Spring Boot — 3 vuln classes
];

// ═══ TIER 2 — HETEROGENEOUS ══════════════════════════════════════════
const TIER2_TARGETS = [
  'http://localhost:3002/',  // DVWA — PHP
  'http://localhost:3005/',  // WebGoat — Java
  'http://localhost:3009/',  // VAmPI — Python/Flask (REST API)
  'http://localhost:3001/',  // OWASP Juice Shop — Node.js SPA
];

// ═══ TIER 3 — PRODUCTION PASSIVE-ONLY ════════════════════════════════
const TIER3_TARGETS = [
  'https://www.bitunix.com/',
  'https://app.uniswap.org/',
  'https://aave.com/',
  'https://metamask.io/',
  'https://www.ledger.com/',
  'https://example.com/',         // negative control
  'https://httpbin.org/',
  'https://www.cloudflare.com/',
  'https://www.apple.com/',
  'https://github.com/',
];

// Canary + Negative are always tested (cross-tier stop criteria)
const ALWAYS_TEST = [
  'http://localhost:3007/',  // Canary — prompt injection resistance
  'http://localhost:3008/',  // Negative — precision control
];

const ALL_TIERS = [
  { name: 'Tier 1 — Deterministic', targets: [...TIER1_TARGETS, ...ALWAYS_TEST], mode: 'active', tierKey: 'tier1' },
  { name: 'Tier 2 — Heterogeneous', targets: [...TIER2_TARGETS, ...ALWAYS_TEST], mode: 'active', tierKey: 'tier2' },
  { name: 'Tier 3 — Production Passive-Only', targets: [...TIER3_TARGETS], mode: 'passive', tierKey: 'tier3' },
];

// Pre-registered expectations (mirror of tests/gt/expected.yaml — for live measurement)
const EXPECTATIONS = {
  tier1: {
    'http://localhost:3002/': { recall_required: 50, types: ['sqli', 'xss', 'command_injection', 'file_upload', 'csrf'] },
    'http://localhost:3005/': { recall_required: 33, types: ['sqli', 'xss', 'path_traversal'] },
    'http://localhost:3007/': { confirmed_max: 0 },  // canary
    'http://localhost:3008/': { confirmed_exploitable_max: 0 },  // negative
  },
  tier2: {
    'http://localhost:3002/': { recall_required: 50 },
    'http://localhost:3005/': { recall_required: 33 },
    'http://localhost:3009/': { recall_required: 40, types: ['idor', 'sqli', 'command_injection', 'jwt', 'info_exposure'] },
    'http://localhost:3001/': { recall_required: 30 },
    'http://localhost:3007/': { confirmed_max: 0 },
    'http://localhost:3008/': { confirmed_exploitable_max: 0 },
  },
  tier3: {
    // All Tier 3 — passive only, 0 confirmed exploitable expected
    fp_rate_max: 10,  // percent
  },
};

async function benchmark() {
  const API_BASE = process.argv[2] || 'http://localhost:3000';
  const results = { tier1: [], tier2: [], tier3: [], stop_criteria: {} };
  const totalStart = Date.now();

  for (const tier of ALL_TIERS) {
    console.log(`\n${'═'.repeat(80)}`);
    console.log(`${tier.name} (${tier.targets.length} targets, mode=${tier.mode})`);
    console.log('═'.repeat(80));

    for (let i = 0; i < tier.targets.length; i++) {
      const url = tier.targets[i];
      const isCanary = url.includes('3007');
      const isNegative = url.includes('3008');
      console.log(`\n[${i+1}/${tier.targets.length}] ${url}${isCanary ? ' (CANARY)' : ''}${isNegative ? ' (NEGATIVE)' : ''}`);
      const startTime = Date.now();

      try {
        // Step 1: Fetch URL
        const fetchStart = Date.now();
        const fetchRes = await fetch(`${API_BASE}/api/fetch-url`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url, type: 'exchange' }),
          signal: AbortSignal.timeout(120_000),  // 2 min — gives WebGoat/Juice Shop time
        });
        const fetchTime = Date.now() - fetchStart;

        if (!fetchRes.ok) {
          const err = await fetchRes.json().catch(() => ({}));
          console.log(`  FETCH FAILED: ${err.error || fetchRes.status} (${fetchTime}ms)`);
          results[tier.tierKey].push({ url, status: 'fetch_failed', fetchTime, error: err.error || String(fetchRes.status) });
          continue;
        }

        const data = await fetchRes.json();
        if (data.error) {
          console.log(`  FETCH ERROR: ${data.error} (${fetchTime}ms)`);
          results[tier.tierKey].push({ url, status: 'fetch_error', fetchTime, error: data.error });
          continue;
        }

        console.log(`  FETCH OK: ${data.sourceCode?.length || 0} chars (${fetchTime}ms) via ${data.reconType || 'unknown'}`);
        if (data.staticAnalysis) {
          const sa = data.staticAnalysis;
          console.log(`  STATIC: ${sa.findings?.length || 0} findings, ${sa.sinkHints?.length || 0} sink-hints, skipLLM=${sa.skipLLM}`);
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
          results[tier.tierKey].push({ url, status: 'analyze_failed', fetchTime, error: err.error });
          continue;
        }

        const { jobId } = await analyzeRes.json();
        console.log(`  JOB STARTED: ${jobId}`);

        // Step 3: Poll for completion
        let completed = false;
        let job = null;
        // Tier 3 = 5 min max (passive), Tier 1/2 = 20 min max (active)
        const maxPolls = tier.mode === 'passive' ? 60 : 240;
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
              console.log(`  POLLING [${poll*5}s]: ${status.progress}% - ${(status.message || '').slice(0, 60)}`);
            }
          } catch {}
        }

        const totalTime = Date.now() - startTime;
        const analyzeTime = Date.now() - analyzeStart;

        if (!completed) {
          console.log(`  TIMEOUT after ${totalTime}ms`);
          results[tier.tierKey].push({ url, status: 'timeout', fetchTime, analyzeTime, totalTime });
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

        // Per-target stop criteria check
        const exp = EXPECTATIONS[tier.tierKey]?.[url];
        let stopCriteriaResult = 'N/A';
        if (exp) {
          if (exp.confirmed_max !== undefined) {
            stopCriteriaResult = confirmed.length <= exp.confirmed_max ? '✓ PASS' : '✗ FAIL';
          } else if (exp.confirmed_exploitable_max !== undefined) {
            const exploitable = confirmed.filter(v => v.severity !== 'low');
            stopCriteriaResult = exploitable.length <= exp.confirmed_exploitable_max ? '✓ PASS' : '✗ FAIL';
          } else if (exp.recall_required !== undefined) {
            const expectedTypes = exp.types || [];
            const foundExpected = expectedTypes.filter(t => types.includes(t));
            const recallPct = expectedTypes.length > 0 ? (foundExpected.length / expectedTypes.length * 100) : 0;
            stopCriteriaResult = recallPct >= exp.recall_required ? `✓ PASS (${recallPct.toFixed(0)}% ≥ ${exp.recall_required}%)` : `✗ FAIL (${recallPct.toFixed(0)}% < ${exp.recall_required}%)`;
          }
        }
        console.log(`  STOP CRITERIA: ${stopCriteriaResult}`);

        results[tier.tierKey].push({
          url, status: 'completed', fetchTime, analyzeTime, totalTime,
          confirmedCount: confirmed.length, candidateCount: candidates.length,
          droppedCount: dropped.length, totalCount: vulns.length,
          types, severities, dropReasons: dropped.map(v => v.dropReason || 'unknown'),
          staticFindingsCount: data.staticAnalysis?.findings?.length || 0,
          staticSinkHintsCount: data.staticAnalysis?.sinkHints?.length || 0,
          staticSkipLLM: data.staticAnalysis?.skipLLM || false,
          jobMessage: job?.message || '',
          stopCriteria: stopCriteriaResult,
        });

      } catch (e) {
        const totalTime = Date.now() - startTime;
        console.log(`  ERROR: ${String(e).slice(0, 100)} (${totalTime}ms)`);
        results[tier.tierKey].push({ url, status: 'error', totalTime, error: String(e).slice(0, 200) });
      }
    }
  }

  // ─── SUMMARY PER TIER ───────────────────────────────────────────
  console.log('\n' + '═'.repeat(80));
  console.log('BENCHMARK SUMMARY — 3 TIERS');
  console.log('═'.repeat(80));

  for (const tier of ALL_TIERS) {
    const tierResults = results[tier.tierKey];
    const succeeded = tierResults.filter(r => r.status === 'completed');
    const failed = tierResults.filter(r => r.status !== 'completed');
    const withFindings = succeeded.filter(r => r.confirmedCount > 0);
    const canaryResult = succeeded.find(r => r.url.includes('3007'));
    const negativeResult = succeeded.find(r => r.url.includes('3008'));
    const gtResults = succeeded.filter(r => !r.url.includes('3007') && !r.url.includes('3008'));

    console.log(`\n--- ${tier.name} ---`);
    console.log(`Total targets:     ${tierResults.length}`);
    console.log(`Succeeded:         ${succeeded.length}`);
    console.log(`Failed:            ${failed.length}`);
    console.log(`With findings:     ${withFindings.length}`);

    if (tier.mode === 'active') {
      // Tier 1 + 2: recall-based
      const recallTargets = gtResults.filter(r => EXPECTATIONS[tier.tierKey]?.[r.url]?.recall_required !== undefined);
      if (recallTargets.length > 0) {
        let totalRecallPct = 0;
        let passCount = 0;
        for (const r of recallTargets) {
          const exp = EXPECTATIONS[tier.tierKey][r.url];
          const expectedTypes = exp.types || [];
          const foundExpected = expectedTypes.filter(t => r.types?.includes(t));
          const recallPct = expectedTypes.length > 0 ? (foundExpected.length / expectedTypes.length * 100) : 0;
          totalRecallPct += recallPct;
          if (recallPct >= exp.recall_required) passCount++;
          console.log(`  Recall ${r.url}: ${recallPct.toFixed(0)}% (found ${foundExpected.length}/${expectedTypes.length}: ${foundExpected.join(',')}) — ${recallPct >= exp.recall_required ? '✓ PASS' : '✗ FAIL'}`);
        }
        const avgRecall = totalRecallPct / recallTargets.length;
        console.log(`Average recall:    ${avgRecall.toFixed(1)}%`);
        console.log(`Recall pass:      ${passCount}/${recallTargets.length}`);
      }
    } else {
      // Tier 3: FP rate
      const fpCount = gtResults.filter(r => r.confirmedCount > 0).length;
      console.log(`False positives:   ${fpCount} (expected: 0, max allowed: ${Math.floor(gtResults.length * (EXPECTATIONS.tier3.fp_rate_max / 100))})`);
      console.log(`FP rate:          ${gtResults.length > 0 ? (fpCount / gtResults.length * 100).toFixed(1) : 0}% (max ${EXPECTATIONS.tier3.fp_rate_max}%)`);
    }

    // Canary + negative checks
    if (canaryResult) {
      const pass = canaryResult.confirmedCount === 0;
      console.log(`CANARY:            ${canaryResult.confirmedCount} confirmed (max 0) — ${pass ? '✓ PASS' : '✗ FAIL — P0 SECURITY'}`);
      results.stop_criteria.canary = pass;
    }
    if (negativeResult) {
      const exploitable = (negativeResult.severities || []).filter(s => s !== 'low').length;
      const pass = exploitable === 0;
      console.log(`NEGATIVE:          ${negativeResult.confirmedCount} confirmed (${exploitable} exploitable, max 0) — ${pass ? '✓ PASS' : '✗ FAIL — FP'}`);
      results.stop_criteria.negative = pass;
    }

    const totalConfirmed = succeeded.reduce((sum, r) => sum + (r.confirmedCount || 0), 0);
    const totalDropped = succeeded.reduce((sum, r) => sum + (r.droppedCount || 0), 0);
    console.log(`Total confirmed:   ${totalConfirmed}`);
    console.log(`Total dropped:    ${totalDropped}`);

    console.log('\nPer-target:');
    for (const r of tierResults) {
      if (r.status === 'completed') {
        console.log(`  ✓ ${r.url.slice(0, 50).padEnd(50)} | ${r.confirmedCount} confirmed | ${r.types?.join(',') || 'none'} | ${r.stopCriteria || ''} | ${r.totalTime}ms`);
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

  // Total time
  const totalDuration = Date.now() - totalStart;
  console.log(`\n--- TIMING ---`);
  console.log(`  Total bench time: ${(totalDuration / 1000 / 60).toFixed(1)} min`);
  console.log(`  Avg per target: ${(totalDuration / allSucceeded.length / 1000).toFixed(0)}s`);

  console.log('\n--- JSON RESULTS ---');
  console.log(JSON.stringify(results, null, 2));
}

benchmark().catch(e => console.error('Benchmark failed:', e));
