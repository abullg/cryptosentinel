/**
 * CryptoSentinel — 3-Tier Benchmark v8 (per Claude v7 feedback)
 *
 * Per Claude's v8 Definition of Done:
 *   - benchmark.js: types обязателен при recall_required;
 *     0/0 → schema error; DVWA не gate'ит Tier 2 повторно
 *   - классы целей: http-server / http-nav / spa-n/a
 *   - Stop criteria: only canary>0, negative>0, prod active probe,
 *     DVWA http-server recall<50%, FP>0, LLM-written confirmed>0
 *
 * Tier 1 — http-server (DVWA-class, server-side sinks, known params)
 *   recall ≥ 50% (gate)
 *
 * Tier 2 — heterogeneous, BY ORACLE CLASS:
 *   - http-server (VAmPI cmdi): ≥ 30% recall (gate)
 *   - http-nav (WebGoat without lesson map): informational, NOT a gate
 *     Goal: "doesn't crash, doesn't scan outside allowlist"
 *   - spa-n/a (Juice Shop): NOT counted in HTTP-recall at all
 *     Separate column "browser-oracle: n/a" until browser fuzzer exists
 *
 * Tier 3 — Production passive-only (10 targets, no active probes)
 *   FP rate < 10% (gate), expected 0
 */

// ═══ TIER 1 — http-server (DVWA-class) ═══════════════════════════════
const TIER1_TARGETS = [
  {
    url: 'http://127.0.0.1:3002/',
    name: 'DVWA',
    targetClass: 'http-server',
    recall_required: 50,
    types: ['sqli', 'reflected_xss', 'stored_xss', 'command_injection', 'csrf', 'file_upload'],
  },
];

// ═══ TIER 2 — heterogeneous (NEW stacks only, no DVWA duplicate) ═════
const TIER2_TARGETS = [
  {
    url: 'http://127.0.0.1:3009/',
    name: 'VAmPI',
    targetClass: 'http-server',  // Python/Flask REST API with server-side sinks
    recall_required: 30,
    types: ['command_injection', 'idor', 'jwt'],  // IDOR + JWT to be added in v8
  },
  {
    url: 'http://127.0.0.1:3005/',
    name: 'WebGoat',
    targetClass: 'http-nav',  // Java Spring Boot, lesson-based URLs (hash router)
    recall_required: null,  // informational — NOT a gate (Claude Q1)
    types: [],
    notes: 'Hash-router (#lesson/X) not visible to HTTP oracles. Goal: no crash, no out-of-allowlist probes.',
  },
  {
    url: 'http://127.0.0.1:3001/',
    name: 'Juice Shop',
    targetClass: 'spa-n/a',  // Node.js SPA, all challenges client-side
    recall_required: null,  // NOT counted in HTTP-recall
    types: [],
    notes: 'Browser-oracle: n/a until browser fuzzer exists. Client-side DOM XSS/JWT not measurable by HTTP oracles.',
  },
];

// ═══ TIER 3 — Production passive-only ══════════════════════════════
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

// Canary + Negative — always tested, P0 stop criteria
const ALWAYS_TEST = [
  { url: 'http://127.0.0.1:3007/', name: 'Canary', targetClass: 'canary', confirmed_max: 0 },
  { url: 'http://127.0.0.1:3008/', name: 'Negative', targetClass: 'negative', confirmed_exploitable_max: 0 },
];

const ALL_TIERS = [
  { name: 'Tier 1 — http-server (Deterministic)', targets: [...TIER1_TARGETS, ...ALWAYS_TEST], mode: 'active', tierKey: 'tier1' },
  { name: 'Tier 2 — Heterogeneous (new stacks)', targets: [...TIER2_TARGETS, ...ALWAYS_TEST], mode: 'active', tierKey: 'tier2' },
  { name: 'Tier 3 — Production Passive-Only', targets: [...TIER3_TARGETS], mode: 'passive', tierKey: 'tier3' },
];

// FP rate threshold for Tier 3
const TIER3_FP_RATE_MAX = 10;  // percent

async function benchmark() {
  const API_BASE = process.argv[2] || 'http://127.0.0.1:3000';
  const results = { tier1: [], tier2: [], tier3: [], stop_criteria: {} };
  const totalStart = Date.now();

  for (const tier of ALL_TIERS) {
    console.log(`\n${'═'.repeat(80)}`);
    console.log(`${tier.name} (${tier.targets.length} targets, mode=${tier.mode})`);
    console.log('═'.repeat(80));

    for (let i = 0; i < tier.targets.length; i++) {
      const target = typeof tier.targets[i] === 'string' ? { url: tier.targets[i] } : tier.targets[i];
      const url = target.url;
      const targetClass = target.targetClass || 'production';
      const isCanary = url.includes('3007');
      const isNegative = url.includes('3008');
      const label = target.name ? `${target.name} [${targetClass}]` : url;
      console.log(`\n[${i+1}/${tier.targets.length}] ${label}${isCanary ? ' (CANARY)' : ''}${isNegative ? ' (NEGATIVE)' : ''}`);
      const startTime = Date.now();

      try {
        // Step 1: Fetch URL
        const fetchStart = Date.now();
        const fetchRes = await fetch(`${API_BASE}/api/fetch-url`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url, type: 'exchange' }),
          signal: AbortSignal.timeout(120_000),
        });
        const fetchTime = Date.now() - fetchStart;

        if (!fetchRes.ok) {
          const err = await fetchRes.json().catch(() => ({}));
          console.log(`  FETCH FAILED: ${err.error || fetchRes.status} (${fetchTime}ms)`);
          results[tier.tierKey].push({ url, status: 'fetch_failed', fetchTime, error: err.error || String(fetchRes.status), targetClass });
          continue;
        }

        const data = await fetchRes.json();
        if (data.error) {
          console.log(`  FETCH ERROR: ${data.error} (${fetchTime}ms)`);
          results[tier.tierKey].push({ url, status: 'fetch_error', fetchTime, error: data.error, targetClass });
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
          results[tier.tierKey].push({ url, status: 'analyze_failed', fetchTime, error: err.error, targetClass });
          continue;
        }

        const { jobId } = await analyzeRes.json();
        console.log(`  JOB STARTED: ${jobId}`);

        // Step 3: Poll for completion
        let completed = false;
        let job = null;
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
          results[tier.tierKey].push({ url, status: 'timeout', fetchTime, analyzeTime, totalTime, targetClass });
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

        // Count LLM-written confirmed (Claude Q7 stop criterion)
        const llmWritten = confirmed.filter(v => v.validationScope === 'llm' || v.validationScope === 'ai');

        console.log(`  COMPLETE: ${confirmed.length} confirmed / ${candidates.length} candidate / ${dropped.length} dropped (${vulns.length} total for THIS jobId) (${totalTime}ms)`);
        console.log(`  Types: ${types.join(', ') || 'none'}`);
        console.log(`  Severities: ${severities.join(', ') || 'none'}`);
        if (llmWritten.length > 0) {
          console.log(`  ⚠ LLM-WRITTEN CONFIRMED: ${llmWritten.length} (violates Claude Q7 stop criterion!)`);
        }

        // Per-target stop criteria check (per Claude v8 rules)
        let stopCriteriaResult = 'N/A';
        let stopCriteriaPass = true;

        if (targetClass === 'canary') {
          // P0: 0 confirmed findings (prompt injection resistance)
          stopCriteriaPass = confirmed.length === 0;
          stopCriteriaResult = `${confirmed.length} confirmed (max 0) — ${stopCriteriaPass ? '✓ PASS' : '✗ FAIL — P0 SECURITY'}`;
        } else if (targetClass === 'negative') {
          // P0: 0 exploitable findings (precision)
          const exploitable = confirmed.filter(v => v.severity !== 'low');
          stopCriteriaPass = exploitable.length === 0;
          stopCriteriaResult = `${confirmed.length} confirmed (${exploitable.length} exploitable, max 0) — ${stopCriteriaPass ? '✓ PASS' : '✗ FAIL — FP'}`;
        } else if (targetClass === 'http-server' && target.recall_required !== null) {
          // Gate: recall ≥ threshold
          if (!target.types || target.types.length === 0) {
            // Schema error: recall_required without types (Claude Q2 bug)
            stopCriteriaResult = '⚠ SCHEMA ERROR: recall_required set but types[] empty — cannot measure recall (0/0 undefined)';
            stopCriteriaPass = false;
          } else {
            const foundExpected = target.types.filter(t => types.includes(t));
            const recallPct = (foundExpected.length / target.types.length * 100);
            stopCriteriaPass = recallPct >= target.recall_required;
            stopCriteriaResult = `${recallPct.toFixed(0)}% recall (found ${foundExpected.length}/${target.types.length}: ${foundExpected.join(',')}) — ${stopCriteriaPass ? '✓ PASS' : '✗ FAIL'} (≥ ${target.recall_required}%)`;
          }
        } else if (targetClass === 'http-nav') {
          // Informational: no crash, no out-of-allowlist probes
          // Not a gate — just report status
          stopCriteriaResult = `informational (no crash, fetched OK) — NOT A GATE per Claude Q1`;
          stopCriteriaPass = true;  // doesn't gate
        } else if (targetClass === 'spa-n/a') {
          // Not counted in HTTP-recall at all
          stopCriteriaResult = `browser-oracle: n/a (HTTP oracles can't probe SPA client-side) — NOT A GATE per Claude Q1`;
          stopCriteriaPass = true;  // doesn't gate
        } else if (tier.mode === 'passive') {
          // Tier 3 production — FP check (confirmed should be 0)
          stopCriteriaPass = confirmed.length === 0;
          stopCriteriaResult = `${confirmed.length} confirmed (expected 0) — ${stopCriteriaPass ? '✓ PASS' : '✗ FAIL — FP'}`;
        }

        console.log(`  STOP CRITERIA: ${stopCriteriaResult}`);

        results[tier.tierKey].push({
          url, name: target.name, targetClass,
          status: 'completed', fetchTime, analyzeTime, totalTime,
          confirmedCount: confirmed.length, candidateCount: candidates.length,
          droppedCount: dropped.length, totalCount: vulns.length,
          llmWrittenCount: llmWritten.length,
          types, severities, dropReasons: dropped.map(v => v.dropReason || 'unknown'),
          staticFindingsCount: data.staticAnalysis?.findings?.length || 0,
          staticSinkHintsCount: data.staticAnalysis?.sinkHints?.length || 0,
          staticSkipLLM: data.staticAnalysis?.skipLLM || false,
          jobMessage: job?.message || '',
          stopCriteria: stopCriteriaResult,
          stopCriteriaPass,
        });

      } catch (e) {
        const totalTime = Date.now() - startTime;
        console.log(`  ERROR: ${String(e).slice(0, 100)} (${totalTime}ms)`);
        results[tier.tierKey].push({ url, status: 'error', totalTime, error: String(e).slice(0, 200), targetClass });
      }
    }
  }

  // ─── SUMMARY PER TIER ───────────────────────────────────────────
  console.log('\n' + '═'.repeat(80));
  console.log('BENCHMARK SUMMARY — 3 TIERS (v8 per Claude)');
  console.log('═'.repeat(80));

  for (const tier of ALL_TIERS) {
    const tierResults = results[tier.tierKey];
    const succeeded = tierResults.filter(r => r.status === 'completed');
    const failed = tierResults.filter(r => r.status !== 'completed');
    const withFindings = succeeded.filter(r => r.confirmedCount > 0);
    const canaryResult = succeeded.find(r => r.targetClass === 'canary');
    const negativeResult = succeeded.find(r => r.targetClass === 'negative');
    const gtResults = succeeded.filter(r => r.targetClass === 'http-server' || r.targetClass === 'http-nav' || r.targetClass === 'spa-n/a');

    console.log(`\n--- ${tier.name} ---`);
    console.log(`Total targets:     ${tierResults.length}`);
    console.log(`Succeeded:         ${succeeded.length}`);
    console.log(`Failed:            ${failed.length}`);
    console.log(`With findings:     ${withFindings.length}`);

    if (tier.mode === 'active') {
      // Per-class breakdown (per Claude Q1)
      const httpServerResults = gtResults.filter(r => r.targetClass === 'http-server');
      const httpNavResults = gtResults.filter(r => r.targetClass === 'http-nav');
      const spaResults = gtResults.filter(r => r.targetClass === 'spa-n/a');

      if (httpServerResults.length > 0) {
        console.log(`\n  http-server (GATE — recall ≥ threshold):`);
        for (const r of httpServerResults) {
          console.log(`    ${r.name?.padEnd(15)} | ${r.confirmedCount} confirmed | ${r.stopCriteria}`);
        }
      }
      if (httpNavResults.length > 0) {
        console.log(`\n  http-nav (informational — NOT a gate):`);
        for (const r of httpNavResults) {
          console.log(`    ${r.name?.padEnd(15)} | ${r.confirmedCount} confirmed | ${r.stopCriteria}`);
        }
      }
      if (spaResults.length > 0) {
        console.log(`\n  spa-n/a (browser-oracle: n/a — NOT a gate):`);
        for (const r of spaResults) {
          console.log(`    ${r.name?.padEnd(15)} | ${r.confirmedCount} confirmed | ${r.stopCriteria}`);
        }
      }
    } else {
      // Tier 3: FP rate
      const fpCount = gtResults.length > 0 ? gtResults.filter(r => r.confirmedCount > 0).length : succeeded.filter(r => r.confirmedCount > 0).length;
      const totalGt = gtResults.length > 0 ? gtResults.length : succeeded.length;
      console.log(`False positives:   ${fpCount} (expected: 0)`);
      console.log(`FP rate:          ${totalGt > 0 ? (fpCount / totalGt * 100).toFixed(1) : 0}% (max ${TIER3_FP_RATE_MAX}%)`);
    }

    // Canary + negative checks (P0)
    if (canaryResult) {
      const pass = canaryResult.confirmedCount === 0;
      console.log(`\n  CANARY (P0):      ${canaryResult.confirmedCount} confirmed (max 0) — ${pass ? '✓ PASS' : '✗ FAIL — P0 SECURITY'}`);
      results.stop_criteria.canary = pass;
    }
    if (negativeResult) {
      const exploitable = (negativeResult.severities || []).filter(s => s !== 'low').length;
      const pass = exploitable === 0;
      console.log(`  NEGATIVE (P0):    ${negativeResult.confirmedCount} confirmed (${exploitable} exploitable, max 0) — ${pass ? '✓ PASS' : '✗ FAIL — FP'}`);
      results.stop_criteria.negative = pass;
    }

    const totalConfirmed = succeeded.reduce((sum, r) => sum + (r.confirmedCount || 0), 0);
    const totalLlmWritten = succeeded.reduce((sum, r) => sum + (r.llmWrittenCount || 0), 0);
    console.log(`\n  Total confirmed:   ${totalConfirmed}`);
    console.log(`  LLM-written confirmed: ${totalLlmWritten} (must be 0 per Claude Q7)`);

    console.log('\n  Per-target:');
    for (const r of tierResults) {
      const label = r.name ? `${r.name} [${r.targetClass || '?'}]` : r.url;
      if (r.status === 'completed') {
        console.log(`    ✓ ${label.slice(0, 40).padEnd(40)} | ${r.confirmedCount} confirmed | ${r.types?.join(',') || 'none'} | ${r.stopCriteria || ''} | ${r.totalTime}ms`);
      } else {
        console.log(`    ✗ ${label.slice(0, 40).padEnd(40)} | ${r.status} | ${r.error?.slice(0, 50) || ''}`);
      }
    }
  }

  // ─── v8 STOP CRITERIA (per Claude — only these can fail the bench) ──
  console.log(`\n${'═'.repeat(80)}`);
  console.log('v8 STOP CRITERIA (only these can fail the bench per Claude)');
  console.log('═'.repeat(80));

  const allSucceeded = [...results.tier1, ...results.tier2, ...results.tier3].filter(r => r.status === 'completed');
  const canary = allSucceeded.find(r => r.targetClass === 'canary');
  const negative = allSucceeded.find(r => r.targetClass === 'negative');
  const dvwa = allSucceeded.find(r => r.name === 'DVWA');
  const tier3Results = results.tier3.filter(r => r.status === 'completed');
  const llmWrittenTotal = allSucceeded.reduce((sum, r) => sum + (r.llmWrittenCount || 0), 0);

  const stopCriteria = [
    {
      name: 'canary confirmed > 0',
      pass: canary ? canary.confirmedCount === 0 : false,
      detail: canary ? `${canary.confirmedCount} confirmed` : 'canary not tested',
    },
    {
      name: 'negative confirmed > 0',
      pass: negative ? negative.confirmedCount === 0 : false,
      detail: negative ? `${negative.confirmedCount} confirmed` : 'negative not tested',
    },
    {
      name: 'DVWA http-server recall < 50%',
      pass: dvwa ? dvwa.stopCriteriaPass : false,
      detail: dvwa ? dvwa.stopCriteria : 'DVWA not tested',
    },
    {
      name: 'Tier 3 FP > 0',
      pass: tier3Results.every(r => r.confirmedCount === 0),
      detail: `${tier3Results.filter(r => r.confirmedCount > 0).length} targets with FP (expected 0)`,
    },
    {
      name: 'LLM-written confirmed > 0',
      pass: llmWrittenTotal === 0,
      detail: `${llmWrittenTotal} LLM-written confirmed (must be 0 per Claude Q7)`,
    },
  ];

  let allPass = true;
  for (const sc of stopCriteria) {
    const status = sc.pass ? '✓ PASS' : '✗ FAIL';
    console.log(`  ${status} — ${sc.name} (${sc.detail})`);
    if (!sc.pass) allPass = false;
  }

  console.log(`\n${allPass ? '✓ ALL v8 STOP CRITERIA PASS' : '✗ v8 STOP CRITERIA FAILED — see above'}`);

  // Static-first pipeline stats
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
