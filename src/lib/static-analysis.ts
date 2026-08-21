/**
 * Static analysis layer — nuclei + gitleaks + sink-hint scanner.
 *
 * Per Claude §8 (static-first redesign):
 *   "Вынести hygiene+secrets из LLM. 15/18 finding'ов + api_leak regex
 *    делаются без GLM. Цель: p50 static pass < 2s/host."
 *
 * This module runs DETERMINISTIC analyzers on HTML/JS content:
 *   1. gitleaks (external binary) — secret regex + entropy
 *   2. sink-hint scanner (in-process) — XSS/SSRF/SQLi/web3 sink catalog
 *
 * Nuclei runs separately on the URL (not on sourceCode) — it makes HTTP
 * requests to the target. We invoke it from /api/fetch-url.
 *
 * Findings from this layer are HIGH-CONFIDENCE (deterministic, no LLM hallucination).
 * They get saved as status='confirmed' directly — no validation needed.
 *
 * If sink-hints are found → LLM is invoked with ONLY the sink context (≤4K chars),
 * not the full 32K sourceCode. This is 8x cheaper and 8x faster.
 * If no sink-hints → LLM is SKIPPED entirely.
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
import { writeFile, mkdir, rm, mkdtemp } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { scanSinkHints, buildLLMContextFromHints, type SinkHint } from './sink-hints';

const execFileAsync = promisify(execFile);

export interface StaticFinding {
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  evidence: string;        // matched string / pattern
  location: string;        // file:line or URL or "sourceCode:offset"
  source: 'gitleaks' | 'sink-hints' | 'nuclei';
  confidence: number;      // 0-1, deterministic = 0.95+
}

export interface StaticAnalysisResult {
  findings: StaticFinding[];
  sinkHints: SinkHint[];
  llmContext: string;        // pre-built ≤4K context for LLM (or '' if no hints)
  skipLLM: boolean;          // true if no sink-hints → LLM should be skipped
  stats: {
    gitleaksMs: number;
    sinkHintsMs: number;
    totalMs: number;
    sourceCodeChars: number;
    truncatedChars: number;   // chars beyond 30K cap
    truncatedPct: number;
  };
}

const STATIC_TIMEOUT_MS = 5_000;  // hard cap per analyzer

/**
 * Run static analysis on fetched sourceCode.
 *
 * @param sourceCode HTML + JS bundle content (already capped to ~32K by fetch-url)
 * @param targetUrl   Original URL (for logging/context)
 */
export async function runStaticAnalysis(
  sourceCode: string,
  targetUrl: string,
): Promise<StaticAnalysisResult> {
  const t0 = Date.now();
  const findings: StaticFinding[] = [];

  // ─── 1. Save sourceCode to temp file for gitleaks ───
  let tmpDir: string | null = null;
  let gitleaksMs = 0;
  try {
    tmpDir = await mkdtemp(join(tmpdir(), 'cs-static-'));
    const htmlFile = join(tmpDir, 'page.html');
    await writeFile(htmlFile, sourceCode, 'utf-8');

    // ─── 2. Run gitleaks on saved file ───
    const gitleaksT0 = Date.now();
    try {
      const { stdout } = await execFileAsync(
        'gitleaks',
        ['detect', '--no-git', '--source', tmpDir, '--report-format', 'json', '--report-path', '-'],
        { timeout: STATIC_TIMEOUT_MS, maxBuffer: 1024 * 1024 },
      );
      gitleaksMs = Date.now() - gitleaksT0;

      // Parse gitleaks JSON output
      if (stdout && stdout.trim()) {
        const gitleaksFindings = JSON.parse(stdout);
        for (const f of gitleaksFindings) {
          // Skip placeholders
          const matchedValue = f.Secret || f.Match || '';
          if (/^(sk-test|test|example|demo|placeholder|changeme|your[_-]?api|foo|bar|xxx|yyy|aaa|00000000|example\.com)/i.test(matchedValue)) {
            continue;
          }
          findings.push({
            type: 'api_leak',
            severity: 'critical',
            title: `${f.RuleID || f.Description || 'Hardcoded secret'} detected`,
            description: `gitleaks rule "${f.RuleID}" matched: ${matchedValue.slice(0, 4)}...${matchedValue.slice(-4)} [len=${matchedValue.length}]`,
            evidence: `prefix=${matchedValue.slice(0, 4)} suffix=${matchedValue.slice(-4)} length=${matchedValue.length}`,
            location: `${f.File}:${f.StartLine || '?'}`,
            source: 'gitleaks',
            confidence: 0.97,
          });
        }
      }
    } catch (e: any) {
      gitleaksMs = Date.now() - gitleaksT0;
      // gitleaks returns non-zero exit code when findings are found (quirk)
      // or if it timed out. Either way, log and continue.
      if (e.code === 'ENOENT') {
        // gitleaks not installed — skip silently (sink-hints still run)
        console.warn('[static-analysis] gitleaks not installed — install via install-static-tools.yml workflow');
      } else if (e.killed) {
        console.warn(`[static-analysis] gitleaks timed out after ${STATIC_TIMEOUT_MS}ms`);
      } else if (e.stdout) {
        // Findings found — parse stdout despite non-zero exit
        try {
          const gitleaksFindings = JSON.parse(e.stdout);
          for (const f of gitleaksFindings) {
            const matchedValue = f.Secret || f.Match || '';
            if (/^(sk-test|test|example|demo|placeholder|changeme|your[_-]?api|foo|bar|xxx|yyy|aaa|00000000|example\.com)/i.test(matchedValue)) {
              continue;
            }
            findings.push({
              type: 'api_leak',
              severity: 'critical',
              title: `${f.RuleID || 'Hardcoded secret'} detected`,
              description: `gitleaks rule "${f.RuleID}" matched: ${matchedValue.slice(0, 4)}...${matchedValue.slice(-4)} [len=${matchedValue.length}]`,
              evidence: `prefix=${matchedValue.slice(0, 4)} suffix=${matchedValue.slice(-4)} length=${matchedValue.length}`,
              location: `${f.File}:${f.StartLine || '?'}`,
              source: 'gitleaks',
              confidence: 0.97,
            });
          }
        } catch (parseErr) {
          console.warn('[static-analysis] gitleaks output parse failed:', String(parseErr).slice(0, 100));
        }
      }
    }
  } finally {
    // Cleanup temp dir
    if (tmpDir) {
      try { await rm(tmpDir, { recursive: true, force: true }); } catch {}
    }
  }

  // ─── 3. Run sink-hint scanner (in-process, no subprocess) ───
  const sinkT0 = Date.now();
  const sinkHints = scanSinkHints(sourceCode);
  const sinkHintsMs = Date.now() - sinkT0;

  // Convert sink-hints to StaticFindings (these are HINTS, not confirmed vulns)
  // But we save them as 'candidate' status — LLM will decide if real.
  // Actually, save them as StaticFindings with source='sink-hints' for clarity.
  for (const h of sinkHints) {
    // Only secrets from sink-hints go to findings (already covered by gitleaks
    // but sink-hints has additional patterns like JWT). Other sink-hints
    // stay as 'candidate' for LLM triage.
    if (h.type === 'secret_pattern') {
      findings.push({
        type: 'api_leak',
        severity: h.severity,
        title: `${h.description}`,
        description: `Static regex matched: ${h.match}. Context: ...${h.contextBefore}${h.contextAfter}...`,
        evidence: h.match,
        location: `sourceCode:offset=${h.location}`,
        source: 'sink-hints',
        confidence: 0.95,
      });
    }
  }

  // ─── 4. Build LLM context from sink-hints (≤4K chars) ───
  const llmContext = buildLLMContextFromHints(sinkHints);
  const skipLLM = sinkHints.length === 0;

  // ─── 5. Truncation stats (per Claude §9.11) ───
  const sourceCodeChars = sourceCode.length;
  const truncatedChars = Math.max(0, sourceCodeChars - 30000);
  const truncatedPct = sourceCodeChars > 30000
    ? (truncatedChars / sourceCodeChars) * 100
    : 0;

  const totalMs = Date.now() - t0;

  return {
    findings,
    sinkHints,
    llmContext,
    skipLLM,
    stats: {
      gitleaksMs,
      sinkHintsMs,
      totalMs,
      sourceCodeChars,
      truncatedChars,
      truncatedPct,
    },
  };
}
