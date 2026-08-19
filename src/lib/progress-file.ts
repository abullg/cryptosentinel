/**
 * CryptoSentinel — Progress File Storage
 *
 * Writes analysis job progress to a JSON FILE instead of SQLite.
 *
 * Why: SQLite Prisma uses a single-writer connection by default. When
 * many concurrent operations try to write (50 parallel HTTP workers
 * saving findings + 15 parallel rigor verifications updating findings
 * + flushTimer writing progress), they queue up at the single
 * connection. If one write hangs (disk I/O, transaction deadlock), ALL
 * writes are blocked — user sees frozen progress forever.
 *
 * File I/O uses kernel async and never serializes through a connection
 * pool. /tmp/cs-progress/ is typically tmpfs (RAM-backed) — instant.
 */
import { writeFileSync, readFileSync, existsSync, mkdirSync } from 'fs';

const PROGRESS_DIR = '/tmp/cs-progress';
try {
  if (!existsSync(PROGRESS_DIR)) mkdirSync(PROGRESS_DIR, { recursive: true });
} catch (e) {
  console.warn('Could not create progress dir:', e);
}

export function progressFilePath(jobId: string): string {
  return `${PROGRESS_DIR}/${jobId}.json`;
}

export interface ProgressState {
  progress: number;
  message: string;
  status: string;
  updatedAt?: number;
}

export function writeProgressFile(jobId: string, state: ProgressState): void {
  try {
    writeFileSync(progressFilePath(jobId), JSON.stringify({ ...state, updatedAt: Date.now() }));
  } catch (e) {
    console.error('[progress-file] writeProgressFile failed:', String(e).slice(0, 100));
  }
}

export function readProgressFile(jobId: string): ProgressState | null {
  try {
    if (!existsSync(progressFilePath(jobId))) return null;
    const data = readFileSync(progressFilePath(jobId), 'utf8');
    return JSON.parse(data);
  } catch { return null; }
}
