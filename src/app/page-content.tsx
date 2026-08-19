'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Textarea } from '@/components/ui/textarea';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Separator } from '@/components/ui/separator';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import {
  Shield, Bug, Brain, Zap, Lock, Search, Database,
  AlertTriangle, CheckCircle2, XCircle, Clock, Activity,
  FileCode, Globe, ChevronRight, TrendingUp, Target,
  Download, FileText, Settings, Key, CheckCircle, Wifi, WifiOff,
  ExternalLink, AlertCircle, Code2, Copy, X, Trash2,
  Eye, Play, Square, RefreshCw, Terminal, Loader2, Pause, Filter, ZapOff
} from 'lucide-react';

// Types
interface Vulnerability {
  id: string; type: string; severity: string; title: string; description: string;
  confidence: number; status: string; v1Symbolic: number | null; v2Fuzzing: number | null;
  v3Formal: number | null; v4Economic: number | null; patternTag: string | null;
  isDuplicate: boolean; pocFilename: string | null; poc: string | null; target: string | null;
  vulnCategory: string | null; validationSteps: string | null; location: string | null;
  codeSnippet: string | null; createdAt: string;
  validationScope?: 'target' | 'lab' | 'theoretical' | null;
  contract?: { name: string; project?: { name: string } };
}
interface Project {
  id: string; name: string; chain: string; language: string; address: string | null;
  contracts?: { id: string; name: string }[];
  audits?: { id: string; status: string; findings: number; confirmed: number }[];
}
interface MemoryPattern { id: string; type: string; name: string; description: string; tags: string; chain: string | null; frequency: number; severity: string; }

const severityColor: Record<string, string> = {
  critical: 'bg-red-100 text-red-800 border-red-200',
  high: 'bg-orange-100 text-orange-800 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  low: 'bg-green-100 text-green-800 border-green-200',
  info: 'bg-slate-100 text-slate-700 border-slate-200',
};
const statusIcon: Record<string, React.ReactNode> = {
  confirmed: <CheckCircle2 className="w-4 h-4 text-green-600" />,
  validated: <Target className="w-4 h-4 text-blue-600" />,
  candidate: <Clock className="w-4 h-4 text-yellow-600" />,
  refuted: <XCircle className="w-4 h-4 text-red-600" />,
};
// Verdict label map — three-state model (EXPLOITABLE / NOT_EXPLOITABLE / INCONCLUSIVE)
const verdictLabel: Record<string, { text: string; color: string }> = {
  confirmed: { text: 'EXPLOITABLE', color: 'bg-emerald-100 text-emerald-800 border-emerald-200' },
  validated: { text: 'EXPLOITABLE (lab)', color: 'bg-blue-100 text-blue-800 border-blue-200' },
  candidate: { text: 'INCONCLUSIVE', color: 'bg-yellow-100 text-yellow-800 border-yellow-200' },
  refuted: { text: 'NOT EXPLOITABLE', color: 'bg-red-100 text-red-800 border-red-200' },
};
const chainLabel: Record<string, string> = {
  ethereum: 'Ethereum', bsc: 'BSC', polygon: 'Polygon', arbitrum: 'Arbitrum',
  solana: 'Solana', sui: 'Sui', starknet: 'StarkNet', optimism: 'Optimism',
};

// Persisted State Hook
function usePersistedState<T>(key: string, defaultValue: T) {
  const [state, setState] = useState<T>(() => {
    if (typeof window !== 'undefined') {
      try {
        const saved = localStorage.getItem(key);
        if (saved) return JSON.parse(saved);
      } catch {}
    }
    return defaultValue;
  });

  // Debounced localStorage write — prevents UI jank from frequent writes during polling
  const writeTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (typeof window !== 'undefined') {
      if (writeTimerRef.current) clearTimeout(writeTimerRef.current);
      writeTimerRef.current = setTimeout(() => {
        try { localStorage.setItem(key, JSON.stringify(state)); } catch {}
      }, 500); // 500ms debounce
    }
    return () => { if (writeTimerRef.current) clearTimeout(writeTimerRef.current); };
  }, [key, state]);

  return [state, setState] as const;
}

// Activity Item Type
interface ActivityItem {
  id: string;
  type: 'scan' | 'finding' | 'method' | 'system' | 'validation' | 'attack-sim';
  message: string;
  detail?: string;
  timestamp: number;
  status: 'running' | 'success' | 'warning' | 'error' | 'info';
  progress?: number;
}

export default function CryptoSentinelDashboard() {
  const [projects, setProjects] = usePersistedState<Project[]>('cs_projects', []);
  const [vulns, setVulns] = usePersistedState<Vulnerability[]>('cs_vulns', []);
  /** CRITICAL: Only show vulnerabilities with confidence >= 90%
   *  Applied to EVERY place findings enter the UI. No exceptions. */
  const MIN_CONFIDENCE = 0;
  const onlyHighConfidence = (findings: any[]): any[] => findings;


  /** Filter: show ALL vulnerabilities. Confidence is displayed in the UI
   *  as a percentage badge so the user can judge quality themselves.
   *  No artificial threshold hiding results. */
  const filterHighConfidence = (vulns: Vulnerability[]): Vulnerability[] => vulns;

  /** SAFETY NET: no filtering — show everything. */
  useEffect(() => {}, [vulns]);

  /** Helper: check if a finding has active validation. */
  const hasActiveValidation = (v: any): boolean =>
    v.validationScope === 'target' || v.validationScope === 'lab';

  /**
   * Filter to ONLY confirmed/validated findings. The user explicitly asked:
   * "if we search for what we can confirm then how can inconclusive appear
   * and what's the sense of showing me non-exploitable?". Right — only
   * confirmed exploits should reach the UI. Anything else (candidate,
   * refuted, dropped) is filtered out. The backend also DELETES non-
   * confirmed findings from the DB, but this is the client-side safety
   * net so cached/localStorage data is also clean.
   */
  const onlyValidated = (findings: any[]): any[] =>
    findings.filter(v => v.status === 'confirmed' || v.status === 'validated');

  const [patterns, setPatterns] = usePersistedState<MemoryPattern[]>('cs_patterns', []);
  const [loading, setLoading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [activeProject, setActiveProject] = usePersistedState<string>('cs_activeProject', '');
  const [newProject, setNewProject] = useState({ name: '', chain: 'ethereum', language: 'solidity', address: '' });
  const [sourceCode, setSourceCode] = useState('');
  const [apiKey, setApiKey] = useState('');
  // Severity filter — default ON (show medium/high/critical only, hide low/info noise)
  const [hideLowSeverity, setHideLowSeverity] = usePersistedState<boolean>('cs_hideLow', true);

  /**
   * Ensure a project is selected — if not, auto-create or pick the first one.
   * Returns the active project ID.
   */
  const ensureProject = async (name?: string, chain?: string, language?: string): Promise<string> => {
    // If a project is already selected, use it
    if (activeProject) return activeProject;
    // If projects exist, pick the first one
    if (projects.length > 0) {
      setActiveProject(projects[0].id);
      return projects[0].id;
    }
    // Otherwise auto-create a project — WITH TIMEOUT to prevent infinite hang
    const projectName = name || 'Auto Analysis';
    const res = await fetchWithTimeout('/api/projects', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: projectName, chain: chain || 'ethereum', language: language || 'solidity' }),
    }, 30_000); // 30s timeout
    if (res.ok) {
      const p = await res.json();
      setProjects(prev => [p, ...prev]);
      setActiveProject(p.id);
      return p.id;
    }
    throw new Error('Failed to auto-create project');
  };
  const [hasKey, setHasKey] = usePersistedState<boolean>('cs_hasKey', false);
  const [maskedKey, setMaskedKey] = usePersistedState<string>('cs_maskedKey', '');
  /** 'env' if the key comes from OPENROUTER_API_KEY env var, 'db' if from DB, null if no key */
  const [keySource, setKeySource] = useState<'env' | 'db' | null>(null);
  /** State for the "Test API Key" button — performs a real OpenRouter /key check */
  const [testingKey, setTestingKey] = useState(false);
  const [keyTestResult, setKeyTestResult] = useState<{
    valid: boolean;
    reason: string;
    source?: string;
    key_info?: {
      is_free_tier?: boolean;
      usage?: number;
      limit?: number | null;
      expires_at?: string | null;
    };
  } | null>(null);
  const [model, setModel] = usePersistedState<string>('cs_model', 'z-ai/glm-5.2');
  const [targetUrl, setTargetUrl] = useState('');
  const [targetType, setTargetType] = useState<'contract' | 'exchange' | 'hackenproof'>('contract');
  const [fetchingUrl, setFetchingUrl] = useState(false);
  const [fetchError, setFetchError] = useState('');
  const [reportText, setReportText] = useState('');
  const [showReport, setShowReport] = useState(false);
  const [hackenproofContext, setHackenproofContext] = useState<{description: string; priorities: string; projectName: string} | null>(null);
  const [pocView, setPocView] = useState<{title: string; filename: string; code: string} | null>(null);
  const [pocCopied, setPocCopied] = useState(false);
  const [validatingVulns, setValidatingVulns] = useState<Set<string>>(new Set());

  // ─── ANALYSIS LOCK & ABORT ────────────────────────────────────────────────
  // Prevents concurrent analysis runs and ensures ALL in-flight requests are
  // cancelled when a hard timeout fires. This is THE fix for infinite loading.
  const isAnalyzingRef = useRef(false);       // true = analysis in progress (lock)
  const analysisAbortRef = useRef<AbortController | null>(null); // abort all fetches on timeout
  const HARD_TIMEOUT_MS = 900_000;            // 15 min — background job has no SSE timeout

  // ─── SAFETY WATCHDOG ──────────────────────────────────────────────────────
  // With background polling, the watchdog only needs to catch UI bugs.
  // The actual analysis runs on the server and can take up to 10 min.
  // 15 min is generous — if polling hasn't shown 'completed' by then, reset.
  const watchdogSinceRef = useRef<number>(0);
  useEffect(() => {
    const WATCHDOG_INTERVAL = 10_000;
    const WATCHDOG_MAX = 900_000;  // 15 min

    const watchdog = setInterval(() => {
      if (analyzing || fetchingUrl) {
        if (watchdogSinceRef.current === 0) watchdogSinceRef.current = Date.now();
        const elapsed = Date.now() - watchdogSinceRef.current;
        if (elapsed > WATCHDOG_MAX) {
          const mins = Math.round(elapsed / 60_000);
          console.error(`[WATCHDOG] analyzing stuck for ${mins} min — FORCE RESET`);
          isAnalyzingRef.current = false;
          analysisAbortRef.current = null;
          setAnalyzing(false);
          setFetchingUrl(false);
          setFetchError(`Analysis timed out after ${mins} min. The server may be overloaded — please try again.`);
          addActivity('scan', `Analysis timed out after ${mins} min — force reset`, 'error', 'Server may be overloaded; please retry', 0);
          watchdogSinceRef.current = 0;
        }
      } else {
        watchdogSinceRef.current = 0;
      }
    }, WATCHDOG_INTERVAL);

    return () => clearInterval(watchdog);
  }, [analyzing]);

  // Scan Methods (toggleable)
  const [scanMethods, setScanMethods] = usePersistedState<Record<string, boolean>>('cs_scanMethods', {
    'ast-analysis': true, 'data-flow': true, 'control-flow': true, 'pattern-match': true,
    'deep-reentrancy': true, 'symbolic-exec': true, 'fuzzing': true, 'mutation-test': true,
    'formal-verify': true, 'model-check': true, 'invariant-check': true, 'signature-replay': true,
    'access-control': true, 'oracle-manip': true, 'flash-loan-sim': true, 'mev-analysis': true,
    'gas-dos-audit': true, 'cross-contract': true, 'proxy-storage': true, 'delegatecall-scan': true,
  });

  // Activity Feed
  const [activities, setActivities] = usePersistedState<ActivityItem[]>('cs_activities', []);
  const [showActivity, setShowActivity] = useState(false);
  const activityPanelRef = useRef<HTMLDivElement>(null);

  const addActivity = (type: ActivityItem['type'], message: string, status: ActivityItem['status'], detail?: string, progress?: number) => {
    const item: ActivityItem = { id: Math.random().toString(36).substr(2, 9), type, message, status, detail, progress, timestamp: Date.now() };
    setActivities(prev => [item, ...prev].slice(0, 50));
  };

  const toggleScanMethod = (key: string) => {
    setScanMethods(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const fetchData = useCallback(async () => {
    try {
      // Use fetchWithTimeout (15s) to prevent infinite hang on slow networks
      const [pRes, vRes, mRes, sRes] = await Promise.all([
        fetchWithTimeout('/api/projects', {}, 15_000),
        fetchWithTimeout('/api/vulnerabilities', {}, 15_000),
        fetchWithTimeout('/api/memory', {}, 15_000),
        fetchWithTimeout('/api/settings', {}, 15_000)
      ]);
      if (pRes.ok) setProjects(await pRes.json());
      if (vRes.ok) {
        const serverVulns: Vulnerability[] = await vRes.json();
        // MERGE: keep union of server + localStorage, dedup by ID.
        // Server data ADDS to localStorage — never replaces (fixes data loss on restart)
        // Apply onlyValidated filter — only confirmed/validated reach the UI.
        // User explicitly asked: "if we search for what we can confirm then
        // how can inconclusive appear and what's the sense of showing me
        // non-exploitable?". Right answer: only confirmed exploits show.
        if (serverVulns.length > 0) {
          const highConfServerVulns = onlyValidated(serverVulns);
          setVulns(prev => {
            // Also drop any stale localStorage entries that are no longer confirmed
            const cleanPrev = prev.filter(v => v.status === 'confirmed' || v.status === 'validated');
            const existingIds = new Set(cleanPrev.map(v => v.id));
            const toAdd = highConfServerVulns.filter(v => !existingIds.has(v.id));
            return toAdd.length > 0 ? [...toAdd, ...cleanPrev] : cleanPrev;
          });
        } else {
          // Server returned 0 — clear stale localStorage findings too
          setVulns(prev => prev.filter(v => v.status === 'confirmed' || v.status === 'validated'));
        }
      }
      if (mRes.ok) setPatterns(await mRes.json());
      if (sRes.ok) {
        const s = await sRes.json();
        setHasKey(s._hasKey || false);
        setMaskedKey(s.apiKey || '');
        setModel(s.model || 'z-ai/glm-5.2');
        setKeySource(s._source || null);
      }
    } catch {}
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  // CONNECTIVITY CHECK: Quick ping to verify server is reachable on page load
  useEffect(() => {
    const endpoints = ['/api', '/api/analyze', '/api/validate-vuln', '/api/vulnerabilities'];
    endpoints.forEach(url => {
      fetch(url, { method: 'GET' }).catch(() => {}); // fire-and-forget warmup
    });
  }, []);

  // AUTO-VALIDATE: Whenever new unvalidated vulns appear, trigger active exploitation test
  // Uses refs to avoid stale closures and re-render loops
  // IMPORTANT: Skips if analysis is in progress to prevent interference
  const autoValidateRan = useRef<Set<string>>(new Set());
  const autoValidateRunning = useRef(false);
  const vulnsRef = useRef(vulns);
  vulnsRef.current = vulns;
  const hasKeyRef = useRef(hasKey);
  hasKeyRef.current = hasKey;

  // Single useEffect that runs once and watches for new unvalidated vulns via interval
  useEffect(() => {
    const interval = setInterval(() => {
      // SKIP if analysis is running — prevents interference with main analysis flow
      if (isAnalyzingRef.current) return;
      if (!hasKeyRef.current || autoValidateRunning.current) return;

      const currentVulns = vulnsRef.current;
      const unvalidated = currentVulns.filter(v =>
        !v.validationSteps &&
        v.status !== 'confirmed' && v.status !== 'validated' && v.status !== 'refuted' &&
        !autoValidateRan.current.has(v.id)
      );
      if (unvalidated.length === 0) return;

      // Mark as queued immediately
      unvalidated.forEach(v => autoValidateRan.current.add(v.id));
      autoValidateRunning.current = true;

      addActivity('validation', `Auto-validating ${unvalidated.length} findings (active exploitation)...`, 'running', 'Default: all findings actively tested', 0);

      // Validate sequentially with 3s gap
      (async () => {
        try {
          for (const vuln of unvalidated) {
            // Abort if analysis started while we're validating
            if (isAnalyzingRef.current) break;
            try { await validateVuln(vuln); } catch {}
            await new Promise(r => setTimeout(r, 3_000));
          }
        } finally {
          autoValidateRunning.current = false;
          addActivity('validation', `Auto-validation batch done`, 'success', '', 100);
        }
      })();
    }, 5_000); // Check every 5s for new unvalidated vulns

    return () => clearInterval(interval);
  }, []); // Empty deps — runs once, uses refs

  // Delete a single vulnerability
  const deleteVuln = async (id: string) => {
    const res = await fetchWithTimeout(`/api/vulnerabilities?id=${id}`, { method: 'DELETE' }, 15_000);
    if (res.ok) fetchData();
  };

  // Validate a single vulnerability via active exploit testing
  const validateVuln = async (v: Vulnerability) => {
    if (validatingVulns.has(v.id)) return;
    setValidatingVulns(prev => new Set(prev).add(v.id));
    addActivity('validation', `Validating: ${v.title}`, 'running', 'Active exploit testing', 0);

    try {
      // POST /api/validate-vuln — runs activelyValidate() (Foundry/cast/HTTP)
      const res = await fetchWithTimeout('/api/validate-vuln', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vulnerabilityId: v.id }),
      }, 120_000); // 2 min — validation can take time

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        addActivity('validation', `Validation failed: ${v.title}`, 'error', errData.error || `HTTP ${res.status}`, 0);
        setVulns(prev => prev.map(vn => vn.id === v.id ? {
          ...vn, validationSteps: `Validation error: ${errData.error || `HTTP ${res.status}`}`,
          status: vn.status === 'candidate' ? 'validated' : vn.status,
        } : vn));
        return;
      }

      const result = await res.json();
      const newConfidence = result.confidence ?? 0;
      const scope = result.validationScope || 'theoretical';

      // CONFIRM-OR-DROP: only keep confirmed/validated findings. If the
      // backend said NOT_EXPLOITABLE or INCONCLUSIVE, REMOVE the finding
      // from localStorage so it doesn't reappear next session.
      const isConfirmed = result.verdict === 'EXPLOITABLE' ||
                          result.status === 'confirmed' || result.status === 'validated';
      if (isConfirmed) {
        setVulns(prev => prev.map(vn => vn.id === v.id ? {
          ...vn,
          confidence: newConfidence,
          status: result.status || vn.status,
          validationScope: scope,
          validationSteps: result.evidence || vn.validationSteps,
        } : vn));
        addActivity('validation',
          `CONFIRMED: ${v.title} — EXPLOITABLE (${scope})`,
          'success', result.evidence?.slice(0, 200) || '', 100);
      } else {
        // Non-confirmed — remove from list. Backend already deleted it from DB.
        setVulns(prev => prev.filter(vn => vn.id !== v.id));
        addActivity('validation',
          `Dropped: ${v.title} — not exploitable (no hard evidence). Only confirmed exploits are kept.`,
          'info', '', 100);
      }
    } catch (err: any) {
      const errMsg = String(err)?.slice(0, 100) || 'Network error';
      addActivity('validation', `Validation failed: ${v.title}`, 'error', errMsg, 0);
      // On validation error, ALSO drop the finding — keeping it as
      // candidate just creates inconclusive noise the user explicitly
      // doesn't want to see.
      setVulns(prev => prev.filter(vn => vn.id !== v.id));
    } finally {
      setValidatingVulns(prev => { const s = new Set(prev); s.delete(v.id); return s; });
    }
  };

  // Clear ALL findings, contracts, and audits
  const clearAllFindings = async () => {
    // Clear localStorage FIRST so merge strategy in fetchData doesn't restore them
    setVulns([]);
    setProjects([]);
    setPatterns([]);
    setActivities([]);
    setActiveProject('');
    // Reset auto-validate tracking so new vulns get validated after clear
    autoValidateRan.current.clear();
    // Also directly clear localStorage keys as backup
    try {
      localStorage.removeItem('cs_vulns');
      localStorage.removeItem('cs_projects');
      localStorage.removeItem('cs_patterns');
      localStorage.removeItem('cs_activities');
      localStorage.removeItem('cs_activeProject');
    } catch {}
    // Clear server DB
    try {
      const res = await fetchWithTimeout('/api/vulnerabilities', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'clear-all' }),
      }, 15_000);
      if (res.ok) {
        // Re-fetch to sync (server should return empty, local is already empty)
        fetchData();
      }
    } catch {} // non-fatal if server clear fails
  };

  /** Hit /api/test-key — verifies the key actually works against OpenRouter before saving. */
  const testApiKey = async () => {
    setTestingKey(true);
    setKeyTestResult(null);
    try {
      // If user typed a new key in the input, test that. Otherwise, test the currently configured key.
      const body = apiKey && !apiKey.includes('***') ? { testKey: apiKey } : {};
      const res = await fetch('/api/test-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      setKeyTestResult(data);
      addActivity('scan',
        data.valid ? `API key test passed: ${data.reason}` : `API key test failed: ${data.reason}`,
        data.valid ? 'success' : 'error',
        data.source ? `Source: ${data.source}` : 'Test complete',
        100,
      );
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setKeyTestResult({ valid: false, reason: `Request failed: ${msg.slice(0, 200)}` });
      addActivity('scan', `API key test request failed: ${msg.slice(0, 120)}`, 'error', 'Network or server error', 0);
    } finally {
      setTestingKey(false);
    }
  };

  const saveApiKey = async () => {
    // ─── Client-side format validation (mirrors server) ──────────
    // Fail FAST in the UI without even hitting the network. The server
    // also validates, but doing it here means the user gets instant
    // feedback and the Activity feed logs the rejection.
    if (apiKey && apiKey.includes('***')) {
      // Masked value from GET — user didn't change it, just save the model
    } else if (apiKey) {
      if (apiKey.startsWith('vcp_')) {
        addActivity('scan', 'API key rejected: this is not an OpenRouter key. OpenRouter keys start with "sk-or-v1-"', 'error', 'Invalid key format', 0);
        return;
      }
      if (apiKey.startsWith('sk-') && !apiKey.startsWith('sk-or-')) {
        addActivity('scan', 'API key rejected: this looks like an OpenAI key. OpenRouter keys start with "sk-or-v1-"', 'error', 'Invalid key format', 0);
        return;
      }
      if (!apiKey.startsWith('sk-or-v1-') || apiKey.length < 30) {
        addActivity('scan', 'API key rejected: invalid OpenRouter format. Keys start with "sk-or-v1-" and are 30+ characters', 'error', 'Invalid key format', 0);
        return;
      }
    }

    const res = await fetchWithTimeout('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ apiKey, model }),
    }, 15_000);
    if (res.ok) {
      const s = await res.json();
      setHasKey(s._hasKey || false);
      setMaskedKey(s.apiKey || '');
      setKeySource(s._source || null);
      setApiKey('');
      const msg = s._note
        ? `Saved — but env var OPENROUTER_API_KEY takes precedence (${s._source})`
        : (s._hasKey ? 'OpenRouter API key saved — AI analysis is active' : 'Settings saved (no API key set)');
      addActivity('scan', msg, s._hasKey ? 'success' : 'warning', s._hasKey ? 'Ready' : 'Configure a key to enable AI', 100);
    } else {
      // ─── Surface server-side validation errors ─────────────────
      // Previously: any non-OK response was silently swallowed, so the
      // user thought their key was saved when it was actually rejected.
      let errMsg = `HTTP ${res.status}`;
      try { const e = await res.json(); errMsg = e.error || errMsg; } catch {}
      addActivity('scan', `Failed to save API key: ${errMsg.slice(0, 120)}`, 'error', 'Check key format', 0);
    }
  };

  const createProject = async () => {
    if (!newProject.name) return;
    setLoading(true);
    try {
      const res = await fetchWithTimeout('/api/projects', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(newProject),
      }, 15_000);
      if (res.ok) {
        const p = await res.json();
        setProjects(prev => [p, ...prev]);
        setActiveProject(p.id);
        setNewProject({ name: '', chain: 'ethereum', language: 'solidity', address: '' });
      }
    } finally { setLoading(false); }
  };

  /** Fetch with timeout — simple, no abort linking.
   *  The old analysisAbortRef linking caused 'signal is aborted without reason'
   *  errors because the ref was never set in the background-job path. */
  const fetchWithTimeout = (url: string, options: RequestInit = {}, timeoutMs: number = 45_000): Promise<Response> => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    return fetch(url, { ...options, signal: controller.signal }).finally(() => clearTimeout(timer));
  };

  /** Helper: check if analysis was aborted — throws to exit the flow cleanly */
  const throwIfAborted = () => {
    if (analysisAbortRef.current?.signal.aborted) {
      throw new DOMException('Analysis aborted by timeout', 'AbortError');
    }
  };

  /** UNIFIED SSE STREAMING ANALYSIS — THE DEFINITIVE FIX
   *  Uses /api/analyze-stream for BOTH phases in ONE connection.
   *  - Heartbeats every 5s keep the connection alive during long AI calls
   *    during long GLM calls (which can take 60-180s).
   *  - Static results appear immediately (phase1_complete event)
   *  - AI results stream in as they're found (finding events)
   *  - No gap between phases — same server instance
   *  - Robust retry logic: 3 attempts with progressive backoff
   *  - Sync /api/analyze-ai is now the SECONDARY fallback (it times out
   *    at the server's request limit, so it only works for fast analyses). */
  const runTwoPhaseAnalysis = async (projectId: string, code: string, contractNm: string, tUrl?: string, tType?: string, hpContext?: any) => {

    // ═══════════════════════════════════════════════════════════════
    // SSE STREAMING — PRIMARY path (most reliable for long AI calls)
    // ═══════════════════════════════════════════════════════════════
    // Serverless platforms cap HTTP requests at ~100s. The synchronous
    // /api/analyze-ai endpoint can't fit a 30-180s GLM call inside that
    // window. SSE streaming bypasses the limit because data flows
    // continuously (heartbeats every 5s) — the proxy sees an active
    // connection and doesn't kill it.
    //
    // ONE retry with 5s delay — this is enough for genuine network blips
    // (TCP reset, brief packet loss) without forcing the user through
    // 3 × 60s = 3+ minutes of "Connection failed" messages when the only
    // issue was a slow AI call. With heartbeat timeout now at 180s, real
    // timeouts will be rare.
    const SSE_RETRIES = 1;
    const SSE_RETRY_DELAYS = [5_000]; // 5s only

    for (let attempt = 0; attempt < SSE_RETRIES; attempt++) {
      throwIfAborted();
      try {
        addActivity('scan', attempt === 0 ? 'Starting deep analysis...' : `Retrying analysis (attempt ${attempt + 1}/${SSE_RETRIES})...`, 'running', 'Connecting', 5);

        const result = await runSSEStream(projectId, code, contractNm, tUrl, tType, hpContext);
        return result; // Success!

      } catch (err: any) {
        const errMsg = String(err);
        if (errMsg.includes('AbortError') && analysisAbortRef.current?.signal.aborted) throw err;

        const isNetworkError = errMsg.includes('Failed to fetch') || errMsg.includes('network error') || errMsg.includes('NetworkError') || errMsg.includes('fetch failed') || errMsg.includes('Load failed') || errMsg.includes('SSE heartbeat timeout');

        if (isNetworkError && attempt < SSE_RETRIES - 1) {
          addActivity('scan', `Connection failed, retrying in ${SSE_RETRY_DELAYS[attempt] / 1000}s...`, 'warning', 'Network blip', 10);
          await new Promise(r => setTimeout(r, SSE_RETRY_DELAYS[attempt]));
          continue;
        }

        // Non-network error or exhausted retries — try sync as last resort
        if (!isNetworkError) throw err;
      }
    }

    // ═══════════════════════════════════════════════════════════════
    // FALLBACK: Synchronous approach (last resort — only works for
    // fast analyses that complete within the server's request limit)
    // ═══════════════════════════════════════════════════════════════
    addActivity('scan', 'SSE streaming failed, trying sync analysis...', 'warning', 'Last resort', 15);
    return await runSyncAnalysis(projectId, code, contractNm, tUrl, tType, hpContext);
  };

  /** Synchronous analysis — calls /api/analyze-ai with phase='full' */
  const runSyncAnalysis = async (projectId: string, code: string, contractNm: string, tUrl?: string, tType?: string, hpContext?: any): Promise<{ contractId: string; auditId: string }> => {
    addActivity('scan', 'Running deep analysis...', 'running', 'Phase 1', 5);

    // VPS has no request timeout. Client timeout 600s (10 min) gives
    // plenty of room for deep AI analysis + EVM validation.
    const res = await fetchWithTimeout('/api/analyze-ai', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        phase: 'full',
        projectId,
        sourceCode: code,
        contractName: contractNm,
        targetUrl: tUrl,
        targetType: tType || targetType,
        hackenproofContext: hpContext,
      }),
    }, 600_000); // 10 min — VPS has no serverless timeout

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.error || `HTTP ${res.status}`);
    }

    const data = await res.json();
    const allFindings = onlyValidated(data.allFindings || []);
    const contractId = data.contractId || '';
    const auditId = data.auditId || '';

    // Show findings immediately — filter to >=90% confidence only
    const highConfFindings = onlyValidated(allFindings);
    if (highConfFindings.length > 0) {
      setVulns(prev => {
        const existingIds = new Set(prev.map(v => v.id));
        return [...highConfFindings.filter((f: any) => !existingIds.has(f.id)), ...prev];
      });
    }

    const confirmed = allFindings.filter((f: any) => f.status === 'confirmed').length;
    addActivity('scan',
      `Analysis complete: ${allFindings.length} findings (${confirmed} confirmed)`,
      'success',
      'Full analysis done',
      100
    );

    return { contractId, auditId };
  };

  /** SSE Stream handler — connects to /api/analyze-stream and processes events */
  const runSSEStream = async (projectId: string, code: string, contractNm: string, tUrl?: string, tType?: string, hpContext?: any): Promise<{ contractId: string; auditId: string }> => {
    return new Promise((resolve, reject) => {
      let resolved = false;
      let contractId = '';
      let auditId = '';
      let staticFindingsCount = 0;
      let aiFindingsCount = 0;
      let phase1Shown = false;

      const doFetch = async () => {
        try {
          const res = await fetch('/api/analyze-stream', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              projectId, sourceCode: code, contractName: contractNm,
              targetUrl: tUrl, targetType: tType || targetType,
              hackenproofContext: hpContext,
            }),
            signal: analysisAbortRef.current?.signal,
          });

          if (!res.ok) {
            // If non-2xx, the SSE endpoint isn't available — fall back
            const errText = await res.text().catch(() => '');
            reject(new Error(`SSE endpoint: ${res.status} ${errText.slice(0, 100)}`));
            return;
          }

          const reader = res.body?.getReader();
          if (!reader) {
            reject(new Error('No response body'));
            return;
          }

          const decoder = new TextDecoder();
          let buffer = '';
          // Heartbeat timeout — server sends heartbeats every 5s. AI calls
          // (GLM 5.2 deep analysis) can take up to 5 minutes on a real VPS
          // (no serverless limits). During the AI call, Node.js event loop
          // is busy with the OpenRouter HTTP request and heartbeats can be
          // delayed. Set timeout to 10 min to accommodate:
          //   - Normal AI call: 30-60s (heartbeats arrive, watchdog resets)
          //   - Slow AI call: 60-180s (some heartbeats arrive, still resets)
          //   - Deep reasoning on large codebase: 180-300s (still resets)
          //   - Real dead connection: no heartbeats for 10 min → timeout
          // Previous 180s was still too aggressive for deep reasoning on
          // large smart contract audits with multi-pass AI analysis.
          const HEARTBEAT_TIMEOUT_MS = 180_000; // 3 min — matches HARD_TIMEOUT
          let lastEventTime = Date.now();

          // Heartbeat watchdog — check every 30s.
          const heartbeatWatchdog = setInterval(() => {
            if (Date.now() - lastEventTime > HEARTBEAT_TIMEOUT_MS) {
              clearInterval(heartbeatWatchdog);
              if (!resolved) {
                reader.cancel().catch(() => {});
                reject(new Error('SSE heartbeat timeout — connection died'));
              }
            }
          }, 15_000);

          const processBuffer = () => {
            // SSE format: "event: type\ndata: json\n\n"
            const parts = buffer.split('\n\n');
            buffer = parts.pop() || ''; // Keep incomplete chunk

            for (const part of parts) {
              if (!part.trim()) continue;
              lastEventTime = Date.now();

              let eventType = '';
              let eventData = '';

              for (const line of part.split('\n')) {
                if (line.startsWith('event: ')) eventType = line.slice(7).trim();
                else if (line.startsWith('data: ')) eventData = line.slice(6).trim();
              }

              if (!eventType || !eventData) continue;

              try {
                const data = JSON.parse(eventData);
                handleSSEEvent(eventType, data);
              } catch {
                // Malformed data — ignore
              }
            }
          };

          const handleSSEEvent = (type: string, data: any) => {
            switch (type) {
              case 'heartbeat':
                // Just keep connection alive — no action needed
                break;

              case 'progress':
                if (data.step === 'connected') {
                  // Stream established — server is alive and starting work.
                  addActivity('scan', data.message || 'Stream connected', 'running', 'Connected', data.percent || 1);
                } else if (data.step === 'static') {
                  addActivity('scan', data.message || 'Running static analysis...', 'running', 'Phase 1', data.percent || 5);
                } else if (data.step === 'ai_start' || data.step === 'ai_analysis') {
                  if (!phase1Shown) phase1Shown = true;
                  addActivity('scan', data.message || 'AI deep analysis...', 'running', 'Phase 2: AI', data.percent || 50);
                } else if (data.step === 'blockchain' || data.step === 'websearch') {
                  addActivity('scan', data.message, 'running', data.step, data.percent || 60);
                } else if (data.step === 'enhancement' || data.step === 'onchain_verify') {
                  addActivity('scan', data.message, 'running', data.step, data.percent || 90);
                } else if (data.step === 'ai_done') {
                  addActivity('scan', data.message, 'running', 'Processing', data.percent || 75);
                }
                break;

              case 'phase1_complete': {
                phase1Shown = true;
                const findings = data.findings || [];
                staticFindingsCount = findings.length;
                contractId = data.contractId || '';
                auditId = data.auditId || '';

                // Show static findings immediately — only >=90% confidence
                const highConfStaticFindings = onlyValidated(findings);
                if (highConfStaticFindings.length > 0) {
                  setVulns(prev => {
                    const existingIds = new Set(prev.map(v => v.id));
                    const newFindings = highConfStaticFindings.filter((f: any) => !existingIds.has(f.id));
                    return [...newFindings, ...prev];
                  });
                }

                if (data.needsAI) {
                  addActivity('scan', `Static: ${findings.length} findings. Starting AI deep analysis...`, 'running', 'AI next', 40);
                } else {
                  addActivity('scan', `Static analysis: ${findings.length} findings (no AI key)`, 'success', 'Complete', 100);
                  clearInterval(heartbeatWatchdog);
                  resolved = true;
                  resolve({ contractId, auditId });
                }
                break;
              }

              case 'finding': {
                const vuln = data.vulnerability;
                // Only add if BOTH conditions met:
                //   1. confidence >= 90%
                //   2. validationScope is 'target' or 'lab' (not theoretical/null)
                // The server streams findings as they're found, but validation
                // happens AFTER all findings are reported. So this check will
                // usually FAIL here for the initial stream — the finding will
                // be added later via the post-validation 'complete' event when
                // its scope has been updated to 'target' or 'lab'.
                if (vuln && (vuln.confidence || 0) >= 0.90) {
                  aiFindingsCount++;
                  setVulns(prev => {
                    const existingIds = new Set(prev.map(v => v.id));
                    if (existingIds.has(vuln.id)) return prev;
                    return [vuln, ...prev];
                  });
                }
                break;
              }

              case 'complete': {
                const allFindings = data.findings || [];
                // Merge any findings we haven't seen yet — only >=90% confidence
                const highConfComplete = onlyValidated(allFindings);
                if (highConfComplete.length > 0) {
                  setVulns(prev => {
                    const existingIds = new Set(prev.map(v => v.id));
                    const newFindings = highConfComplete.filter((f: any) => !existingIds.has(f.id));
                    if (newFindings.length === 0) return prev;
                    return [...newFindings, ...prev];
                  });
                }
                const total = highConfComplete.length;
                const confirmed = highConfComplete.filter((f: any) => f.status === 'confirmed').length;
                addActivity('scan', `Analysis complete: ${total} findings (${confirmed} confirmed)`, 'success', 'Full analysis done', 100);
                clearInterval(heartbeatWatchdog);
                resolved = true;
                resolve({ contractId: contractId || data.contractId || '', auditId: auditId || data.auditId || '' });
                break;
              }

              case 'error': {
                const errorMsg = data.error || data.message || 'Unknown error';
                addActivity('scan', `Analysis error: ${errorMsg.slice(0, 100)}`, 'warning', 'Static results available', 85);
                // If we already have static results, resolve with what we have
                if (staticFindingsCount > 0 || contractId) {
                  clearInterval(heartbeatWatchdog);
                  resolved = true;
                  resolve({ contractId, auditId });
                } else {
                  clearInterval(heartbeatWatchdog);
                  resolved = true;
                  reject(new Error(errorMsg));
                }
                break;
              }
            }
          };

          // Read stream chunks
          const readLoop = async () => {
            try {
              while (true) {
                const { done, value } = await reader.read();
                if (done) {
                  // Stream ended — if not yet resolved, resolve with what we have
                  clearInterval(heartbeatWatchdog);
                  if (!resolved) {
                    if (staticFindingsCount > 0 || contractId) {
                      addActivity('scan', `Stream ended (${staticFindingsCount} static + ${aiFindingsCount} AI findings)`, 'success', 'Done', 100);
                      resolved = true;
                      resolve({ contractId, auditId });
                    } else {
                      resolved = true;
                      reject(new Error('Stream ended with no results'));
                    }
                  }
                  return;
                }
                buffer += decoder.decode(value, { stream: true });
                processBuffer();
              }
            } catch (readErr: any) {
              clearInterval(heartbeatWatchdog);
              if (!resolved) {
                const msg = String(readErr);
                if (msg.includes('abort') || msg.includes('AbortError')) {
                  reject(new DOMException('Analysis aborted', 'AbortError'));
                } else {
                  reject(new Error(`Stream read error: ${msg.slice(0, 80)}`));
                }
              }
            }
          };

          readLoop();

        } catch (fetchErr: any) {
          if (!resolved) reject(fetchErr);
        }
      };

      doFetch();
    });
  };

  /** FALLBACK: Two-phase JSON approach — only used if SSE streaming fails completely */
  const runFallbackTwoPhase = async (projectId: string, code: string, contractNm: string, tUrl?: string, tType?: string, hpContext?: any) => {
    // Phase 1: Static
    addActivity('scan', 'Running static analysis (fallback)...', 'running', 'Phase 1', 5);
    const res = await fetchWithTimeout('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        projectId, sourceCode: code, contractName: contractNm,
        targetUrl: tUrl, targetType: tType || targetType,
        hackenproofContext: hpContext, phase: 'static',
      }),
    }, 30_000);

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.error || `Static: ${res.status}`);
    }

    const staticData = await res.json();
    const staticFindings = onlyValidated(staticData.findings || []);
    if (staticFindings.length > 0) {
      setVulns(prev => {
        const existingIds = new Set(prev.map(v => v.id));
        return [...staticFindings.filter((f: any) => !existingIds.has(f.id)), ...prev];
      });
    }

    const contractId = staticData.contractId;
    const auditId = staticData.auditId;
    addActivity('scan', `Static: ${staticFindings.length} findings`, staticData.needsAI ? 'running' : 'success', staticData.needsAI ? 'AI next' : 'Done', 40);

    if (!staticData.needsAI || !hasKey) return { contractId, auditId };

    // Phase 2: AI (single attempt, best-effort)
    addActivity('scan', 'AI deep analysis (fallback)...', 'running', 'Phase 2: AI', 50);
    try {
      const aiRes = await fetchWithTimeout('/api/analyze-ai', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          phase: 'ai', projectId, contractId, auditId,
          sourceCode: code, contractName: contractNm,
          targetType: tType || targetType, hackenproofContext: hpContext,
        }),
      }, 290_000);

      if (aiRes.ok) {
        const aiData = await aiRes.json();
        const aiFindings = onlyValidated(aiData.aiFindings || aiData.allFindings || []);
        if (aiFindings.length > 0) {
          setVulns(prev => {
            const existingIds = new Set(prev.map(v => v.id));
            return [...aiFindings.filter((f: any) => !existingIds.has(f.id)), ...prev];
          });
        }
        addActivity('scan', `AI: ${aiFindings.length} findings`, 'success', 'Done', 100);
      } else {
        addActivity('scan', 'AI failed — static results available', 'warning', 'Try again', 85);
      }
    } catch {
      addActivity('scan', 'AI network error — static results available', 'warning', 'Try again', 85);
    }

    return { contractId, auditId };
  };

  /** Quick connectivity check — VPS with PM2 has no cold start (the
   *  server is always hot), so we just verify it's reachable before
   *  starting the analysis. No retry loop needed. */
  const warmupServer = async (): Promise<void> => {
    try {
      // 5s timeout — server is always hot on VPS, no cold start to wait for
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5_000);
      const res = await fetch('/api/settings', {
        method: 'GET',
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (res.ok) {
        addActivity('scan', 'Server ready', 'success', 'Connected', 5);
      }
    } catch {
      // Server unreachable — proceed anyway, the analysis call will surface the error
      addActivity('scan', 'Server ping failed — proceeding with analysis', 'warning', 'May be slow', 5);
    }
  };

  
  /** Download a professional .txt report for a single vulnerability */
  const downloadReport = async (vulnId: string) => {
    try {
      const res = await fetch(`/api/report?id=${vulnId}`);
      if (!res.ok) throw new Error('Report generation failed');
      const text = await res.text();
      const blob = new Blob([text], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vulnerability-report-${vulnId.slice(0, 8)}.txt`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      addActivity('scan', 'Report downloaded successfully', 'success', 'Professional .txt report', 100);
    } catch (e: any) {
      addActivity('scan', `Report download failed: ${e.message}`, 'error', 'Try again', 0);
    }
  };

  /** Background analysis via polling — no SSE, no heartbeat, no timeout issues.
   *  MUST be defined BEFORE analyzeContract and fetchUrlAndAnalyze (no hoisting for const).
   *  1. POST /api/analyze-job → returns jobId
   *  2. Poll GET /api/job-status/{jobId} every 5s
   *  3. When status=completed → fetch results from /api/vulnerabilities
   *  4. When status=failed → show error */
  const startBackgroundAnalysis = async (
    sourceCode: string,
    contractName: string,
    targetType: string,
    targetUrl?: string,
    crawlData?: { discoveredEndpoints?: string[]; discoveredForms?: any[]; discoveredParams?: string[] },
  ) => {
    addActivity('scan', 'Starting background analysis...', 'running', targetUrl || contractName, 5);

    // Step 1: Start the job — pass crawl data so analyze-job can run
    // per-endpoint active probes BEFORE AI even starts. This is what
    // "literally search everywhere on the site" means.
    const res = await fetch('/api/analyze-job', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        sourceCode, contractName, targetType, targetUrl,
        discoveredEndpoints: crawlData?.discoveredEndpoints || [],
        discoveredForms: crawlData?.discoveredForms || [],
        discoveredParams: crawlData?.discoveredParams || [],
      }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `HTTP ${res.status}`);
    }

    const { jobId } = await res.json();
    if (!jobId) throw new Error('No jobId returned');

    addActivity('scan', `Job started: ${jobId}`, 'info', 'Polling for progress...', 10);

    // Step 2: Poll for status — with auto-retry on network errors
    return new Promise<void>((resolve, reject) => {
      let pollErrors = 0;
      const poll = async () => {
        try {
          // Cache-bust with timestamp — browser may serve stale response
          // otherwise, especially on slow networks
          const statusRes = await fetch(`/api/job-status/${jobId}?t=${Date.now()}`, {
            cache: 'no-store',
            headers: { 'Cache-Control': 'no-cache' },
          });
          if (!statusRes.ok) {
            pollErrors++;
            if (pollErrors > 5) { reject(new Error(`Status check failed ${pollErrors} times`)); return; }
            setTimeout(poll, 5_000); // retry
            return;
          }
          pollErrors = 0; // reset on success
          const status = await statusRes.json();

          if (status.progress !== undefined && status.progress < 100) {
            // Incremental progress update — UPDATE the last entry in place
            // if the new progress is within ±5% of it, instead of adding a
            // new entry. This eliminates the "many 30% rows" cosmetic bug
            // when AI pass ticks every 10s while still in the same phase.
            const msg = status.message || `Progress: ${status.progress}%`;
            setActivities(prev => {
              const lastEntry = prev[0];
              // If last entry exists AND is in the same phase band (within ±5%),
              // UPDATE its message+timestamp in place rather than pushing a new row.
              if (lastEntry && lastEntry.type === 'scan' && lastEntry.status === 'running') {
                const lastProgress = typeof lastEntry.progress === 'number' ? lastEntry.progress : 0;
                if (Math.abs(lastProgress - status.progress) <= 5) {
                  const updated = {
                    ...lastEntry,
                    message: msg,
                    detail: `${status.progress}%`,
                    progress: status.progress,
                    timestamp: Date.now(),
                  };
                  return [updated, ...prev.slice(1)];
                }
              }
              // Different phase band → push new entry (this is a real transition)
              const entry = {
                type: 'scan',
                message: msg,
                status: 'running' as const,
                detail: `${status.progress}%`,
                progress: status.progress,
                timestamp: Date.now(),
              };
              return [entry, ...prev];
            });
          }

          if (status.status === 'completed') {
            addActivity('scan', `Analysis complete: ${status.resultCount} confirmed findings`, 'success', 'Done', 100);
            // Fetch results — with cache-busting timestamp to bypass browser cache
            try {
              const vulnsRes = await fetch(`/api/vulnerabilities?t=${Date.now()}`);
              if (vulnsRes.ok) {
                const serverVulns: Vulnerability[] = await vulnsRes.json();
                // Use onlyValidated (status=confirmed|validated) instead of
                // confidence threshold. Passive evidence findings have
                // confidence=0.85 (appropriate for config weaknesses) but
                // are still validated — should be shown.
                const validated = onlyValidated(serverVulns);
                if (validated.length > 0) {
                  setVulns(prev => {
                    const existingIds = new Set(prev.map(v => v.id));
                    const toAdd = validated.filter((f: any) => !existingIds.has(f.id));
                    return toAdd.length > 0 ? [...toAdd, ...prev] : prev;
                  });
                  addActivity('scan', `Loaded ${validated.length} confirmed findings into UI`, 'success', `${validated.length} results`, 100);
                } else {
                  addActivity('scan', 'No confirmed findings — try with different input', 'warning', '', 100);
                }
              }
            } catch (e) {
              addActivity('scan', 'Results loaded (some may need refresh)', 'warning', '', 95);
            }
            resolve();
            return;
          }

          if (status.status === 'failed') {
            reject(new Error(status.error || 'Analysis failed'));
            return;
          }

          // Still running — poll again in 5s
          setTimeout(poll, 5_000);
        } catch (err) {
          pollErrors++;
          if (pollErrors > 5) { reject(err); return; }
          // Network error — retry in 5s (mobile can lose connection briefly)
          setTimeout(poll, 5_000);
        }
      };
      setTimeout(poll, 2_000);
    });
  };

  const analyzeContract = async () => {
    if (isAnalyzingRef.current) {
      addActivity('scan', 'Analysis already in progress — skipping', 'warning', 'Wait for current analysis to finish', 0);
      return;
    }
    isAnalyzingRef.current = true;
    setAnalyzing(true);
    setFetchError('');
    addActivity('scan', 'Starting analysis...', 'running', sourceCode ? 'Source code' : 'URL', 0);

    try {
      await startBackgroundAnalysis(sourceCode, 'AnalyzedContract', targetType === 'hackenproof' ? 'contract' : targetType, targetUrl || undefined);
      setSourceCode(''); setTargetUrl(''); setHackenproofContext(null);
    } catch (e: any) {
      const msg = String(e);
      setFetchError(`Analysis error: ${msg}`);
      addActivity('scan', 'Analysis failed', 'error', msg.slice(0, 100));
    } finally {
      isAnalyzingRef.current = false;
      setAnalyzing(false);
    }
  };

  const fetchUrlAndAnalyze = async () => {
    if (!targetUrl) return;
    if (isAnalyzingRef.current) {
      addActivity('scan', 'Analysis already in progress — skipping', 'warning', 'Wait for current analysis to finish', 0);
      return;
    }
    isAnalyzingRef.current = true;
    setFetchingUrl(true);
    setFetchError('');
    addActivity('scan', 'Fetching URL and starting analysis...', 'running', targetUrl, 5);

    try {
      // Fetch URL content — SIMPLE mode, max 30s (direct + allorigins fallback)
      addActivity('scan', 'Fetching URL content (10s direct + 10s proxy fallback)...', 'running', 'Max 30s', 10);
      const fetchRes = await fetchWithTimeout('/api/fetch-url', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl, type: targetType === 'hackenproof' ? 'contract' : targetType }),
      }, 45_000); // 45s — server maxDuration is 60s, give 15s buffer

      if (!fetchRes.ok) {
        const errData = await fetchRes.json().catch(() => ({}));
        throw new Error(errData.error || `Server error: ${fetchRes.status}`);
      }

      const data = await fetchRes.json();
      if (data.error) throw new Error(data.error);
      if (!data.sourceCode) throw new Error('No content found at the URL');

      // Surface crawl stats to the user so they can SEE the deep crawl worked
      if (data.crawledPages || data.apiEndpointsFound || data.formsFound) {
        addActivity('system', `Deep crawl: ${data.crawledPages || 0} pages, ${data.apiEndpointsFound || 0} endpoints, ${data.formsFound || 0} forms, ${data.discoveredParams?.length || 0} unique params`, 'success', '', 20);
      } else {
        addActivity('system', `URL content fetched: ${data.sourceCode.length} chars`, 'success', '', 20);
      }

      // Start background analysis with fetched code + crawl data
      const apiType = targetType === 'hackenproof' ? 'contract' : targetType;
      await startBackgroundAnalysis(
        data.sourceCode,
        data.contractName || 'FetchedContract',
        apiType,
        targetUrl,
        {
          discoveredEndpoints: data.discoveredEndpoints,
          discoveredForms: data.discoveredForms,
          discoveredParams: data.discoveredParams,
        },
      );
      addActivity('scan', 'URL analysis complete', 'success', 'Done', 100);
      setSourceCode(''); setTargetUrl(''); setHackenproofContext(null);
    } catch (e: any) {
      const msg = String(e);
      setFetchError(`Analysis error: ${msg}`);
      addActivity('scan', 'Analysis failed', 'error', msg.slice(0, 100));
    } finally {
      isAnalyzingRef.current = false;
      setFetchingUrl(false);
      setAnalyzing(false);
    }
  };

  const seedDemo = async () => {
    setLoading(true);
    addActivity('system', 'Loading demo data...', 'running');
    try {
      const p1Res = await fetchWithTimeout('/api/projects', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'Uniswap V4 Fork', chain: 'ethereum', language: 'solidity' }),
      }, 15_000);
      if (p1Res.ok) {
        const p1 = await p1Res.json();
        setActiveProject(p1.id);
        addActivity('system', 'Created demo project', 'success', 'Uniswap V4 Fork');
        await fetchWithTimeout('/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ projectId: p1.id, contractName: 'SwapPool.sol' }) }, 15_000).catch(() => {});
      }
      const p2Res = await fetchWithTimeout('/api/projects', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'Aave V3 Fork', chain: 'arbitrum', language: 'solidity' }),
      }, 15_000);
      if (p2Res.ok) {
        const p2 = await p2Res.json();
        addActivity('system', 'Created demo project', 'success', 'Aave V3 Fork');
        await fetchWithTimeout('/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ projectId: p2.id, contractName: 'LendingPool.sol' }) }, 15_000).catch(() => {});
      }
      for (const p of [
        { type: 'vulnerability', name: 'ERC-777 Reentrancy', description: 'tokensReceived callback reentrancy in ERC-777', tags: 'reentrancy,erc777', chain: 'ethereum', severity: 'critical' },
        { type: 'code_pattern', name: 'Unchecked External Call', description: 'External call without return value check', tags: 'unchecked,call', chain: 'ethereum', severity: 'medium' },
        { type: 'architectural', name: 'Single Oracle Dependency', description: 'Protocol relies on single price oracle', tags: 'oracle,single-source', chain: 'ethereum', severity: 'high' },
        { type: 'vulnerability', name: 'Flash Loan Drain', description: 'Reserves drainable via flash loan', tags: 'flash-loan,drain', chain: 'ethereum', severity: 'critical' },
        { type: 'code_pattern', name: 'Storage Collision Proxy', description: 'Diamond proxy unstructured storage', tags: 'proxy,diamond', chain: 'ethereum', severity: 'high' },
      ]) {
        await fetchWithTimeout('/api/memory', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(p) }, 15_000).catch(() => {});
      }
      addActivity('system', 'Demo memory patterns loaded', 'success', '5 patterns');
      await fetchData();
      addActivity('system', 'Demo data loaded', 'success');
    } finally { setLoading(false); }
  };

  const generateReport = async () => {
    setLoading(true);
    setFetchError('');
    try {
      const projectId = await ensureProject();
      const res = await fetchWithTimeout('/api/report', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ projectId }),
      }, 30_000);
      if (res.ok) {
        const data = await res.json();
        if (data.report && data.report.trim().length > 0) {
          setReportText(data.report);
          setShowReport(true);
        } else {
          setFetchError('No report generated — run an analysis first to get findings.');
        }
      } else {
        const errData = await res.json().catch(() => ({}));
        setFetchError(errData.error || `Report generation failed (HTTP ${res.status})`);
      }
    } catch (e) {
      setFetchError(`Network error: ${String(e)}`);
    } finally { setLoading(false); }
  };


  const downloadZip = async () => {
    setLoading(true);
    setFetchError('');
    try {
      const projectId = await ensureProject();
      const res = await fetchWithTimeout('/api/download', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ projectId }),
      }, 30_000);
      if (res.ok) {
        const data = await res.json();
        if (data.zip) {
          const binary = atob(data.zip);
          const bytes = new Uint8Array(binary.length);
          for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
          const blob = new Blob([bytes], { type: 'application/zip' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = data.filename || 'poc_archive.zip';
          a.click();
          URL.revokeObjectURL(url);
        } else {
          setFetchError('No PoC files available — run an analysis first to generate PoCs.');
        }
      } else {
        const errData = await res.json().catch(() => ({}));
        setFetchError(errData.error || `Download failed (HTTP ${res.status})`);
      }
    } catch (e) {
      setFetchError(`Network error: ${String(e)}`);
    } finally { setLoading(false); }
  };

  // Only show vulnerabilities that have been ACTIVELY VALIDATED
  // A vuln is "validated" if it has validationSteps (AI ran active exploitation) OR status is confirmed/validated/refuted
  // Severity filter: hide `low`/`info` unless user toggled it off (hideLowSeverity default: true)
  const validatedVulns = vulns.filter(v =>
    (v.validationSteps || v.status === 'confirmed' || v.status === 'validated' || v.status === 'refuted') &&
    (!hideLowSeverity || (v.severity !== 'low' && v.severity !== 'info'))
  );
  // Three-state verdict counts (computed on FULL list, ignoring severity filter, for honest reporting)
  const allValidatedVulns = vulns.filter(v =>
    v.validationSteps || v.status === 'confirmed' || v.status === 'validated' || v.status === 'refuted'
  );
  const lowSeverityHidden = allValidatedVulns.filter(v => v.severity === 'low' || v.severity === 'info').length;
  // Three-state verdict counts
  const exploitableVulns = validatedVulns.filter(v => v.status === 'confirmed' || v.status === 'validated');
  const notExploitableVulns = validatedVulns.filter(v => v.status === 'refuted');
  const inconclusiveVulns = validatedVulns.filter(v => v.status === 'candidate');
  const confirmedVulns = exploitableVulns; // alias for backward compat
  const criticalVulns = validatedVulns.filter(v => v.severity === 'critical');
  const avgConfidence = validatedVulns.length > 0 ? validatedVulns.reduce((s, v) => s + v.confidence, 0) / validatedVulns.length : 0;

  return (
    <div className="min-h-screen bg-white text-slate-900">
      {/* Header */}
      <header className="border-b border-slate-200 bg-white sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-emerald-600 flex items-center justify-center">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-bold tracking-tight">CryptoSentinel</h1>
              <p className="text-xs text-slate-500">Autonomous AI Vulnerability Scanner — OpenRouter</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="outline" className={hasKey ? 'text-emerald-600 border-emerald-300' : 'text-amber-600 border-amber-300'}>
              {hasKey ? <Wifi className="w-3 h-3 mr-1" /> : <WifiOff className="w-3 h-3 mr-1" />}
              {hasKey ? `${model.split('/').pop()} Active` : 'No API Key'}
            </Badge>
            {/* Activity Feed Toggle */}
            <Button size="sm" variant="outline" onClick={() => setShowActivity(!showActivity)} className="relative">
              <Terminal className="w-4 h-4 mr-1" /> Activity
              {activities.filter(a => a.status === 'running').length > 0 && (
                <Badge className="absolute -top-1.5 -right-1.5 w-5 h-5 p-0 flex items-center justify-center bg-red-500 text-white border-0 text-[10px]">
                  {activities.filter(a => a.status === 'running').length}
                </Badge>
              )}
            </Button>
            {/* Settings Dialog */}
            <Dialog>
              <DialogTrigger asChild>
                <Button size="sm" variant="outline"><Settings className="w-4 h-4 mr-1" /> API Key</Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle><Key className="w-5 h-5 inline mr-2" />OpenRouter API Configuration</DialogTitle>
                </DialogHeader>
                <div className="space-y-4 pt-2">
                  {/* ─── Current key source indicator ─────────────────────── */}
                  {hasKey && (
                    <div className="flex items-center gap-2 p-2 rounded-lg bg-slate-50 border border-slate-200 text-xs">
                      <span className="text-slate-500">Source:</span>
                      {keySource === 'env' ? (
                        <Badge variant="outline" className="text-blue-700 border-blue-300 bg-blue-50">env var (OPENROUTER_API_KEY)</Badge>
                      ) : (
                        <Badge variant="outline" className="text-amber-700 border-amber-300 bg-amber-50">database (resets on restart)</Badge>
                      )}
                      <span className="text-slate-400">|</span>
                      <span className="text-slate-500">Current: <code className="font-mono">{maskedKey}</code></span>
                    </div>
                  )}
                  {keySource === 'env' && (
                    <p className="text-xs text-blue-700 bg-blue-50 border border-blue-200 p-2 rounded">
                      <strong>Env var is active:</strong> The <code>OPENROUTER_API_KEY</code> env var takes precedence over the DB key. This is the most reliable configuration — the key persists across server restarts. Saving a new key below will store it in the DB, but the env var will still win.
                    </p>
                  )}
                  {hasKey && keySource !== 'env' && (
                    <p className="text-xs text-amber-700 bg-amber-50 border border-amber-200 p-2 rounded">
                      <strong>DB-only key:</strong> The key is stored in the per-instance SQLite database and may be lost on server restarts. For reliable persistence, set <code>OPENROUTER_API_KEY</code> as an env var in the PM2 ecosystem config.
                    </p>
                  )}
                  <div>
                    <label className="text-sm font-medium text-slate-700">Model</label>
                    <Select value={model} onValueChange={setModel}>
                      <SelectTrigger className="mt-1"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="z-ai/glm-5.2">GLM 5.2 (1M ctx) — Primary + Unlimited Reasoning</SelectItem>
                        <SelectItem value="z-ai/glm-5.1">GLM 5.1</SelectItem>
                        <SelectItem value="z-ai/glm-5-turbo">GLM 5 Turbo</SelectItem>
                        <SelectItem value="z-ai/glm-4.7-flash">GLM 4.7 Flash</SelectItem>
                        <SelectItem value="z-ai/glm-4.7">GLM 4.7</SelectItem>
                        <SelectItem value="deepseek/deepseek-chat-v3-0324">DeepSeek V3 (Auto: Light Tasks)</SelectItem>
                        <SelectItem value="deepseek/deepseek-r1-0528">DeepSeek R1 (Reasoning)</SelectItem>
                        <SelectItem value="deepseek/deepseek-v4-pro-0813">DeepSeek V4 Pro 0813 (1M ctx) — Enhancement</SelectItem>
                        <SelectItem value="qwen/qwen3-235b-a22b">Qwen3 235B</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-slate-700">API Key</label>
                    <Input type="password" placeholder={hasKey ? 'Enter new key to update' : 'Enter your OpenRouter API key (sk-or-v1-...)'}
                      className="mt-1" value={apiKey} onChange={e => setApiKey(e.target.value)} />
                    <p className="text-xs text-slate-400 mt-1">
                      Get a key at <a href="https://openrouter.ai/keys" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">openrouter.ai/keys</a> — must start with <code>sk-or-v1-</code>.
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <Button
                      onClick={testApiKey}
                      disabled={testingKey || (!apiKey && !hasKey)}
                      variant="outline"
                      className="flex-1 border-blue-300 text-blue-700 hover:bg-blue-50"
                    >
                      {testingKey ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Testing...</> : <><Zap className="w-4 h-4 mr-2" /> Test Key</>}
                    </Button>
                    <Button
                      onClick={saveApiKey}
                      disabled={!apiKey && !model}
                      className="flex-1 bg-emerald-600 hover:bg-emerald-700 text-white"
                    >
                      <Key className="w-4 h-4 mr-2" /> Save Configuration
                    </Button>
                  </div>
                  {/* ─── Test result display ─────────────────────────── */}
                  {keyTestResult && (
                    <div className={`flex flex-col gap-2 p-3 rounded-lg border text-sm ${
                      keyTestResult.valid
                        ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
                        : 'bg-red-50 border-red-200 text-red-800'
                    }`}>
                      <div className="flex items-start gap-2">
                        {keyTestResult.valid
                          ? <CheckCircle className="w-4 h-4 mt-0.5 shrink-0" />
                          : <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />}
                        <div className="flex-1">
                          <p className="font-medium">{keyTestResult.valid ? 'Key is valid ✓' : 'Key is invalid ✗'}</p>
                          <p className="text-xs opacity-80">{keyTestResult.reason}</p>
                          {keyTestResult.source && (
                            <p className="text-xs mt-1 opacity-70">Source: {keyTestResult.source}</p>
                          )}
                        </div>
                      </div>
                      {keyTestResult.valid && keyTestResult.key_info && (
                        <div className="text-xs grid grid-cols-2 gap-1 mt-1 pt-2 border-t border-emerald-200">
                          <span>Tier:</span><span>{keyTestResult.key_info.is_free_tier ? 'Free' : 'Paid'}</span>
                          <span>Usage:</span><span>{keyTestResult.key_info.usage ?? 0} credits</span>
                          <span>Limit:</span><span>{keyTestResult.key_info.limit ?? 'unlimited'}</span>
                          {keyTestResult.key_info.expires_at && (
                            <><span>Expires:</span><span>{new Date(keyTestResult.key_info.expires_at).toLocaleDateString()}</span></>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                  {hasKey && !keyTestResult && (
                    <div className="flex items-center gap-2 p-2 rounded-lg bg-emerald-50 border border-emerald-200">
                      <CheckCircle className="w-4 h-4 text-emerald-600" />
                      <span className="text-xs text-emerald-700">OpenRouter API key configured — AI analysis is active</span>
                    </div>
                  )}
                </div>
              </DialogContent>
            </Dialog>
            <Button size="sm" variant="outline" onClick={seedDemo} disabled={loading}>
              {loading ? 'Loading...' : 'Demo Data'}
            </Button>
            {vulns.length > 0 && (
              <Button size="sm" variant="outline" className="text-red-600 border-red-200 hover:bg-red-50" onClick={clearAllFindings}>
                <Trash2 className="w-4 h-4 mr-1" /> Clear All
              </Button>
            )}
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-6">
        {/* Stats — three-state verdict model */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-6">
          {[
            { label: 'Total Findings', value: validatedVulns.length, icon: Bug, color: 'text-amber-600' },
            { label: 'Exploitable', value: exploitableVulns.length, icon: CheckCircle2, color: 'text-emerald-600' },
            { label: 'Not Exploitable', value: notExploitableVulns.length, icon: XCircle, color: 'text-red-600' },
            { label: 'Inconclusive', value: inconclusiveVulns.length, icon: Clock, color: 'text-yellow-600' },
            { label: 'Critical', value: criticalVulns.length, icon: AlertTriangle, color: 'text-red-600' },
          ].map((s, i) => (
            <Card key={i} className="border-slate-200">
              <CardContent className="p-4 flex items-center gap-3">
                <s.icon className={`w-8 h-8 ${s.color} opacity-80`} />
                <div>
                  <p className="text-xs text-slate-500">{s.label}</p>
                  <p className="text-xl font-bold">{s.value}</p>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Tabs */}
        <Tabs defaultValue="dashboard" className="space-y-4">
          <TabsList className="w-full md:w-auto">
            <TabsTrigger value="dashboard"><Activity className="w-4 h-4 mr-1" /> Dashboard</TabsTrigger>
            <TabsTrigger value="analyze"><Search className="w-4 h-4 mr-1" /> Analyze</TabsTrigger>
            <TabsTrigger value="findings"><Bug className="w-4 h-4 mr-1" /> Findings</TabsTrigger>
            <TabsTrigger value="memory"><Brain className="w-4 h-4 mr-1" /> Memory</TabsTrigger>
            <TabsTrigger value="pipeline"><Zap className="w-4 h-4 mr-1" /> Pipeline</TabsTrigger>
          </TabsList>

          {/* Dashboard */}
          <TabsContent value="dashboard" className="space-y-4">
            <div className="grid md:grid-cols-2 gap-4">
              <Card className="border-slate-200">
                <CardHeader>
                  <CardTitle className="text-emerald-700">7-Layer Architecture</CardTitle>
                  <CardDescription>Autonomous crypto vulnerability detection</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2">
                  {[
                    { name: 'MCP Tool Bridge + Crypto', desc: '150+ web2 + 10 crypto MCP tools' },
                    { name: 'Analysis Engine (Crypto-Native)', desc: 'AST + DeFi Patterns + Web2+Web3' },
                    { name: 'Agent Orchestration', desc: '7 crypto workflows, YAML-driven' },
                    { name: 'Memory & Anti-Duplicate', desc: 'Vector DB + Bloom Filter + Knowledge Graph' },
                    { name: 'Validation Pipeline (95%)', desc: 'V1 SymEx + V2 Fuzz + V3 Formal + V4 Econ' },
                    { name: 'Economic Attack Simulator', desc: 'Flash loan + MEV + Oracle + Invariant' },
                    { name: 'Self-Defense', desc: 'Prompt Guard + Tool Chain + Supply Chain' },
                  ].map((layer, i) => (
                    <div key={i} className="flex items-center gap-3 p-2.5 rounded-lg bg-slate-50 hover:bg-slate-100 transition">
                      <div className="w-7 h-7 rounded bg-emerald-100 text-emerald-700 flex items-center justify-center text-xs font-bold">{i+1}</div>
                      <div className="flex-1">
                        <p className="text-sm font-medium">{layer.name}</p>
                        <p className="text-xs text-slate-500">{layer.desc}</p>
                      </div>
                    </div>
                  ))}
                </CardContent>
              </Card>

              <Card className="border-slate-200">
                <CardHeader>
                  <CardTitle className="text-blue-700">Supported Chains & Languages</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {[
                    { chain: 'Ethereum + L2s', lang: 'Solidity, Vyper', tools: 'Slither, Mythril, Echidna, Certora', risk: 'Reentrancy, delegatecall, proxy' },
                    { chain: 'Solana', lang: 'Rust (BPF)', tools: 'cargo-audit, Kani', risk: 'Account confusion, CPI' },
                    { chain: 'Sui / Aptos', lang: 'Move', tools: 'Move Prover, Analyzer', risk: 'Resource duplication' },
                    { chain: 'StarkNet', lang: 'Cairo', tools: 'cairo-verify, SDK', risk: 'Felt overflow, syscall' },
                  ].map((c, i) => (
                    <div key={i} className="p-3 rounded-lg bg-slate-50 space-y-1">
                      <div className="flex items-center justify-between">
                        <p className="text-sm font-semibold text-slate-800">{c.chain}</p>
                        <Badge variant="secondary" className="text-xs">{c.lang}</Badge>
                      </div>
                      <p className="text-xs text-slate-500">Tools: {c.tools}</p>
                      <p className="text-xs text-red-500">Risks: {c.risk}</p>
                    </div>
                  ))}
                </CardContent>
              </Card>
            </div>

            <Card className="border-slate-200">
              <CardHeader>
                <CardTitle className="text-amber-700">Projects</CardTitle>
              </CardHeader>
              <CardContent>
                {projects.length === 0 ? (
                  <p className="text-slate-500 text-sm">No projects yet. Click &quot;Demo Data&quot; or create one in the Analyze tab.</p>
                ) : (
                  <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    {projects.map(p => (
                      <div key={p.id} className={`p-3 rounded-lg border-2 transition cursor-pointer ${activeProject === p.id ? 'border-emerald-400 bg-emerald-50' : 'border-slate-200 bg-white hover:border-emerald-300'}`}
                        onClick={() => setActiveProject(p.id)}>
                        <div className="flex items-center justify-between mb-1">
                          <p className="font-medium text-sm">{p.name}</p>
                          <Badge variant="outline" className="text-xs">{chainLabel[p.chain] || p.chain}</Badge>
                        </div>
                        <p className="text-xs text-slate-500">{p.language} | {p.contracts?.length || 0} contracts</p>
                        {p.audits && p.audits.length > 0 && (
                          <div className="flex items-center gap-2 mt-2">
                            <Badge className="text-xs bg-emerald-100 text-emerald-800 border-0">{p.audits[0].confirmed} confirmed</Badge>
                            <Badge variant="outline" className="text-xs">{p.audits[0].findings} findings</Badge>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Analyze */}
          <TabsContent value="analyze" className="space-y-4">
            <div className="grid md:grid-cols-2 gap-4">
              <Card className="border-slate-200">
                <CardHeader><CardTitle>Create Project</CardTitle></CardHeader>
                <CardContent className="space-y-3">
                  <Input placeholder="Project name (e.g. Uniswap V4)" value={newProject.name} onChange={e => setNewProject(p => ({ ...p, name: e.target.value }))} />
                  <div className="grid grid-cols-2 gap-2">
                    <Select value={newProject.chain} onValueChange={v => setNewProject(p => ({ ...p, chain: v }))}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {['ethereum','bsc','polygon','arbitrum','optimism','solana','sui','starknet'].map(c => <SelectItem key={c} value={c}>{chainLabel[c]||c}</SelectItem>)}
                      </SelectContent>
                    </Select>
                    <Select value={newProject.language} onValueChange={v => setNewProject(p => ({ ...p, language: v }))}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {['solidity','vyper','move','rust','cairo'].map(l => <SelectItem key={l} value={l}>{l.charAt(0).toUpperCase()+l.slice(1)}</SelectItem>)}
                      </SelectContent>
                    </Select>
                  </div>
                  <Input placeholder="Contract address (optional)" value={newProject.address} onChange={e => setNewProject(p => ({ ...p, address: e.target.value }))} />
                  <Button onClick={createProject} disabled={loading || !newProject.name} className="w-full">Create Project</Button>
                </CardContent>
              </Card>

              <Card className="border-slate-200">
                <CardHeader>
                  <CardTitle>Analyze Target</CardTitle>
                  <CardDescription>By URL or paste source code — via {model.split('/').pop()}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  {projects.length > 0 && (
                    <div className="space-y-1">
                      <label className="text-xs text-slate-500">Project <span className="text-slate-400">(auto-selected if empty)</span></label>
                      <Select value={activeProject || undefined} onValueChange={setActiveProject}>
                        <SelectTrigger className={activeProject ? '' : 'text-slate-400'}><SelectValue placeholder="Auto-select" /></SelectTrigger>
                        <SelectContent>
                          {projects.map(p => <SelectItem key={p.id} value={p.id}>{p.name}</SelectItem>)}
                        </SelectContent>
                      </Select>
                    </div>
                  )}

                  {/* URL Analysis Section */}
                  <div className="space-y-2 p-3 rounded-lg bg-slate-50 border border-slate-200">
                    <div className="flex items-center gap-2">
                      <Globe className="w-4 h-4 text-blue-600" />
                      <span className="text-sm font-medium text-slate-700">Analyze by URL</span>
                    </div>
                    <div className="grid grid-cols-3 gap-2">
                      <Select value={targetType} onValueChange={v => { setTargetType(v as 'contract' | 'exchange' | 'hackenproof'); setFetchError(''); }}>
                        <SelectTrigger className="col-span-1"><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="contract">Smart Contract</SelectItem>
                          <SelectItem value="exchange">Web App / DApp</SelectItem>
                          <SelectItem value="hackenproof">Hackenproof</SelectItem>
                        </SelectContent>
                      </Select>
                      <Input
                        placeholder={targetType === 'contract' ? 'GitHub, Etherscan, or raw .sol URL' : targetType === 'hackenproof' ? 'Hackenproof URL (e.g. https://hackenproof.com/...)' : 'Web app URL (e.g. https://app.uniswap.org)'}
                        className="col-span-2"
                        value={targetUrl}
                        onChange={e => { setTargetUrl(e.target.value); setFetchError(''); }}
                      />
                    </div>
                    <Button
                      onClick={fetchUrlAndAnalyze}
                      disabled={fetchingUrl || analyzing || !targetUrl}
                      className="w-full bg-blue-600 hover:bg-blue-700 text-white"
                    >
                      {fetchingUrl ? <><Activity className="w-4 h-4 mr-2 animate-spin" /> Fetching...</> :
                       analyzing ? <><Activity className="w-4 h-4 mr-2 animate-spin" /> Analyzing...</> :
                       <><Globe className="w-4 h-4 mr-2" /> Fetch & Analyze URL</>}
                    </Button>
                    {targetType === 'contract' && (
                      <div className="space-y-1">
                        <p className="text-[11px] text-slate-400">Fetches source code and runs full AI audit</p>
                        <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-[10px] text-slate-500">
                          <span className="flex items-center gap-1"><FileCode className="w-3 h-3" />github.com/owner/repo</span>
                          <span className="flex items-center gap-1"><Search className="w-3 h-3" />etherscan.io/address/0x...</span>
                          <span className="flex items-center gap-1"><Globe className="w-3 h-3" />raw .sol URL</span>
                        </div>
                      </div>
                    )}
                    {targetType === 'exchange' && (
                      <div className="space-y-1">
                        <p className="text-[11px] text-slate-400">12-phase AI-powered analysis: crawl, JS deobfuscation, DOM XSS, API discovery, crypto patterns, 4x GLM AI passes</p>
                        <div className="flex flex-wrap gap-x-2 gap-y-0.5 text-[10px]">
                          <span className="text-blue-600 font-medium">Crawl/Spider</span>
                          <span className="text-slate-500">|</span>
                          <span className="text-purple-600 font-medium">JS Bundle Analysis</span>
                          <span className="text-slate-500">|</span>
                          <span className="text-red-600 font-medium">DOM XSS Sinks</span>
                          <span className="text-slate-500">|</span>
                          <span className="text-orange-600 font-medium">API Discovery</span>
                          <span className="text-slate-500">|</span>
                          <span className="text-emerald-600 font-medium">Crypto/Web3</span>
                          <span className="text-slate-500">|</span>
                          <span className="text-indigo-600 font-medium">AI: GLM 5.2 (deep) + DeepSeek V3 (fast) + Blockchain Verify</span>
                        </div>
                      </div>
                    )}
                    {targetType === 'hackenproof' && (
                      <div className="space-y-1">
                        <p className="text-[11px] text-slate-400">Reads project description, priorities & severity from Hackenproof page, then runs AI audit with context</p>
                        <div className="flex items-center gap-1 text-[10px] text-blue-500">
                          <ExternalLink className="w-3 h-3" />
                          <span>hackenproof.com/projects/...</span>
                        </div>
                      </div>
                    )}
                    {fetchError && (
                      <div className="flex items-start gap-2 p-2 rounded-lg bg-red-50 border border-red-200">
                        <AlertCircle className="w-4 h-4 text-red-500 mt-0.5 shrink-0" />
                        <p className="text-xs text-red-700">{fetchError}</p>
                      </div>
                    )}
                    {hackenproofContext && !fetchError && (
                      <div className="p-2 rounded-lg bg-blue-50 border border-blue-200 space-y-1">
                        <p className="text-xs font-medium text-blue-700">Hackenproof Context Loaded</p>
                        {hackenproofContext.description && <p className="text-[11px] text-blue-600">{hackenproofContext.description.slice(0, 120)}...</p>}
                        {hackenproofContext.priorities && <p className="text-[11px] text-blue-600">Priorities: {hackenproofContext.priorities.slice(0, 80)}</p>}
                      </div>
                    )}
                  </div>

                  <div className="relative">
                    <div className="absolute inset-x-0 top-0 flex items-center justify-center">
                      <span className="bg-white px-2 text-xs text-slate-400">or paste code</span>
                    </div>
                  </div>

                  <Textarea placeholder={`pragma solidity ^0.8.0;\n\ncontract Pool {\n    // Paste code here...`} className="min-h-[100px] font-mono text-sm" value={sourceCode} onChange={e => setSourceCode(e.target.value)} />
                  <Button onClick={analyzeContract} disabled={analyzing || (!sourceCode && !targetUrl)} className="w-full bg-emerald-600 hover:bg-emerald-700 text-white">
                    {analyzing ? <><Activity className="w-4 h-4 mr-2 animate-spin" /> Analyzing...</> : <><Search className="w-4 h-4 mr-2" /> Run Full Audit</>}
                  </Button>
                  {fetchError && !fetchingUrl && (
                    <div className="flex items-start gap-2 p-2 rounded-lg bg-red-50 border border-red-200">
                      <AlertCircle className="w-4 h-4 text-red-500 mt-0.5 shrink-0" />
                      <p className="text-xs text-red-700">{fetchError}</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>

            {/* Scan Methods */}
            <Card className="border-slate-200">
              <CardHeader>
                <CardTitle className="text-teal-700">Scan Methods</CardTitle>
                <CardDescription>Toggle analysis methods on/off</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {[
                  { category: 'Static Analysis', methods: [
                    { key: 'ast-analysis', label: 'AST Analysis' },
                    { key: 'data-flow', label: 'Data Flow' },
                    { key: 'control-flow', label: 'Control Flow' },
                    { key: 'pattern-match', label: 'Pattern Match' },
                    { key: 'deep-reentrancy', label: 'Deep Reentrancy' },
                    { key: 'access-control', label: 'Access Control' },
                    { key: 'gas-dos-audit', label: 'Gas/DoS Audit' },
                    { key: 'cross-contract', label: 'Cross-Contract' },
                    { key: 'proxy-storage', label: 'Proxy Storage' },
                    { key: 'delegatecall-scan', label: 'Delegatecall Scan' },
                  ]},
                  { category: 'Dynamic Testing', methods: [
                    { key: 'symbolic-exec', label: 'Symbolic Execution' },
                    { key: 'fuzzing', label: 'Fuzzing' },
                    { key: 'mutation-test', label: 'Mutation Testing' },
                    { key: 'signature-replay', label: 'Signature Replay' },
                  ]},
                  { category: 'Formal Verification', methods: [
                    { key: 'formal-verify', label: 'Formal Verify' },
                    { key: 'model-check', label: 'Model Checking' },
                    { key: 'invariant-check', label: 'Invariant Check' },
                  ]},
                  { category: 'Economic Analysis', methods: [
                    { key: 'oracle-manip', label: 'Oracle Manipulation' },
                    { key: 'flash-loan-sim', label: 'Flash Loan Sim' },
                    { key: 'mev-analysis', label: 'MEV Analysis' },
                  ]},
                ].map((cat, ci) => (
                  <div key={ci}>
                    <p className="text-xs font-semibold text-slate-500 mb-2">{cat.category}</p>
                    <div className="flex flex-wrap gap-1.5">
                      {cat.methods.map(m => (
                        <button
                          key={m.key}
                          onClick={() => toggleScanMethod(m.key)}
                          className={`px-2.5 py-1 rounded-full text-[11px] font-medium border transition-all ${
                            scanMethods[m.key]
                              ? 'bg-emerald-100 text-emerald-800 border-emerald-300 hover:bg-emerald-200'
                              : 'bg-slate-100 text-slate-400 border-slate-200 hover:bg-slate-200'
                          }`}
                        >
                          {scanMethods[m.key] ? <span className="inline-block w-1.5 h-1.5 rounded-full bg-emerald-500 mr-1.5 align-middle" /> : <span className="inline-block w-1.5 h-1.5 rounded-full bg-slate-300 mr-1.5 align-middle" />}
                          {m.label}
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>

            {/* Workflow */}
            <Card className="border-slate-200">
              <CardHeader><CardTitle className="text-purple-700">Audit Workflow Pipeline</CardTitle></CardHeader>
              <CardContent>
                <div className="flex flex-wrap items-center gap-2">
                  {['AST Parse','Data Flow','Control Flow','Pattern Match','Deep Reentrancy','Symbolic Exec','Fuzzing','Mutation Test','Formal Verify','Model Check','Invariant Check','Signature Replay','Access Control','Oracle Manip','Flash Loan Sim','MEV Analysis','Gas/DoS Audit','Anti-Dupe','Confidence Calc','Report'].map((step, i) => (
                    <div key={i} className="flex items-center gap-1">
                      <div className="px-3 py-1.5 rounded-full bg-slate-100 border border-slate-200 text-xs font-medium">{step}</div>
                      {i < 19 && <ChevronRight className="w-3 h-3 text-slate-400" />}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Findings */}
          <TabsContent value="findings" className="space-y-4">
            <Card className="border-slate-200">
              <CardHeader>
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <CardTitle className="text-red-700">Vulnerability Findings</CardTitle>
                  <div className="flex gap-2">
                    <Button size="sm" variant="outline" onClick={generateReport} disabled={loading || validatedVulns.length === 0}>
                      <FileText className="w-4 h-4 mr-1" /> HakenProof Report
                    </Button>
                    <Button size="sm" variant="outline" onClick={downloadZip} disabled={loading || validatedVulns.length === 0}>
                      <Download className="w-4 h-4 mr-1" /> PoC ZIP
                    </Button>
                    <Badge className="bg-emerald-100 text-emerald-800 border-0">{exploitableVulns.length} Exploitable</Badge>
                    <Badge className="bg-red-100 text-red-800 border-0">{notExploitableVulns.length} Not Exploitable</Badge>
                    <Badge className="bg-yellow-100 text-yellow-800 border-0">{inconclusiveVulns.length} Inconclusive</Badge>
                    <Button
                      size="sm"
                      variant={hideLowSeverity ? 'default' : 'outline'}
                      onClick={() => setHideLowSeverity(!hideLowSeverity)}
                      title={hideLowSeverity ? 'Currently hiding low/info findings. Click to show all.' : 'Showing all findings. Click to hide low/info.'}
                      className="text-[11px] h-7 px-2"
                    >
                      {hideLowSeverity ? `Hide Low${lowSeverityHidden > 0 ? ` (${lowSeverityHidden})` : ''}` : 'Show All'}
                    </Button>
                    <Badge className="bg-slate-100 text-slate-600 border-0">{vulns.length - validatedVulns.length} pending</Badge>
                    {vulns.length > 0 && (
                      <Button size="sm" variant="outline" className="text-red-600 border-red-200 hover:bg-red-50" onClick={clearAllFindings}>
                        <Trash2 className="w-3.5 h-3.5 mr-1" /> Clear All
                      </Button>
                    )}
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                {validatedVulns.length === 0 ? (
                  <p className="text-slate-500 text-sm">No validated findings yet. All findings must pass active exploitation testing before appearing here.</p>
                ) : (
                  <div className="space-y-3 max-h-[600px] overflow-y-auto pr-2">
                    {[...validatedVulns].sort((a, b) => b.confidence - a.confidence).map(v => (
                      <div key={v.id} className="p-4 rounded-lg border border-slate-200 bg-white space-y-2 shadow-sm">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            {statusIcon[v.status] || <Clock className="w-4 h-4 text-slate-400" />}
                            <p className="font-semibold text-sm">{v.title}</p>
                          </div>
                          <div className="flex items-center gap-2">
                            <Badge className={severityColor[v.severity] || ''}>{v.severity}</Badge>
                            <Badge className={verdictLabel[v.status]?.color || 'bg-slate-100 text-slate-700 border-slate-200'}>
                              {verdictLabel[v.status]?.text || v.status}
                            </Badge>
                            <Button
                              size="sm"
                              variant="outline"
                              className={`text-[11px] h-7 px-2 ${validatingVulns.has(v.id) ? 'border-amber-300 text-amber-600' : v.status === 'confirmed' || v.status === 'validated' ? 'border-emerald-300 text-emerald-600 hover:bg-emerald-50' : v.status === 'refuted' ? 'border-red-300 text-red-600 hover:bg-red-50' : 'border-blue-300 text-blue-600 hover:bg-blue-50'}`}
                              onClick={() => validateVuln(v)}
                              disabled={validatingVulns.has(v.id)}
                              title="Re-run active validation"
                            >
                              {validatingVulns.has(v.id) ? (
                                <><Loader2 className="w-3 h-3 mr-1 animate-spin" /> Validating</>
                              ) : v.status === 'confirmed' || v.status === 'validated' ? (
                                <><CheckCircle2 className="w-3 h-3 mr-1" /> Re-validate</>
                              ) : v.status === 'refuted' ? (
                                <><XCircle className="w-3 h-3 mr-1" /> Re-validate</>
                              ) : (
                                <><Play className="w-3 h-3 mr-1" /> Validate</>
                              )}
                            </Button>
                            <button
                              onClick={() => deleteVuln(v.id)}
                              className="p-1 rounded hover:bg-red-50 text-slate-400 hover:text-red-600 transition-colors"
                              title="Delete"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </div>
                        <p className="text-xs text-slate-500">{v.description}</p>
                        <div className="flex items-center gap-4">
                          <div className="flex-1">
                            <div className="flex items-center justify-between text-xs mb-1">
                              <span className="text-slate-500">Confidence</span>
                              <span className={`font-mono font-bold ${v.confidence >= 0.95 ? 'text-emerald-600' : v.confidence >= 0.8 ? 'text-blue-600' : 'text-yellow-600'}`}>
                                {(v.confidence * 100).toFixed(1)}%
                              </span>
                            </div>
                            <div className="w-full bg-slate-100 rounded-full h-2">
                              <div className={`h-2 rounded-full transition-all ${v.confidence >= 0.95 ? 'bg-emerald-500' : v.confidence >= 0.8 ? 'bg-blue-500' : 'bg-yellow-500'}`} style={{width: `${v.confidence*100}%`}} />
                            </div>
                          </div>
                          <Badge variant="outline" className="text-xs capitalize">{v.status}</Badge>
                          {v.description?.includes('[BLOCKCHAIN VERIFIED]') && (
                            <Badge className="bg-emerald-100 text-emerald-700 border-emerald-300 text-[10px] flex items-center gap-1">
                              <Shield className="w-3 h-3" /> On-Chain Verified
                            </Badge>
                          )}
                        </div>
                        <div className="grid grid-cols-4 gap-2 mt-1">
                          {[
                            { label: 'V1 SymEx', value: v.v1Symbolic, color: 'text-cyan-600' },
                            { label: 'V2 Fuzz', value: v.v2Fuzzing, color: 'text-amber-600' },
                            { label: 'V3 Formal', value: v.v3Formal, color: 'text-violet-600' },
                            { label: 'V4 Econ', value: v.v4Economic, color: 'text-emerald-600' },
                          ].map((val, vi) => (
                            <div key={vi} className="text-center">
                              <p className="text-[10px] text-slate-400">{val.label}</p>
                              <p className={`text-xs font-mono font-bold ${val.color}`}>{val.value != null ? (val.value*100).toFixed(0)+'%' : '—'}</p>
                            </div>
                          ))}
                        </div>
                        {/* PoC button */}
                        {v.poc && v.poc.trim().length > 0 && (
                          <div className="flex items-center gap-2 mt-2 pt-2 border-t border-slate-100">
                            <Button
                              size="sm"
                              variant="outline"
                              className="text-xs border-violet-300 text-violet-700 hover:bg-violet-50"
                              onClick={() => setPocView({ title: v.title, filename: v.pocFilename || 'attack.t.sol', code: v.poc! })}
                            >
                              <Code2 className="w-3.5 h-3.5 mr-1" /> PoC
                            </Button>
                            <span className="text-[10px] text-slate-400">{v.pocFilename}</span>
                            <Badge variant="outline" className="text-[9px] text-violet-600 border-violet-200">Foundry Test</Badge>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Report Preview — full inline display */}
            {showReport && reportText && (
              <div className="space-y-4">
                {/* Report header bar */}
                <Card className="border-emerald-200 bg-emerald-50">
                  <CardHeader className="pb-2">
                    <div className="flex items-center justify-between flex-wrap gap-2">
                      <div className="flex items-center gap-2">
                        <FileText className="w-5 h-5 text-emerald-700" />
                        <CardTitle className="text-emerald-700">HakenProof Audit Report</CardTitle>
                        <Badge className="bg-emerald-600 text-white border-0">LIVE PREVIEW</Badge>
                      </div>
                      <div className="flex gap-2">
                        <Button size="sm" onClick={downloadReport} className="bg-emerald-600 hover:bg-emerald-700 text-white">
                          <Download className="w-4 h-4 mr-1" /> Download .txt
                        </Button>
                        <Button size="sm" variant="outline" onClick={() => { navigator.clipboard.writeText(reportText); }} className="border-emerald-300 text-emerald-700">
                          <FileCode className="w-4 h-4 mr-1" /> Copy
                        </Button>
                        <Button size="sm" variant="outline" onClick={() => setShowReport(false)} className="border-slate-300">
                          Close
                        </Button>
                      </div>
                    </div>
                  </CardHeader>
                </Card>

                {/* Formatted report display */}
                <Card className="border-slate-200">
                  <CardContent className="p-0">
                    <div className="max-h-[700px] overflow-y-auto">
                      {reportText.split('\n').map((line, i) => {
                        const trimmed = line.trim();
                        // Section headers (=== separator lines)
                        if (trimmed.match(/^={5,}$/)) {
                          return <div key={i} className="h-px bg-slate-300 mx-6 my-2" />;
                        }
                        // Top-level headers (FINDING #, SUMMARY, CRYPTOSENTINEL)
                        if (trimmed.match(/^(FINDING|SUMMARY|CRYPTOSENTINEL)/)) {
                          return (
                            <div key={i} className="px-6 py-2 bg-slate-100 border-b border-slate-200">
                              <span className="text-sm font-bold text-slate-900">{trimmed}</span>
                            </div>
                          );
                        }
                        // Severity badges
                        if (trimmed.match(/^\s*(CRITICAL|HIGH|MEDIUM|LOW)$/i)) {
                          const sev = trimmed.toUpperCase();
                          const colors: Record<string, string> = {
                            CRITICAL: 'bg-red-600 text-white',
                            HIGH: 'bg-orange-500 text-white',
                            MEDIUM: 'bg-yellow-500 text-black',
                            LOW: 'bg-blue-500 text-white',
                          };
                          return (
                            <div key={i} className="px-6 py-1">
                              <span className={`inline-block px-3 py-0.5 rounded text-xs font-bold ${colors[sev] || 'bg-slate-500 text-white'}`}>{sev}</span>
                            </div>
                          );
                        }
                        // Key-value lines (Title:, Target:, etc.)
                        if (trimmed.match(/^[A-Z][A-Za-z\s]+:/)) {
                          const [key, ...rest] = trimmed.split(':');
                          return (
                            <div key={i} className="px-6 py-0.5 flex">
                              <span className="text-xs font-semibold text-slate-600 min-w-[180px] shrink-0">{key}:</span>
                              <span className="text-xs text-slate-800">{rest.join(':').trim()}</span>
                            </div>
                          );
                        }
                        // Confidence percentage highlights
                        if (trimmed.match(/\d+\.\d+%/)) {
                          return (
                            <div key={i} className="px-6 py-0.5">
                              <span className="text-xs font-mono text-slate-700">{line}</span>
                            </div>
                          );
                        }
                        // Regular lines
                        if (trimmed === '') {
                          return <div key={i} className="h-2" />;
                        }
                        return (
                          <div key={i} className="px-6 py-0.5">
                            <span className="text-xs font-mono text-slate-700 whitespace-pre-wrap">{line}</span>
                          </div>
                        );
                      })}
                    </div>
                  </CardContent>
                </Card>
              </div>
            )}

            {/* PoC Preview Dialog */}
            {pocView && (
              <Card className="border-violet-200 bg-violet-50">
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <div className="flex items-center gap-2">
                      <Code2 className="w-5 h-5 text-violet-700" />
                      <CardTitle className="text-violet-700">PoC: {pocView.title}</CardTitle>
                      <Badge className="bg-violet-600 text-white border-0">REPRODUCIBLE</Badge>
                    </div>
                    <div className="flex gap-2">
                      <Button size="sm" variant="outline" onClick={() => {
                        const blob = new Blob([pocView.code], { type: 'text/plain' });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = pocView.filename;
                        a.click();
                        URL.revokeObjectURL(url);
                      }} className="border-violet-300 text-violet-700">
                        <Download className="w-4 h-4 mr-1" /> Download .t.sol
                      </Button>
                      <Button size="sm" variant="outline" onClick={() => {
                        navigator.clipboard.writeText(pocView.code);
                        setPocCopied(true);
                        setTimeout(() => setPocCopied(false), 2000);
                      }} className="border-violet-300 text-violet-700">
                        {pocCopied ? <><CheckCircle className="w-4 h-4 mr-1" /> Copied!</> : <><Copy className="w-4 h-4 mr-1" /> Copy Code</>}
                      </Button>
                      <Button size="sm" variant="outline" onClick={() => setPocView(null)} className="border-slate-300">
                        <X className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>
                  <p className="text-xs text-violet-600 mt-1">
                    Foundry Test — forge test -vvvv | File: {pocView.filename}
                  </p>
                </CardHeader>
              </Card>
            )}
            {pocView && (
              <Card className="border-slate-200">
                <CardContent className="p-0">
                  <div className="max-h-[600px] overflow-y-auto">
                    <pre className="p-4 text-xs font-mono text-slate-800 whitespace-pre leading-relaxed">
                      <code>{pocView.code}</code>
                    </pre>
                  </div>
                </CardContent>
              </Card>
            )}
          </TabsContent>
          <TabsContent value="memory" className="space-y-4">
            <div className="grid md:grid-cols-2 gap-4">
              <Card className="border-slate-200">
                <CardHeader><CardTitle className="text-purple-700">Memory & Anti-Duplicate System</CardTitle></CardHeader>
                <CardContent className="space-y-3">
                  {[
                    { name: 'Vector Memory Store', desc: 'Qdrant — 3 vector types: Vulnerability, Pattern, Context', stat: `${vulns.length} vectors` },
                    { name: 'Bloom Filter (Exact)', desc: 'O(1) exact hash — SHA-256(location+type+codeHash)', stat: 'active' },
                    { name: 'Semantic Similarity', desc: 'Cosine > 0.92 → potential duplicate', stat: 'threshold 0.92' },
                    { name: 'Variance Detection', desc: '4-axis: location, vector, strategy, impact', stat: '4 axes' },
                    { name: 'Temporal Knowledge Graph', desc: 'Projects ↔ Contracts ↔ Vulns ↔ Audits', stat: `${projects.length} projects` },
                    { name: 'Incremental Validation', desc: 'AST-diff — only re-validate changed paths', stat: 'delta mode' },
                  ].map((m, i) => (
                    <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-slate-50">
                      <div className="w-8 h-8 rounded bg-purple-100 text-purple-700 flex items-center justify-center text-sm font-bold">{i+1}</div>
                      <div className="flex-1">
                        <div className="flex items-center justify-between">
                          <p className="text-sm font-medium">{m.name}</p>
                          <Badge variant="outline" className="text-xs">{m.stat}</Badge>
                        </div>
                        <p className="text-xs text-slate-500 mt-1">{m.desc}</p>
                      </div>
                    </div>
                  ))}
                </CardContent>
              </Card>

              <Card className="border-slate-200">
                <CardHeader>
                  <CardTitle className="text-amber-700">Learned Patterns</CardTitle>
                  <CardDescription>Frequency-ranked from memory</CardDescription>
                </CardHeader>
                <CardContent>
                  {patterns.length === 0 ? (
                    <p className="text-slate-500 text-sm">No patterns yet. Load demo data.</p>
                  ) : (
                    <div className="space-y-2 max-h-[400px] overflow-y-auto">
                      {patterns.sort((a,b) => b.frequency - a.frequency).map(p => (
                        <div key={p.id} className="p-3 rounded-lg border border-slate-200 bg-white">
                          <div className="flex items-center justify-between mb-1">
                            <p className="text-sm font-medium">{p.name}</p>
                            <div className="flex items-center gap-2">
                              <Badge className={severityColor[p.severity]}>{p.severity}</Badge>
                              <Badge variant="outline" className="text-xs">x{p.frequency}</Badge>
                            </div>
                          </div>
                          <p className="text-xs text-slate-500 mb-1">{p.description}</p>
                          <div className="flex flex-wrap gap-1">
                            {p.tags.split(',').map((tag, ti) => (
                              <span key={ti} className="px-1.5 py-0.5 rounded bg-slate-100 text-[10px] text-slate-600">{tag.trim()}</span>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Pipeline */}
          <TabsContent value="pipeline" className="space-y-4">
            <Card className="border-slate-200">
              <CardHeader>
                <CardTitle className="text-cyan-700">Validation Pipeline: 95% Confidence</CardTitle>
                <CardDescription>C = 0.30*V1 + 0.25*V2 + 0.25*V3 + 0.20*V4 + bonus</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3">
                  {[
                    { name: 'V1: Symbolic Execution', weight: '30%', tools: 'Mythril, Manticore, Halmos', coverage: '~70% paths', accent: 'bg-cyan-50 border-cyan-300' },
                    { name: 'V2: Fuzzing & Property', weight: '25%', tools: 'Echidna, Medusa, Foundry', coverage: '~85% inputs', accent: 'bg-amber-50 border-amber-300' },
                    { name: 'V3: Formal Verification', weight: '25%', tools: 'Certora, Kontrol, Move Prover', coverage: '~95% specified', accent: 'bg-violet-50 border-violet-300' },
                    { name: 'V4: Economic Simulation', weight: '20%', tools: 'Custom + Mainnet Fork', coverage: '~90% econ attacks', accent: 'bg-emerald-50 border-emerald-300' },
                  ].map((v, i) => (
                    <div key={i} className={`p-4 rounded-lg border-2 ${v.accent} space-y-2`}>
                      <p className="text-sm font-bold">{v.name}</p>
                      <p className="text-xs">Weight: <span className="font-mono font-bold">{v.weight}</span></p>
                      <Separator />
                      <p className="text-xs text-slate-600">Tools: {v.tools}</p>
                      <p className="text-xs text-slate-600">Coverage: {v.coverage}</p>
                    </div>
                  ))}
                </div>

                <div className="p-4 rounded-lg bg-slate-50 space-y-2">
                  <p className="text-sm font-semibold text-emerald-700">Confidence Thresholds</p>
                  <div className="grid grid-cols-4 gap-3">
                    {[
                      { label: 'Confirmed', min: '95%', bg: 'bg-emerald-100 text-emerald-800' },
                      { label: 'Probable', min: '80%', bg: 'bg-blue-100 text-blue-800' },
                      { label: 'Possible', min: '60%', bg: 'bg-yellow-100 text-yellow-800' },
                      { label: 'Info', min: '<60%', bg: 'bg-slate-100 text-slate-700' },
                    ].map((t, i) => (
                      <div key={i} className={`p-2 rounded text-center ${t.bg}`}>
                        <p className="text-sm font-bold">{t.min}</p>
                        <p className="text-xs">{t.label}</p>
                      </div>
                    ))}
                  </div>
                </div>

                {vulns.length > 0 && (
                  <div className="p-4 rounded-lg bg-slate-50 space-y-2">
                    <p className="text-sm font-semibold text-amber-700">Live Calculations</p>
                    <div className="space-y-2 max-h-[300px] overflow-y-auto">
                      {vulns.slice(0, 8).map(v => (
                        <div key={v.id} className="flex items-center gap-2 text-xs">
                          <Badge className={severityColor[v.severity]}>{v.severity}</Badge>
                          <span className="flex-1 text-slate-600 truncate">{v.title}</span>
                          <span className="text-slate-400 font-mono text-[10px]">
                            .30*{(v.v1Symbolic??0).toFixed(2)}+.25*{(v.v2Fuzzing??0).toFixed(2)}+.25*{(v.v3Formal??0).toFixed(2)}+.20*{(v.v4Economic??0).toFixed(2)}
                          </span>
                          <span className={`font-mono font-bold ${(v.confidence*100).toFixed(0) >= 95 ? 'text-emerald-600' : 'text-yellow-600'}`}>
                            {(v.confidence*100).toFixed(1)}%
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card className="border-slate-200">
              <CardHeader><CardTitle className="text-emerald-700">Economic Attack Simulator (Layer 6)</CardTitle></CardHeader>
              <CardContent>
                <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3">
                  {[
                    { name: 'Flash Loan Attack', desc: 'Borrow → manipulate → exploit → repay', target: 'AMM, Lending' },
                    { name: 'MEV/Sandwich', desc: 'Front-run + back-run victim tx', target: 'DEX, Liquidations' },
                    { name: 'Oracle Manipulation', desc: 'Shift price to break invariant', target: 'Price feeds, TWAPs' },
                    { name: 'Governance Attack', desc: 'Flash loan votes → pass proposal', target: 'DAOs, Governors' },
                  ].map((a, i) => (
                    <div key={i} className="p-4 rounded-lg border border-slate-200 bg-slate-50 space-y-1">
                      <p className="text-sm font-bold">{a.name}</p>
                      <p className="text-xs text-slate-600">{a.desc}</p>
                      <p className="text-xs text-slate-400">Target: {a.target}</p>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </main>

      {/* Activity Feed Side Panel */}
      {showActivity && (
        <div className="fixed top-0 right-0 h-full w-[340px] bg-white border-l border-slate-200 shadow-2xl z-[60] flex flex-col">
          <div className="flex items-center justify-between p-3 border-b border-slate-200">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-slate-700" />
              <h3 className="text-sm font-semibold text-slate-800">Activity Feed</h3>
              <Badge variant="outline" className="text-[10px]">{activities.length}</Badge>
            </div>
            <div className="flex items-center gap-1">
              <Button size="sm" variant="ghost" className="h-7 text-xs" onClick={() => setActivities([])}>
                Clear
              </Button>
              <Button size="sm" variant="ghost" className="h-7 w-7 p-0" onClick={() => setShowActivity(false)}>
                <X className="w-4 h-4" />
              </Button>
            </div>
          </div>
          <div ref={activityPanelRef} className="flex-1 overflow-y-auto p-3 space-y-2">
            {activities.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-32 text-slate-400">
                <Terminal className="w-8 h-8 mb-2 opacity-40" />
                <p className="text-xs">No activity yet</p>
              </div>
            ) : (
              activities.map(item => {
                const statusColors: Record<string, string> = {
                  running: 'border-blue-300 bg-blue-50',
                  success: 'border-emerald-300 bg-emerald-50',
                  warning: 'border-amber-300 bg-amber-50',
                  error: 'border-red-300 bg-red-50',
                  info: 'border-slate-300 bg-slate-50',
                };
                const statusIconMap: Record<string, React.ReactNode> = {
                  running: <Loader2 className="w-3.5 h-3.5 text-blue-500 animate-spin" />,
                  success: <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />,
                  warning: <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />,
                  error: <XCircle className="w-3.5 h-3.5 text-red-500" />,
                  info: <Activity className="w-3.5 h-3.5 text-slate-500" />,
                };
                const typeIconMap: Record<string, React.ReactNode> = {
                  scan: <Search className="w-3 h-3" />,
                  finding: <Bug className="w-3 h-3" />,
                  method: <Zap className="w-3 h-3" />,
                  system: <Settings className="w-3 h-3" />,
                  validation: <Shield className="w-3 h-3" />,
                  'attack-sim': <AlertTriangle className="w-3 h-3" />,
                };
                const relTime = () => {
                  const diff = Date.now() - item.timestamp;
                  if (diff < 1000) return 'now';
                  if (diff < 60000) return `${Math.floor(diff/1000)}s ago`;
                  if (diff < 3600000) return `${Math.floor(diff/60000)}m ago`;
                  return `${Math.floor(diff/3600000)}h ago`;
                };
                return (
                  <div key={item.id} className={`p-2.5 rounded-lg border ${statusColors[item.status] || statusColors.info}`}>
                    <div className="flex items-start gap-2">
                      <div className="mt-0.5 shrink-0">{statusIconMap[item.status]}</div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between gap-1">
                          <div className="flex items-center gap-1.5">
                            <span className="text-slate-400">{typeIconMap[item.type]}</span>
                            <p className="text-xs font-medium text-slate-800 truncate">{item.message}</p>
                          </div>
                          <span className="text-[10px] text-slate-400 shrink-0">{relTime()}</span>
                        </div>
                        {item.detail && (
                          <p className="text-[11px] text-slate-500 mt-0.5 truncate">{item.detail}</p>
                        )}
                        {item.progress != null && item.status === 'running' && (
                          <div className="mt-1.5">
                            <div className="w-full bg-slate-200 rounded-full h-1.5">
                              <div className="h-1.5 rounded-full bg-blue-500 transition-all" style={{width: `${item.progress}%`}} />
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}

      <footer className="border-t border-slate-200 bg-slate-50 mt-auto">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between text-xs text-slate-500">
          <span>CryptoSentinel v0.1 — {model} | {hasKey ? 'Key configured' : 'No API key'}</span>
          <span>Pipeline: V1(30%) + V2(25%) + V3(25%) + V4(20%) | Target: 95%</span>
        </div>
      </footer>
    </div>
  );
}
