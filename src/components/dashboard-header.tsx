'use client';

import { useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import {
  Shield, Settings, Key, CheckCircle, Wifi, WifiOff,
  Terminal, Trash2, Loader2, AlertCircle, Zap
} from 'lucide-react';

interface DashboardHeaderProps {
  hasKey: boolean;
  model: string;
  maskedKey: string;
  /** 'env' if OPENROUTER_API_KEY env var is being used; 'db' if from DB; null if none */
  keySource?: 'env' | 'db' | null;
  apiKey: string;
  setApiKey: (v: string) => void;
  setModel: (v: string) => void;
  saveApiKey: () => void;
  showActivity: boolean;
  setShowActivity: (v: boolean) => void;
  runningCount: number;
  activitiesCount: number;
  vulnCount: number;
  seedDemo: () => void;
  clearAllFindings: () => void;
  loading: boolean;
  syncStatus: 'synced' | 'local' | 'checking';
}

interface TestKeyResult {
  valid: boolean;
  reason: string;
  source?: string;
  key_info?: {
    label?: string;
    is_free_tier?: boolean;
    usage?: number;
    limit?: number | null;
    limit_remaining?: number | null;
    expires_at?: string | null;
  };
}

export default function DashboardHeader({
  hasKey, model, maskedKey, keySource, apiKey, setApiKey, setModel, saveApiKey,
  showActivity, setShowActivity, runningCount, activitiesCount,
  vulnCount, seedDemo, clearAllFindings, loading, syncStatus,
}: DashboardHeaderProps) {
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<TestKeyResult | null>(null);

  /** Hit /api/test-key — verifies the key actually works against OpenRouter before saving. */
  const testApiKey = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      // If a key is typed in the input, test that. Otherwise, test the currently configured key.
      const body = apiKey && !apiKey.includes('***')
        ? { testKey: apiKey }
        : {};
      const res = await fetch('/api/test-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      setTestResult(data);
    } catch (e) {
      setTestResult({
        valid: false,
        reason: `Request failed: ${e instanceof Error ? e.message : String(e)}`,
      });
    } finally {
      setTesting(false);
    }
  };

  return (
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
          {/* Sync status indicator */}
          <Badge variant="outline" className={
            syncStatus === 'synced' ? 'text-emerald-600 border-emerald-300' :
            syncStatus === 'local' ? 'text-amber-600 border-amber-300' :
            'text-slate-400 border-slate-200'
          }>
            {syncStatus === 'synced' ? 'Server synced' : syncStatus === 'local' ? 'Local data (server empty)' : 'Checking...'}
          </Badge>
          <Badge variant="outline" className={hasKey ? 'text-emerald-600 border-emerald-300' : 'text-amber-600 border-amber-300'}>
            {hasKey ? <Wifi className="w-3 h-3 mr-1" /> : <WifiOff className="w-3 h-3 mr-1" />}
            {hasKey ? `${model.split('/').pop()} Active` : 'No API Key'}
          </Badge>
          {/* Activity Feed Toggle */}
          <Button size="sm" variant="outline" onClick={() => setShowActivity(!showActivity)} className="relative">
            <Terminal className="w-4 h-4 mr-1" /> Activity
            {runningCount > 0 && (
              <Badge className="absolute -top-1.5 -right-1.5 w-5 h-5 p-0 flex items-center justify-center bg-red-500 text-white border-0 text-[10px]">
                {runningCount}
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
                    ) : keySource === 'db' ? (
                      <Badge variant="outline" className="text-amber-700 border-amber-300 bg-amber-50">database (may reset on cold start)</Badge>
                    ) : null}
                    <span className="text-slate-400">|</span>
                    <span className="text-slate-500">Current: <code className="font-mono">{maskedKey}</code></span>
                  </div>
                )}
                {keySource === 'env' && (
                  <p className="text-xs text-blue-700 bg-blue-50 border border-blue-200 p-2 rounded">
                    <strong>Env var is active:</strong> The <code>OPENROUTER_API_KEY</code> env var (set via Vercel dashboard) takes precedence over the DB key. This is the most reliable configuration — the key persists across cold starts. Saving a new key below will store it in the DB, but the env var will still win.
                  </p>
                )}
                {hasKey && keySource === 'db' && (
                  <p className="text-xs text-amber-700 bg-amber-50 border border-amber-200 p-2 rounded">
                    <strong>DB-only key:</strong> The key is stored in the per-instance SQLite database and may be lost on cold starts. For reliable persistence, set <code>OPENROUTER_API_KEY</code> as a Vercel env var.
                  </p>
                )}

                {/* Model selector */}
                <div>
                  <label className="text-sm font-medium text-slate-700">Model</label>
                  <Select value={model} onValueChange={setModel}>
                    <SelectTrigger className="mt-1"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="z-ai/glm-5.2">GLM 5.2 (1M ctx) — Recommended</SelectItem>
                      <SelectItem value="z-ai/glm-5.1">GLM 5.1</SelectItem>
                      <SelectItem value="z-ai/glm-5-turbo">GLM 5 Turbo</SelectItem>
                      <SelectItem value="z-ai/glm-4.7-flash">GLM 4.7 Flash</SelectItem>
                      <SelectItem value="z-ai/glm-4.7">GLM 4.7</SelectItem>
                      <SelectItem value="deepseek/deepseek-r1-0528">DeepSeek R1 (Reasoning)</SelectItem>
                      <SelectItem value="qwen/qwen3-235b-a22b">Qwen3 235B</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                {/* API Key input */}
                <div>
                  <label className="text-sm font-medium text-slate-700">API Key</label>
                  <Input type="password" placeholder={hasKey ? 'Enter new key to update' : 'Enter your OpenRouter API key (sk-or-v1-...)'}
                    className="mt-1" value={apiKey} onChange={e => setApiKey(e.target.value)} />
                  <p className="text-xs text-slate-400 mt-1">
                    Get a key at <a href="https://openrouter.ai/keys" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">openrouter.ai/keys</a> — must start with <code>sk-or-v1-</code>.
                  </p>
                </div>

                {/* ─── Test + Save buttons ────────────────────────────── */}
                <div className="flex gap-2">
                  <Button
                    onClick={testApiKey}
                    disabled={testing || (!apiKey && !hasKey)}
                    variant="outline"
                    className="flex-1 border-blue-300 text-blue-700 hover:bg-blue-50"
                  >
                    {testing ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Testing...</> : <><Zap className="w-4 h-4 mr-2" /> Test Key</>}
                  </Button>
                  <Button
                    onClick={saveApiKey}
                    disabled={!apiKey && !model}
                    className="flex-1 bg-emerald-600 hover:bg-emerald-700 text-white"
                  >
                    <Key className="w-4 h-4 mr-2" /> Save Configuration
                  </Button>
                </div>

                {/* ─── Test result ────────────────────────────────────── */}
                {testResult && (
                  <div className={`flex flex-col gap-2 p-3 rounded-lg border text-sm ${
                    testResult.valid
                      ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
                      : 'bg-red-50 border-red-200 text-red-800'
                  }`}>
                    <div className="flex items-start gap-2">
                      {testResult.valid
                        ? <CheckCircle className="w-4 h-4 mt-0.5 shrink-0" />
                        : <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />}
                      <div className="flex-1">
                        <p className="font-medium">{testResult.valid ? 'Key is valid' : 'Key is invalid'}</p>
                        <p className="text-xs opacity-80">{testResult.reason}</p>
                        {testResult.source && (
                          <p className="text-xs mt-1 opacity-70">Source: {testResult.source}</p>
                        )}
                      </div>
                    </div>
                    {testResult.valid && testResult.key_info && (
                      <div className="text-xs grid grid-cols-2 gap-1 mt-1 pt-2 border-t border-emerald-200">
                        <span>Tier:</span><span>{testResult.key_info.is_free_tier ? 'Free' : 'Paid'}</span>
                        <span>Usage:</span><span>{testResult.key_info.usage ?? 0} credits</span>
                        <span>Limit:</span><span>{testResult.key_info.limit ?? 'unlimited'}</span>
                        {testResult.key_info.expires_at && (
                          <><span>Expires:</span><span>{new Date(testResult.key_info.expires_at).toLocaleDateString()}</span></>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {/* ─── Success banner when key is configured ─────────── */}
                {hasKey && (
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
          {vulnCount > 0 && (
            <Button size="sm" variant="outline" className="text-red-600 border-red-200 hover:bg-red-50" onClick={clearAllFindings}>
              <Trash2 className="w-4 h-4 mr-1" /> Clear All
            </Button>
          )}
        </div>
      </div>
    </header>
  );
