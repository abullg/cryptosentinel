'use client';

import { useState, useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import {
  Bug, CheckCircle2, XCircle, Clock, Target, FileText, Download,
  Trash2, Code2, Search as SearchIcon, Filter,
} from 'lucide-react';

interface Vulnerability {
  id: string; type: string; severity: string; title: string; description: string;
  confidence: number; status: string; v1Symbolic: number | null; v2Fuzzing: number | null;
  v3Formal: number | null; v4Economic: number | null; patternTag: string | null;
  isDuplicate: boolean; pocFilename: string | null; poc: string | null; target: string | null;
  vulnCategory: string | null; validationSteps: string | null; location: string | null;
  codeSnippet: string | null; createdAt: string;
  contract?: { name: string; project?: { name: string } };
}

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

interface FindingsListProps {
  vulns: Vulnerability[];
  deleteVuln: (id: string) => void;
  generateReport: () => void;
  downloadZip: () => void;
  clearAllFindings: () => void;
  loading: boolean;
  setPocView: (v: { title: string; filename: string; code: string } | null) => void;
}

const SEVERITY_OPTIONS = ['all', 'critical', 'high', 'medium', 'low', 'info'] as const;
// User explicitly asked: "if we search for what we can confirm then how can
// inconclusive appear and what's the sense of showing me non-exploitable?".
// Right answer: don't show them at all. Removed 'candidate' and 'refuted'
// from STATUS_OPTIONS — only 'confirmed' and 'validated' (= lab-confirmed
// via Foundry) are shown. The backend also DELETEs non-confirmed findings
// from the DB, so these options never had anything to display anyway.
const STATUS_OPTIONS = ['all', 'confirmed', 'validated'] as const;

export default function FindingsList({
  vulns, deleteVuln, generateReport, downloadZip, clearAllFindings, loading, setPocView,
}: FindingsListProps) {
  const [searchText, setSearchText] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [typeFilter, setTypeFilter] = useState<string>('all');

  // Extract unique types
  const uniqueTypes = useMemo(() => {
    const types = new Set(vulns.map(v => v.type));
    return Array.from(types).sort();
  }, [vulns]);

  const confirmedCount = vulns.filter(v => v.status === 'confirmed').length;

  // Apply filters
  const filteredVulns = useMemo(() => {
    return vulns.filter(v => {
      if (searchText) {
        const q = searchText.toLowerCase();
        if (!v.title.toLowerCase().includes(q) && !v.description.toLowerCase().includes(q)) return false;
      }
      if (severityFilter !== 'all' && v.severity !== severityFilter) return false;
      if (statusFilter !== 'all' && v.status !== statusFilter) return false;
      if (typeFilter !== 'all' && v.type !== typeFilter) return false;
      return true;
    }).sort((a, b) => b.confidence - a.confidence);
  }, [vulns, searchText, severityFilter, statusFilter, typeFilter]);

  return (
    <Card className="border-slate-200">
      <CardHeader>
        <div className="flex items-center justify-between flex-wrap gap-2">
          <CardTitle className="text-red-700">Vulnerability Findings</CardTitle>
          <div className="flex gap-2 flex-wrap">
            <Button size="sm" variant="outline" onClick={generateReport} disabled={loading || vulns.length === 0}>
              <FileText className="w-4 h-4 mr-1" /> HakenProof Report
            </Button>
            <Button size="sm" variant="outline" onClick={downloadZip} disabled={loading || vulns.length === 0}>
              <Download className="w-4 h-4 mr-1" /> PoC ZIP
            </Button>
            <Badge className="bg-emerald-100 text-emerald-800 border-0">{confirmedCount} Confirmed</Badge>
            {vulns.length > 0 && (
              <Button size="sm" variant="outline" className="text-red-600 border-red-200 hover:bg-red-50" onClick={clearAllFindings}>
                <Trash2 className="w-3.5 h-3.5 mr-1" /> Clear All
              </Button>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {/* Search + Filters */}
        {vulns.length > 0 && (
          <div className="space-y-2">
            {/* Search input */}
            <div className="relative">
              <SearchIcon className="absolute left-2.5 top-2.5 w-4 h-4 text-slate-400" />
              <Input
                placeholder="Search findings by title or description..."
                className="pl-9"
                value={searchText}
                onChange={e => setSearchText(e.target.value)}
              />
            </div>
            {/* Severity filter pills */}
            <div className="flex flex-wrap items-center gap-1.5">
              <Filter className="w-3.5 h-3.5 text-slate-400 mr-1" />
              {SEVERITY_OPTIONS.map(s => (
                <button
                  key={s}
                  onClick={() => setSeverityFilter(s)}
                  className={`px-2 py-0.5 rounded-full text-[11px] font-medium border transition-all ${
                    severityFilter === s
                      ? 'bg-emerald-100 text-emerald-800 border-emerald-300'
                      : 'bg-slate-50 text-slate-500 border-slate-200 hover:bg-slate-100'
                  }`}
                >
                  {s === 'all' ? 'All' : s.charAt(0).toUpperCase() + s.slice(1)}
                </button>
              ))}
            </div>
            {/* Status filter pills */}
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[11px] text-slate-400 mr-1">Status:</span>
              {STATUS_OPTIONS.map(s => (
                <button
                  key={s}
                  onClick={() => setStatusFilter(s)}
                  className={`px-2 py-0.5 rounded-full text-[11px] font-medium border transition-all ${
                    statusFilter === s
                      ? 'bg-emerald-100 text-emerald-800 border-emerald-300'
                      : 'bg-slate-50 text-slate-500 border-slate-200 hover:bg-slate-100'
                  }`}
                >
                  {s === 'all' ? 'All' : s.charAt(0).toUpperCase() + s.slice(1)}
                </button>
              ))}
            </div>
            {/* Type filter dropdown */}
            <div className="flex items-center gap-2">
              <span className="text-[11px] text-slate-400">Type:</span>
              <Select value={typeFilter} onValueChange={setTypeFilter}>
                <SelectTrigger className="w-[180px] h-7 text-xs">
                  <SelectValue placeholder="All types" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All types</SelectItem>
                  {uniqueTypes.map(t => (
                    <SelectItem key={t} value={t}>{t}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <span className="text-xs text-slate-400 ml-auto">
                {filteredVulns.length} of {vulns.length} findings
              </span>
            </div>
          </div>
        )}

        {vulns.length === 0 ? (
          <p className="text-slate-500 text-sm">No findings yet. Run an analysis first.</p>
        ) : filteredVulns.length === 0 ? (
          <p className="text-slate-500 text-sm">No findings match the current filters.</p>
        ) : (
          <div className="space-y-3 max-h-[600px] overflow-y-auto pr-2">
            {filteredVulns.map(v => (
              <div key={v.id} className="p-4 rounded-lg border border-slate-200 bg-white space-y-2 shadow-sm">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    {statusIcon[v.status] || <Clock className="w-4 h-4 text-slate-400" />}
                    <p className="font-semibold text-sm">{v.title}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge className={severityColor[v.severity] || ''}>{v.severity}</Badge>
                    <button
                      onClick={() => deleteVuln(v.id)}
                      className="p-1 rounded hover:bg-red-50 text-slate-400 hover:text-red-600 transition-colors"
                      title="Delete finding"
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
                      <div className={`h-2 rounded-full transition-all ${v.confidence >= 0.95 ? 'bg-emerald-500' : v.confidence >= 0.8 ? 'bg-blue-500' : 'bg-yellow-500'}`} style={{ width: `${v.confidence * 100}%` }} />
                    </div>
                  </div>
                  <Badge variant="outline" className="text-xs capitalize">{v.status}</Badge>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mt-1">
                  {[
                    { label: 'V1 SymEx', value: v.v1Symbolic, color: 'text-cyan-600' },
                    { label: 'V2 Fuzz', value: v.v2Fuzzing, color: 'text-amber-600' },
                    { label: 'V3 Formal', value: v.v3Formal, color: 'text-violet-600' },
                    { label: 'V4 Econ', value: v.v4Economic, color: 'text-emerald-600' },
                  ].map((val, vi) => (
                    <div key={vi} className="text-center">
                      <p className="text-[10px] text-slate-400">{val.label}</p>
                      <p className={`text-xs font-mono font-bold ${val.color}`}>{val.value != null ? (val.value * 100).toFixed(0) + '%' : '—'}</p>
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
                      <Code2 className="w-3.5 h-3.5 mr-1" /> View PoC
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
  );
}
