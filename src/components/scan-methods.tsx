'use client';

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Info } from 'lucide-react';

interface ScanMethodsProps {
  scanMethods: Record<string, boolean>;
  toggleScanMethod: (key: string) => void;
}

// Method definitions with heuristic labels
const SCAN_CATEGORIES = [
  { category: 'Static Analysis', methods: [
    { key: 'ast-analysis', label: 'AST Analysis', heuristic: false },
    { key: 'data-flow', label: 'Data Flow', heuristic: false },
    { key: 'control-flow', label: 'Control Flow', heuristic: false },
    { key: 'pattern-match', label: 'Pattern Match', heuristic: false },
    { key: 'deep-reentrancy', label: 'Deep Reentrancy', heuristic: false },
    { key: 'access-control', label: 'Access Control', heuristic: false },
    { key: 'gas-dos-audit', label: 'Gas/DoS Audit', heuristic: false },
    { key: 'cross-contract', label: 'Cross-Contract', heuristic: false },
    { key: 'proxy-storage', label: 'Proxy Storage', heuristic: false },
    { key: 'delegatecall-scan', label: 'Delegatecall Scan', heuristic: false },
  ]},
  { category: 'Dynamic Testing', methods: [
    { key: 'symbolic-exec', label: 'Symbolic Analysis', heuristic: true },
    { key: 'fuzzing', label: 'Fuzz Patterns', heuristic: true },
    { key: 'mutation-test', label: 'Mutation Testing', heuristic: true },
    { key: 'signature-replay', label: 'Signature Replay', heuristic: true },
  ]},
  { category: 'Formal Verification', methods: [
    { key: 'formal-verify', label: 'Formal Check', heuristic: true },
    { key: 'model-check', label: 'Model Analysis', heuristic: true },
    { key: 'invariant-check', label: 'Invariant Check', heuristic: true },
  ]},
  { category: 'Economic Analysis', methods: [
    { key: 'oracle-manip', label: 'Oracle Manipulation', heuristic: false },
    { key: 'flash-loan-sim', label: 'Flash Loan Sim', heuristic: false },
    { key: 'mev-analysis', label: 'MEV Analysis', heuristic: false },
  ]},
];

export default function ScanMethods({ scanMethods, toggleScanMethod }: ScanMethodsProps) {
  return (
    <Card className="border-slate-200">
      <CardHeader>
        <CardTitle className="text-teal-700">Scan Methods</CardTitle>
        <CardDescription>Toggle analysis methods on/off</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {SCAN_CATEGORIES.map((cat, ci) => (
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
                  {m.heuristic && (
                    <Badge variant="outline" className="ml-1.5 px-1 py-0 text-[9px] leading-none border-amber-300 text-amber-600">
                      Heuristic
                    </Badge>
                  )}
                </button>
              ))}
            </div>
          </div>
        ))}
        {/* Heuristic disclaimer */}
        <div className="flex items-start gap-2 p-2.5 rounded-lg bg-amber-50 border border-amber-200">
          <Info className="w-4 h-4 text-amber-600 mt-0.5 shrink-0" />
          <p className="text-[11px] text-amber-800">
            Heuristic methods use pattern matching and AST analysis. For production audits, integrate with Slither/Mythril/Echidna.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

// Also export the method labels map for use in analyzeContract
export const METHOD_LABELS: Record<string, string> = {
  'ast-analysis': 'AST Analysis', 'data-flow': 'Data Flow', 'control-flow': 'Control Flow',
  'pattern-match': 'Pattern Match', 'deep-reentrancy': 'Deep Reentrancy', 'symbolic-exec': 'Symbolic Analysis (Heuristic)',
  'fuzzing': 'Fuzz Patterns (Heuristic)', 'mutation-test': 'Mutation Testing', 'formal-verify': 'Formal Check (Heuristic)',
  'model-check': 'Model Analysis (Heuristic)', 'invariant-check': 'Invariant Check', 'signature-replay': 'Signature Replay',
  'access-control': 'Access Control', 'oracle-manip': 'Oracle Manipulation', 'flash-loan-sim': 'Flash Loan Sim',
  'mev-analysis': 'MEV Analysis', 'gas-dos-audit': 'Gas/DoS Audit', 'cross-contract': 'Cross-Contract',
  'proxy-storage': 'Proxy Storage', 'delegatecall-scan': 'Delegatecall Scan',
};
