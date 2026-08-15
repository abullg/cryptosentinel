'use client';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  CheckCircle2, XCircle, AlertTriangle, Activity,
  Search, Bug, Zap, Settings, Shield, Loader2, Terminal, X,
} from 'lucide-react';

interface ActivityItem {
  id: string;
  type: 'scan' | 'finding' | 'method' | 'system' | 'validation' | 'attack-sim';
  message: string;
  detail?: string;
  timestamp: number;
  status: 'running' | 'success' | 'warning' | 'error' | 'info';
  progress?: number;
}

interface ActivityFeedProps {
  showActivity: boolean;
  setShowActivity: (v: boolean) => void;
  activities: ActivityItem[];
  setActivities: (v: ActivityItem[]) => void;
  analyzing: boolean;
  panelRef: React.RefObject<HTMLDivElement | null>;
}

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

function relTime(timestamp: number) {
  const diff = Date.now() - timestamp;
  if (diff < 1000) return 'now';
  if (diff < 60000) return `${Math.floor(diff / 1000)}s ago`;
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  return `${Math.floor(diff / 3600000)}h ago`;
}

export default function ActivityFeed({
  showActivity, setShowActivity, activities, setActivities, analyzing, panelRef,
}: ActivityFeedProps) {
  const runningCount = activities.filter(a => a.status === 'running').length;

  return (
    <>
      {/* Floating Activity Indicator (when panel is closed and tasks are running) */}
      {!showActivity && runningCount > 0 && (
        <button
          onClick={() => setShowActivity(true)}
          className="fixed bottom-6 right-6 z-[70] flex items-center gap-2 px-4 py-2.5 rounded-full bg-slate-900 text-white shadow-lg hover:bg-slate-800 transition-all animate-pulse"
        >
          <Loader2 className="w-4 h-4 animate-spin" />
          <span className="text-sm font-medium">{runningCount} active</span>
          <Badge className="bg-emerald-500 text-white border-0 text-[10px] px-1.5">{activities.length}</Badge>
        </button>
      )}

      {/* Activity Feed Side Panel */}
      {showActivity && (
        <div className="fixed top-0 right-0 h-full w-full md:w-[380px] bg-white border-l border-slate-200 shadow-2xl z-[60] flex flex-col">
          <div className="flex items-center justify-between p-3 border-b border-slate-200">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-slate-700" />
              <h3 className="text-sm font-semibold text-slate-800">Activity Feed</h3>
              <Badge variant="outline" className="text-[10px]">{activities.length}</Badge>
              {runningCount > 0 && (
                <Badge className="bg-blue-100 text-blue-800 border-0 text-[10px]">
                  <Loader2 className="w-3 h-3 mr-1 animate-spin inline" />
                  {runningCount} running
                </Badge>
              )}
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
          {/* Active scan progress bar */}
          {analyzing && (
            <div className="px-3 py-2 bg-blue-50 border-b border-blue-100">
              <div className="flex items-center gap-2 mb-1">
                <Loader2 className="w-3.5 h-3.5 text-blue-600 animate-spin" />
                <span className="text-xs font-medium text-blue-800">Scan in progress...</span>
              </div>
              <div className="w-full bg-blue-200 rounded-full h-1.5 overflow-hidden">
                <div className="h-1.5 rounded-full bg-blue-600 animate-pulse" style={{ width: '100%' }} />
              </div>
            </div>
          )}
          <div ref={panelRef} className="flex-1 overflow-y-auto p-3 space-y-2">
            {activities.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-32 text-slate-400">
                <Terminal className="w-8 h-8 mb-2 opacity-40" />
                <p className="text-xs">No activity yet</p>
              </div>
            ) : (
              activities.map(item => (
                <div key={item.id} className={`p-2.5 rounded-lg border ${statusColors[item.status] || statusColors.info}`}>
                  <div className="flex items-start gap-2">
                    <div className="mt-0.5 shrink-0">{statusIconMap[item.status]}</div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between gap-1">
                        <div className="flex items-center gap-1.5">
                          <span className="text-slate-400">{typeIconMap[item.type]}</span>
                          <p className="text-xs font-medium text-slate-800 truncate">{item.message}</p>
                        </div>
                        <span className="text-[10px] text-slate-400 shrink-0">{relTime(item.timestamp)}</span>
                      </div>
                      {item.detail && (
                        <p className="text-[11px] text-slate-500 mt-0.5 truncate">{item.detail}</p>
                      )}
                      {item.progress != null && item.status === 'running' && (
                        <div className="mt-1.5">
                          <div className="w-full bg-slate-200 rounded-full h-1.5">
                            <div className="h-1.5 rounded-full bg-blue-500 transition-all" style={{ width: `${item.progress}%` }} />
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </>
  );
}
