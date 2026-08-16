/**
 * Next.js Loading UI — shown while the page segment is loading.
 * Replaces the blank white screen during initial load with a branded
 * spinner that matches the app's design language.
 */
import { Shield } from 'lucide-react';

export default function Loading() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50">
      <div className="text-center">
        <div className="w-16 h-16 mx-auto mb-4 rounded-xl bg-emerald-600 flex items-center justify-center animate-pulse">
          <Shield className="w-8 h-8 text-white" />
        </div>
        <h1 className="text-xl font-bold text-slate-900 mb-1">CryptoSentinel</h1>
        <p className="text-sm text-slate-500 mb-4">Загрузка сканера уязвимостей...</p>
        <div className="flex justify-center">
          <div className="w-8 h-8 border-4 border-slate-200 border-t-emerald-600 rounded-full animate-spin"></div>
        </div>
      </div>
    </div>
  );
}
