'use client';

/**
 * Next.js Error Boundary — catches runtime errors in any route segment.
 * Without this, an unhandled error in page-content.tsx renders a blank
 * white page with "Page couldn't load" message.
 *
 * This boundary catches:
 *   - React render errors
 *   - Hydration mismatches
 *   - Uncaught exceptions in client components
 *   - ChunkLoadError (when a JS chunk fails to load)
 *
 * It does NOT catch:
 *   - Errors in server components (those need global-error.tsx)
 *   - Errors in event handlers (those need try/catch)
 */

import { useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { AlertCircle, RefreshCw, Home } from 'lucide-react';

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Log to console for debugging, but don't crash the UI
    console.error('[CryptoSentinel Error Boundary]', error);
  }, [error]);

  // Handle ChunkLoadError specifically — common after deploys when the
  // browser has cached an old chunk reference
  const isChunkError = error?.name === 'ChunkLoadError' ||
                       error?.message?.includes('Failed to fetch dynamically imported module') ||
                       error?.message?.includes('Loading chunk');

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50 p-4">
      <div className="max-w-md w-full bg-white rounded-xl shadow-lg border border-slate-200 p-8 text-center">
        <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-red-100 flex items-center justify-center">
          <AlertCircle className="w-8 h-8 text-red-600" />
        </div>
        <h2 className="text-xl font-bold text-slate-900 mb-2">
          {isChunkError ? 'Сайт обновлён' : 'Что-то пошло не так'}
        </h2>
        <p className="text-sm text-slate-600 mb-6">
          {isChunkError
            ? 'Браузер загрузил старую версию. Нажмите кнопку ниже, чтобы загрузить новую.'
            : 'Произошла ошибка при загрузке страницы. Попробуйте обновить — если не поможет, вернитесь на главную.'}
        </p>
        {process.env.NODE_ENV === 'development' && (
          <pre className="text-xs text-left bg-slate-100 p-3 rounded mb-4 overflow-auto max-h-32">
            {error?.message}
          </pre>
        )}
        <div className="flex gap-2 justify-center">
          <Button onClick={reset} className="bg-emerald-600 hover:bg-emerald-700">
            <RefreshCw className="w-4 h-4 mr-2" />
            Попробовать снова
          </Button>
          <Button
            variant="outline"
            onClick={() => {
              // Hard reload — bypass cache
              window.location.href = window.location.pathname + '?t=' + Date.now();
            }}
          >
            <Home className="w-4 h-4 mr-2" />
            На главную
          </Button>
        </div>
        {error?.digest && (
          <p className="text-xs text-slate-400 mt-4">Error ID: {error.digest}</p>
        )}
      </div>
    </div>
  );
}
