'use client';

/**
 * Global Error Boundary — catches errors that escape the root layout,
 * including errors in server components and the layout itself.
 * This is the LAST line of defense against a blank white page.
 */

import { useEffect } from 'react';

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error('[CryptoSentinel Global Error]', error);
  }, [error]);

  return (
    <html lang="ru">
      <body style={{ margin: 0, fontFamily: 'system-ui, sans-serif', background: '#f8fafc' }}>
        <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '1rem' }}>
          <div style={{ maxWidth: '28rem', width: '100%', background: 'white', borderRadius: '0.75rem', boxShadow: '0 10px 25px rgba(0,0,0,0.1)', border: '1px solid #e2e8f0', padding: '2rem', textAlign: 'center' }}>
            <div style={{ width: '4rem', height: '4rem', margin: '0 auto 1rem', borderRadius: '50%', background: '#fef2f2', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <span style={{ fontSize: '2rem' }}>⚠</span>
            </div>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: '#0f172a', marginBottom: '0.5rem' }}>
              Критическая ошибка
            </h2>
            <p style={{ fontSize: '0.875rem', color: '#64748b', marginBottom: '1.5rem' }}>
              Сервер недоступен или произошёл сбой. Попробуйте обновить страницу.
            </p>
            <button
              onClick={() => reset()}
              style={{
                background: '#059669', color: 'white', border: 'none',
                padding: '0.5rem 1rem', borderRadius: '0.375rem',
                cursor: 'pointer', fontWeight: 500, marginRight: '0.5rem',
              }}
            >
              Попробовать снова
            </button>
            <button
              onClick={() => { window.location.reload(); }}
              style={{
                background: 'white', color: '#475569', border: '1px solid #cbd5e1',
                padding: '0.5rem 1rem', borderRadius: '0.375rem', cursor: 'pointer', fontWeight: 500,
              }}
            >
              Перезагрузить
            </button>
            {error?.digest && (
              <p style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: '1rem' }}>
                Error ID: {error.digest}
              </p>
            )}
          </div>
        </div>
      </body>
    </html>
  );
}
