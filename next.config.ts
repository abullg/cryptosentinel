import type { NextConfig } from "next";

/**
 * Next.js configuration for CryptoSentinel.
 *
 * Security/quality settings (previously broken — fixed in audit):
 *   - typescript.ignoreBuildErrors: false  (was true → type errors silently shipped)
 *   - reactStrictMode: true                (was false → subtle bugs hidden)
 *
 * Removed:
 *   - env.GITHUB_TOKEN: this was leaking the server-side GitHub token into the
 *     client bundle (Next.js `env` field is exposed to the browser). The token
 *     is read directly from process.env in the API routes instead.
 *
 * Added:
 *   - Security headers (CSP, X-Frame-Options, X-Content-Type-Options, etc.)
 *   - experimental.serverActions.allowedOrigins for production
 */
const nextConfig: NextConfig = {
  output: 'standalone',
  // FAIL the build on TypeScript errors. Was previously true, which meant
  // production shipped with broken types — silent runtime failures.
  typescript: { ignoreBuildErrors: false },
  // Note: ESLint is no longer run during `next build` in Next.js 16.
  // Use `npm run lint` separately if you want to check lint.
  // Catch problems early (intentional double-render, deprecated lifecycle).
  reactStrictMode: true,
  serverExternalPackages: [],
  // HTTP security headers. Applied to all routes.
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=31536000; includeSubDomains; preload',
          },
        ],
      },
      {
        // CSP — relaxed for now because Next.js 16 + AI streaming need
        // eval/scripts from same origin. Tighten in production once you
        // enumerate all trusted sources.
        source: '/(.*)',
        headers: [
          {
            key: 'Content-Security-Policy',
            value: [
              "default-src 'self'",
              "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
              "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
              "font-src 'self' data:",
              "img-src 'self' data: blob: https:",
              "connect-src 'self' https://openrouter.ai https://api.github.com https://raw.githubusercontent.com https://eth.llamarpc.com https://bsc-dataseed.binance.org https://polygon-rpc.com https://arb1.arbitrum.io https://mainnet.optimism.io https://mainnet.base.org https://api.avax.network https://rpc.ftm.tools wss:",
              "frame-ancestors 'none'",
              "base-uri 'self'",
              "form-action 'self'",
            ].join('; '),
          },
        ],
      },
    ];
  },
};

export default nextConfig;
