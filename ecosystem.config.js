/**
 * PM2 process config for CryptoSentinel.
 *
 * Audit fixes:
 *   - max_restarts: 10  (was 9999 — masked crashes indefinitely)
 *   - DATABASE_URL: /data/cryptosentinel.db (was /tmp — wiped on reboot)
 *   - Added CRYPTOSENTINEL_AUTH_TOKEN (read from env, see README)
 *
 * IMPORTANT: use the standalone server.js, NOT 'next start'.
 *   - next.config.ts has output: 'standalone'
 *   - Next.js 16: "next start does not work with output: standalone"
 *   - Running `next start` causes silent crashes on long-running SSE
 *     streams (the AI analysis times out and PM2 restarts the process,
 *     leading to the "stuck loading for 20 minutes" symptom).
 */
module.exports = {
  apps: [{
    name: 'cryptosentinel',
    script: '.next/standalone/server.js',
    cwd: '/app',
    interpreter: 'node',

    env: {
      // ── Persistent DB ───────────────────────────────────────────────
      // Was `file:/tmp/cryptosentinel.db` — /tmp is wiped on reboot and
      // every analysis was lost. Now under /data (mount as a volume in
      // production, or create a real dir on the VPS filesystem).
      DATABASE_URL: process.env.DATABASE_URL || 'file:/data/cryptosentinel.db',

      // ── Network ─────────────────────────────────────────────────────
      HOSTNAME: '0.0.0.0',
      PORT: process.env.PORT || 3000,
      NEXT_RUNTIME: 'nodejs',
      NODE_ENV: 'production',

      // ── Memory (VPS has 8GB) ────────────────────────────────────────
      // Allow up to 2GB for large smart contract multi-pass analysis.
      NODE_OPTIONS: '--unhandled-rejections=strict --max-old-space-size=2048',

      // ── Secrets (set these on the VPS in /etc/environment or PM2 env) ─
      OPENROUTER_API_KEY: process.env.OPENROUTER_API_KEY || '',
      GITHUB_TOKEN: process.env.GITHUB_TOKEN || '',
      CRYPTOSENTINEL_AUTH_TOKEN: process.env.CRYPTOSENTINEL_AUTH_TOKEN || '',
      CRYPTOSENTINEL_APP_URL: process.env.CRYPTOSENTINEL_APP_URL || '',
    },

    // ── Restart policy (audit fix HIGH-1) ────────────────────────────
    // Was 9999 — masked crashed loops indefinitely. Now 10 — fail
    // fast so a deploy-time misconfiguration is visible immediately.
    max_restarts: 10,
    restart_delay: 5000,
    min_uptime: '10s',
    watch: false,
    autorestart: true,

    // ── Memory threshold (VPS has 8GB) ────────────────────────────────
    max_memory_restart: '2G',

    // ── Timeouts (audit fix HIGH-2 + SSE compat) ─────────────────────
    // 10s kill_timeout + 30s listen_timeout for long AI streams.
    kill_timeout: 10000,
    listen_timeout: 30000,

    // ── Logs ──────────────────────────────────────────────────────────
    out_file: '/var/log/cryptosentinel/out.log',
    error_file: '/var/log/cryptosentinel/error.log',
    merge_logs: true,
    time: true,
  }]
};
