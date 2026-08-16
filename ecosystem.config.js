module.exports = {
  apps: [{
    name: 'cryptosentinel',
    // IMPORTANT: use the standalone server.js, NOT 'next start'.
    // next.config.ts has output: 'standalone', and Next.js warns:
    //   "next start" does not work with "output: standalone" configuration.
    //   Use "node .next/standalone/server.js" instead.
    // Running `next start` with standalone causes the server to crash
    // silently on long-running requests (the AI analysis times out
    // after 100s and PM2 restarts the process, leading to the
    // 'stuck loading for 20 minutes' symptom).
    script: '.next/standalone/server.js',
    cwd: '/app',
    interpreter: 'node',
    env: {
      // VPS KVM 2 (Hostinger, 8GB RAM) — give Node.js 2GB heap for
      // large smart contract source code analysis and multi-pass AI.
      NODE_OPTIONS: '--unhandled-rejections=none --max-old-space-size=2048',
      DATABASE_URL: 'file:/tmp/cryptosentinel.db',
      HOSTNAME: '0.0.0.0',
      PORT: 3000,
      NEXT_RUNTIME: 'nodejs',
      NODE_ENV: 'production',
    },
    max_restarts: 9999,
    restart_delay: 1000,
    min_uptime: 5000,
    watch: false,
    autorestart: true,
    max_memory_restart: '2G', // VPS has 8GB, allow Node up to 2GB before restart
    kill_timeout: 10000, // 10s — give long SSE streams time to finish
    listen_timeout: 30000,
  }]
};
