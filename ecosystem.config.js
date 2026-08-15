module.exports = {
  apps: [{
    name: 'cryptosentinel',
    script: '/home/z/my-project/.next/standalone/server.js',
    cwd: '/home/z/my-project',
    interpreter: 'node',
    env: {
      NODE_OPTIONS: '--unhandled-rejections=none --max-old-space-size=512',
      DATABASE_URL: 'file:/home/z/my-project/prisma/dev.db',
      HOSTNAME: '0.0.0.0',
      PORT: 3000
    },
    max_restarts: 9999,
    restart_delay: 200,
    min_uptime: 500,
    watch: false,
    autorestart: true,
    max_memory_restart: '400M',
    kill_timeout: 1000,
    listen_timeout: 3000,
  }]
};
