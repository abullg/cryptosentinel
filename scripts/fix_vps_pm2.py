#!/usr/bin/env python3
"""Apply ecosystem.config.js fix on VPS and restart PM2 cleanly."""
import os, sys, paramiko

HOST = "187.77.181.127"
PASSWORD = os.environ.get("DEPLOY_PWD", "")
if not PASSWORD:
    print("ERROR: DEPLOY_PWD not set", file=sys.stderr); sys.exit(2)

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(hostname=HOST, port=22, username="root",
          password=PASSWORD, look_for_keys=False, allow_agent=False, timeout=30)

def run(cmd, t=60):
    print(f"\n$ {cmd}", flush=True)
    _, o, e = c.exec_command(cmd, timeout=t)
    out = o.read().decode(errors="replace")
    err = e.read().decode(errors="replace")
    print(out, end="", flush=True)
    if err: print("STDERR:", err[:500], flush=True)
    print(f"[exit={o.channel.exit_status}]", flush=True)
    return out

# Step 1: stop PM2 process
print("=== Step 1: Stop PM2 process ===", flush=True)
run("pm2 stop cryptosentinel 2>&1 || true")
run("pm2 delete cryptosentinel 2>&1 || true")

# Step 2: write new ecosystem.config.js
print("\n=== Step 2: Write new /app/ecosystem.config.js ===", flush=True)
new_config = '''module.exports = {
  apps: [{
    name: 'cryptosentinel',
    // IMPORTANT: use the standalone server.js, NOT 'next start'.
    // next.config.ts has output: 'standalone', and Next.js 16 warns:
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
      NODE_OPTIONS: '--unhandled-rejections=none --max-old-space-size=1024',
      DATABASE_URL: 'file:/tmp/cryptosentinel.db',
      HOSTNAME: '0.0.0.0',
      PORT: '3000',
      NEXT_RUNTIME: 'nodejs',
      NODE_ENV: 'production',
    },
    max_restarts: 9999,
    restart_delay: 1000,
    min_uptime: '5s',
    watch: false,
    autorestart: true,
    max_memory_restart: '1G',
    kill_timeout: 5000,
    listen_timeout: 10000,
  }]
};
'''
# Write via cat heredoc
cmd = f"""cat > /app/ecosystem.config.js << 'ECOSEOF'
{new_config}
ECOSEOF
echo "Wrote /app/ecosystem.config.js:"
cat /app/ecosystem.config.js | head -20
"""
run(cmd)

# Step 3: ensure standalone server.js exists
print("\n=== Step 3: Verify .next/standalone/server.js exists ===", flush=True)
run("ls -la /app/.next/standalone/server.js && head -5 /app/.next/standalone/server.js")

# Step 4: ensure database exists
print("\n=== Step 4: Push prisma schema ===", flush=True)
run("cd /app && DATABASE_URL=file:/tmp/cryptosentinel.db npx prisma db push --accept-data-loss 2>&1 | tail -5")

# Step 5: start with new config
print("\n=== Step 5: Start PM2 with new config ===", flush=True)
run("cd /app && pm2 start ecosystem.config.js 2>&1")
run("pm2 list 2>&1")
run("pm2 save 2>&1 | tail -3")

# Step 6: wait and verify
print("\n=== Step 6: Wait 5s, verify server responds ===", flush=True)
run("sleep 5 && curl -s -o /dev/null -w 'HTTP %{http_code} | time=%{time_total}s\\n' http://localhost:3000/api/settings 2>&1")

# Step 7: check logs for warnings
print("\n=== Step 7: Check logs for the 'standalone' warning ===", flush=True)
run("pm2 logs cryptosentinel --lines 30 --nostream 2>&1 | tail -40")

c.close()
print("\n=== DONE ===", flush=True)
