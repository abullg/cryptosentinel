#!/usr/bin/env python3
"""NUCLEAR rebuild — clear ALL caches and rebuild from scratch."""
import os, sys, paramiko

HOST = "187.77.181.127"
PASSWORD = os.environ.get("DEPLOY_PWD", "")
PROJECT_DIR = "/app"

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
    if err and len(err) < 1000: print("STDERR:", err[:500], flush=True)
    return o.channel.exit_status

# Step 1: Stop PM2
print("=== Step 1: Stop PM2 ===", flush=True)
run("pm2 stop cryptosentinel 2>&1 | tail -3")

# Step 2: NUCLEAR clear — delete ALL build artifacts and caches
print("\n=== Step 2: NUCLEAR cache clear ===", flush=True)
run(f"cd {PROJECT_DIR} && rm -rf .next .turbo node_modules/.cache .cache 2>&1")
run(f"ls -la {PROJECT_DIR}/.next 2>&1 || echo '.next deleted OK'")

# Step 3: git pull latest
print("\n=== Step 3: git pull ===", flush=True)
run(f"cd {PROJECT_DIR} && git fetch origin main && git reset --hard origin/main 2>&1 | tail -5")
run(f"cd {PROJECT_DIR} && git log --oneline -3")

# Step 4: npm ci (clean install)
print("\n=== Step 4: npm ci ===", flush=True)
run(f"cd {PROJECT_DIR} && npm ci --no-audit --no-fund 2>&1 | tail -5", t=300)

# Step 5: prisma generate
print("\n=== Step 5: prisma generate ===", flush=True)
run(f"cd {PROJECT_DIR} && npx prisma generate 2>&1 | tail -3", t=60)

# Step 6: prisma db push (create fresh DB)
print("\n=== Step 6: prisma db push ===", flush=True)
run(f"cd {PROJECT_DIR} && DATABASE_URL=file:/tmp/cryptosentinel.db npx prisma db push --accept-data-loss 2>&1 | tail -5", t=60)

# Step 7: FRESH build (no cache to reuse)
print("\n=== Step 7: FRESH next build ===", flush=True)
ec = run(f"cd {PROJECT_DIR} && NODE_OPTIONS=--max-old-space-size=2048 npx next build 2>&1 | tail -30", t=600)
if ec != 0:
    print(f"ERROR: build failed (exit {ec})", file=sys.stderr)
    sys.exit(5)

# Step 8: Copy static into standalone
print("\n=== Step 8: Copy static into standalone ===", flush=True)
run(f"cd {PROJECT_DIR} && cp -r .next/static .next/standalone/.next/ && cp -r public .next/standalone/ 2>&1")

# Step 9: VERIFY the fix is in the bundled route.js
print("\n=== Step 9: VERIFY fix in bundled route.js ===", flush=True)
run(f"grep -c '_deleted' {PROJECT_DIR}/.next/standalone/.next/server/app/api/analyze-stream/route.js 2>&1")
run(f"grep -c 'deleteMany' {PROJECT_DIR}/.next/standalone/.next/server/app/api/analyze-stream/route.js 2>&1")
run(f"grep -c 'deleteMany' {PROJECT_DIR}/.next/standalone/.next/server/app/api/analyze-ai/route.js 2>&1")
run(f"ls {PROJECT_DIR}/.next/standalone/.next/server/app/error.js 2>&1")
run(f"ls {PROJECT_DIR}/.next/standalone/.next/server/app/global-error.js 2>&1")
run(f"ls {PROJECT_DIR}/.next/standalone/.next/server/app/loading.js 2>&1")

# Step 10: Restart PM2
print("\n=== Step 10: Restart PM2 ===", flush=True)
run("pm2 restart cryptosentinel --update-env 2>&1 | tail -5")
run("pm2 list 2>&1 | head -6")

# Step 11: Wait and verify
print("\n=== Step 11: Verify server ===", flush=True)
run("sleep 5 && curl -s -o /dev/null -w 'HTTP %{http_code} | %{time_total}s\\n' http://localhost:3000/ 2>&1")
run("curl -s http://localhost:3000/ 2>&1 | grep -oE '/_next/static/chunks/[a-z0-9_-]+\\.js' | sort -u | head -5")
# Verify ALL chunks return 200
run("""for chunk in $(curl -s http://localhost:3000/ | grep -oE '/_next/static/chunks/[a-z0-9_-]+\\.js' | sort -u); do
  code=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:3000$chunk)
  echo "$code $chunk"
done""")

# Step 12: Quick API test
print("\n=== Step 12: Quick API tests ===", flush=True)
for ep in ["/api", "/api/settings", "/api/projects", "/api/vulnerabilities"]:
    run(f"curl -s -o /dev/null -w 'GET {ep}: HTTP %{{http_code}} | %{{time_total}}s\\n' http://localhost:3000{ep}")

c.close()
print("\n=== NUCLEAR REBUILD COMPLETE ===", flush=True)
