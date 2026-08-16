#!/usr/bin/env python3
"""Deploy CryptoSentinel fix to /app on VPS at 187.77.181.127."""
import os, sys, paramiko

HOST = "187.77.181.127"
PASSWORD = os.environ.get("DEPLOY_PWD", "")
PROJECT_DIR = "/app"
if not PASSWORD:
    print("ERROR: DEPLOY_PWD not set", file=sys.stderr); sys.exit(2)

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(hostname=HOST, port=22, username="root",
          password=PASSWORD, look_for_keys=False, allow_agent=False, timeout=30)


def run(cmd, t=600, show=True):
    if show: print(f"\n$ {cmd}", flush=True)
    _, o, e = c.exec_command(cmd, timeout=t)
    out = o.read().decode(errors="replace")
    err = e.read().decode(errors="replace")
    if show and out: print(out, end="", flush=True)
    if show and err: print(err, end="", file=sys.stderr, flush=True)
    if show: print(f"[exit={o.channel.exit_status}]", flush=True)
    return o.channel.exit_status, out, err


print("=== Step 1: confirm /app is the project ===", flush=True)
run(f"cd {PROJECT_DIR} && pwd && ls -la package.json next.config.ts ecosystem.config.js 2>&1 | head -10", t=15)

print("\n=== Step 2: git fetch + check log ===", flush=True)
run(f"cd {PROJECT_DIR} && git fetch origin main 2>&1 | tail -5 && echo '---CURRENT---' && git log --oneline -3 && echo '---REMOTE---' && git log --oneline -3 origin/main", t=60)

print("\n=== Step 3: git status + reset any local changes ===", flush=True)
run(f"cd {PROJECT_DIR} && git status --short | head -10", t=15)
run(f"cd {PROJECT_DIR} && git stash --include-untracked 2>&1 | tail -3 || true", t=30)

print("\n=== Step 4: git pull (or reset --hard if needed) ===", flush=True)
ec, out, _ = run(f"cd {PROJECT_DIR} && git pull --ff-only origin main 2>&1 | tail -10", t=120)
if ec != 0:
    print("Pull failed, doing hard reset to origin/main ...", flush=True)
    run(f"cd {PROJECT_DIR} && git reset --hard origin/main 2>&1 | tail -3", t=60)

print("\n=== Step 5: verify HEAD on remote ===", flush=True)
run(f"cd {PROJECT_DIR} && git log --oneline -5", t=15)

print("\n=== Step 6: npm ci (install deps) ===", flush=True)
run(f"cd {PROJECT_DIR} && npm ci --no-audit --no-fund --prefer-offline 2>&1 | tail -5", t=300)

print("\n=== Step 7: prisma generate ===", flush=True)
run(f"cd {PROJECT_DIR} && npx prisma generate 2>&1 | tail -5", t=60)

print("\n=== Step 8: npm run build ===", flush=True)
ec, _, _ = run(f"cd {PROJECT_DIR} && NODE_OPTIONS=--max-old-space-size=2048 npm run build 2>&1 | tail -50", t=600)
if ec != 0:
    print(f"ERROR: build failed (exit {ec})", file=sys.stderr)
    sys.exit(5)

# IMPORTANT: when output: 'standalone' is set in next.config.ts, Next.js builds
# the server bundle in .next/standalone but does NOT copy the static assets
# (JS chunks, CSS, public/) into it. Without this copy step, every chunk
# returns 404 and the browser shows "Page couldn't load".
print("\n=== Step 8b: copy static into standalone ===", flush=True)
run(f"cd {PROJECT_DIR} && cp -r .next/static .next/standalone/.next/ && cp -r public .next/standalone/ 2>&1 | tail -3", t=30)
run(f"ls {PROJECT_DIR}/.next/standalone/.next/static/chunks/ 2>&1 | head -10", t=15)

print("\n=== Step 9: restart PM2 ===", flush=True)
run(f"pm2 restart cryptosentinel --update-env 2>&1 | tail -10", t=60)
run("pm2 list", t=15)

print("\n=== Step 10: wait 5s and verify ===", flush=True)
run("sleep 5 && curl -s -o /dev/null -w 'HTTP %{{http_code}} | time=%{{time_total}}s\\n' http://localhost:3000/", t=30)
run("curl -s http://localhost:3000/ 2>&1 | grep -oE '/_next/static/chunks/[a-z0-9_-]+\\.js' | sort -u | head -5", t=15)

# Compare with old hashes — the OLD ones were:
# 0cz1d0mv5g_q7, 1-xpt797kfjge, 11wjr7r9hs-rf, 2-ihr09a4-itm, 2jcvj5brh974f, 3c3fkwvsi0q1g, turbopack-0816b8w9z4u9r
print("\n=== Step 11: check if /api/settings is still alive (warm-up) ===", flush=True)
run("sleep 2 && curl -s -o /dev/null -w 'HTTP %{{http_code}}\\n' http://localhost:3000/api/settings", t=15)

c.close()
print("\n=== DEPLOY COMPLETE ===", flush=True)
