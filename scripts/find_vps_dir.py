#!/usr/bin/env python3
"""Locate the CryptoSentinel project directory on the VPS."""
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
    print(f"$ {cmd}", flush=True)
    _, o, e = c.exec_command(cmd, timeout=t)
    out = o.read().decode(errors="replace")
    err = e.read().decode(errors="replace")
    print(out, end="", flush=True)
    if err: print(err, end="", file=sys.stderr, flush=True)
    print(f"[exit={o.channel.exit_status}]", flush=True)
    return out

print("=== Step 1: whoami + pwd ===")
run("whoami && pwd && hostname")

print("\n=== Step 2: list /root ===")
run("ls -la /root/")

print("\n=== Step 3: search for package.json anywhere ===")
run("find / -maxdepth 6 -name 'package.json' 2>/dev/null | grep -vE 'node_modules|\\.npm' | head -20", t=120)

print("\n=== Step 4: search for cryptosentinel dir ===")
run("find / -maxdepth 6 -type d -iname '*cryptosentinel*' 2>/dev/null | head -20", t=120)

print("\n=== Step 5: search for next.config.ts ===")
run("find / -maxdepth 6 -name 'next.config.*' 2>/dev/null | grep -v node_modules | head -10", t=120)

print("\n=== Step 6: PM2 process list ===")
run("command -v pm2 && pm2 list 2>&1 || echo 'pm2 not in path'; ps aux | grep -E 'next|node' | grep -v grep | head -10", t=30)

print("\n=== Step 7: check what's running on port 10000 or 3000 ===")
run("ss -tlnp 2>&1 | grep -E ':10000|:3000|:80' | head -10", t=15)

c.close()
print("\n=== DONE ===", flush=True)
