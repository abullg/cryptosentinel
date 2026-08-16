#!/usr/bin/env python3
"""Diagnose what's hanging on the VPS."""
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
    if err: print(err, end="", file=sys.stderr, flush=True)
    print(f"[exit={o.channel.exit_status}]", flush=True)
    return out

print("=== PM2 status ===")
run("pm2 list")

print("\n=== PM2 logs (last 80 lines) ===")
run("pm2 logs cryptosentinel --lines 80 --nostream 2>&1 | tail -100")

print("\n=== Active connections to localhost:3000 ===")
run("ss -tnp 2>&1 | grep ':3000' | head -20")

print("\n=== Top processes by CPU ===")
run("ps aux --sort=-%cpu | head -10")

print("\n=== Memory ===")
run("free -h")

print("\n=== Disk ===")
run("df -h | head -10")

print("\n=== Outgoing connections (to GLM API etc) ===")
run("ss -tn state established 2>&1 | grep -v ':3000\\|:22\\|:80' | head -20")

c.close()
print("\n=== DONE ===", flush=True)
