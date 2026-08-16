#!/usr/bin/env python3
"""Quick check of SSE output captured from previous run."""
import os, sys, paramiko

HOST = "187.77.181.127"
PASSWORD = os.environ.get("DEPLOY_PWD", "")

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(hostname=HOST, port=22, username="root",
          password=PASSWORD, look_for_keys=False, allow_agent=False, timeout=30)

print("=== Check if /tmp/sse_out.txt exists ===")
_, o, _ = c.exec_command("ls -la /tmp/sse_out.txt /tmp/vault.json 2>&1", timeout=10)
print(o.read().decode(errors="replace"))

print("\n=== Last 80 lines of PM2 logs ===")
_, o, _ = c.exec_command("pm2 logs cryptosentinel --lines 80 --nostream 2>&1 | tail -100", timeout=20)
out = o.read().decode(errors="replace")
print(out[-3000:])  # last 3k chars

print("\n=== If sse_out.txt exists, summarize ===")
_, o, _ = c.exec_command("""if [ -f /tmp/sse_out.txt ]; then
  echo "OUTPUT SIZE: $(wc -c < /tmp/sse_out.txt)"
  echo "---EVENT COUNTS---"
  grep "^event:" /tmp/sse_out.txt | sort | uniq -c
  echo "---TARGET/LAB/THEORETICAL markers---"
  grep -oE "TARGET-VALIDATED[A-Za-z -]*|LAB-VALIDATED[A-Za-z -]*|THEORETICAL[A-Za-z -]*" /tmp/sse_out.txt | head -10
  echo "---FINDINGS---"
  grep -E '"title"|"severity"|"confidence"|"validationScope"' /tmp/sse_out.txt | head -20
fi""", timeout=15)
print(o.read().decode(errors="replace"))

c.close()
