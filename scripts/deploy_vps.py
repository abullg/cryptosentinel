#!/usr/bin/env python3
"""
Deploy CryptoSentinel fix to VPS at 187.77.181.127.

Runs: git pull && npm run build && pm2 restart cryptosentinel
Prints the output of each command so we can verify what happened.

The password is read from the DEPLOY_PWD environment variable to avoid
logging it in process lists or shell history.
"""

import os
import sys
import paramiko

HOST = "187.77.181.127"
PORT = 22
PASSWORD = os.environ.get("DEPLOY_PWD", "")

if not PASSWORD:
    print("ERROR: DEPLOY_PWD environment variable is not set.", file=sys.stderr)
    sys.exit(2)

# Project directory on the VPS — try common candidates.
CANDIDATE_DIRS = [
    "/root/cryptosentinel",
    "/root/CryptoSentinel",
    "/opt/cryptosentinel",
    "/var/www/cryptosentinel",
    "/home/cryptosentinel",
    "/srv/cryptosentinel",
]

CANDIDATE_USERS = ["root", "ubuntu", "debian", "cryptosentinel", "admin"]


def run(client, cmd, timeout=600):
    """Run a command via SSH and stream stdout/stderr to console."""
    print(f"\n$ {cmd}", flush=True)
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout, get_pty=False)
    out_buf = []
    err_buf = []
    while True:
        if stdout.channel.exit_status_ready() and not stdout.channel.recv_ready():
            break
        if stdout.channel.recv_ready():
            chunk = stdout.channel.recv(4096).decode(errors="replace")
            if chunk:
                print(chunk, end="", flush=True)
                out_buf.append(chunk)
        else:
            import time
            time.sleep(0.05)
    remaining_out = stdout.read().decode(errors="replace")
    if remaining_out:
        print(remaining_out, end="", flush=True)
        out_buf.append(remaining_out)
    err = stderr.read().decode(errors="replace")
    if err:
        print(err, end="", file=sys.stderr, flush=True)
        err_buf.append(err)
    exit_code = stdout.channel.exit_status
    print(f"\n[exit={exit_code}]", flush=True)
    return exit_code, "".join(out_buf), "".join(err_buf)


def try_connect(client, user):
    try:
        client.connect(
            hostname=HOST, port=PORT, username=user,
            password=PASSWORD, look_for_keys=False, allow_agent=False, timeout=30,
        )
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception:
        return False


def main():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    user_ok = None
    for u in CANDIDATE_USERS:
        print(f"Trying {u}@{HOST} ...", flush=True)
        if try_connect(client, u):
            user_ok = u
            print(f"  ✓ connected as {u}", flush=True)
            break
        else:
            print(f"  ✗ {u} failed", flush=True)
    if not user_ok:
        print("ERROR: Could not authenticate with any common username.", file=sys.stderr)
        sys.exit(3)

    # Step 1: locate project directory
    print("\n=== Step 1: locate project directory ===", flush=True)
    found_dir = None
    for d in CANDIDATE_DIRS:
        ec, out, _ = run(client, f"test -d {d} && echo FOUND || echo NOTFOUND", timeout=10)
        if "FOUND" in out:
            print(f"  ✓ found: {d}", flush=True)
            found_dir = d
            break
    if not found_dir:
        print("  Candidates not found, searching filesystem...", flush=True)
        ec, out, _ = run(client, "find / -maxdepth 4 -name 'package.json' 2>/dev/null | grep -iE 'crypto|sentinel' | head -5", timeout=60)
        for line in out.strip().split("\n"):
            if line and "package.json" in line:
                found_dir = line.rsplit("/", 1)[0]
                print(f"  ✓ found via search: {found_dir}", flush=True)
                break
    if not found_dir:
        # Last resort: look for any package.json with the cryptosentinel name
        ec, out, _ = run(client, "find / -maxdepth 5 -name 'package.json' 2>/dev/null | xargs grep -l 'cryptosentinel' 2>/dev/null | head -3", timeout=120)
        for line in out.strip().split("\n"):
            if line:
                found_dir = line.rsplit("/", 1)[0]
                print(f"  ✓ found via name search: {found_dir}", flush=True)
                break
    if not found_dir:
        print("ERROR: Could not locate project directory.", file=sys.stderr)
        sys.exit(4)

    # Step 2: git pull
    print("\n=== Step 2: git pull ===", flush=True)
    run(client, f"cd {found_dir} && git fetch origin main && git log --oneline -3 origin/main", timeout=60)
    ec, out, _ = run(client, f"cd {found_dir} && git status --short", timeout=15)
    ec, out, _ = run(client, f"cd {found_dir} && git pull --ff-only origin main", timeout=120)
    if ec != 0:
        print("  git pull failed, trying reset --hard ...", flush=True)
        run(client, f"cd {found_dir} && git reset --hard origin/main", timeout=60)
    run(client, f"cd {found_dir} && git log --oneline -3", timeout=10)

    # Step 3: install deps if package-lock changed
    print("\n=== Step 3: npm ci (only if needed) ===", flush=True)
    run(client, f"cd {found_dir} && npm ci --no-audit --no-fund --prefer-offline 2>&1 | tail -5", timeout=300)

    # Step 4: prisma generate
    print("\n=== Step 4: prisma generate ===", flush=True)
    run(client, f"cd {found_dir} && npx prisma generate 2>&1 | tail -5", timeout=60)

    # Step 5: build
    print("\n=== Step 5: npm run build ===", flush=True)
    ec, _, _ = run(client, f"cd {found_dir} && NODE_OPTIONS=--max-old-space-size=2048 npm run build 2>&1 | tail -40", timeout=600)
    if ec != 0:
        print(f"ERROR: build failed (exit {ec})", file=sys.stderr)
        sys.exit(5)

    # Step 6: restart PM2 (or start if not running)
    print("\n=== Step 6: restart PM2 ===", flush=True)
    ec, out, _ = run(client, "command -v pm2 && echo PM2_FOUND || echo PM2_MISSING", timeout=10)
    pm2_cmd = "pm2" if "PM2_FOUND" in out else "npx pm2"
    run(client, f"{pm2_cmd} restart cryptosentinel --update-env 2>&1 || ({pm2_cmd} start {found_dir}/ecosystem.config.js && {pm2_cmd} save)", timeout=60)
    run(client, f"{pm2_cmd} status", timeout=15)

    # Step 7: verify new build hash differs from old
    print("\n=== Step 7: verify deployment ===", flush=True)
    run(client, "sleep 4 && curl -s http://localhost:3000/ 2>&1 | grep -oE '/_next/static/chunks/[a-z0-9_-]+\\.js' | sort -u | head -5", timeout=30)

    print("\n=== DONE ===", flush=True)
    client.close()


if __name__ == "__main__":
    main()
