#!/bin/bash
set -e

# Audit fix: /tmp is wiped on container restart → data loss.
# Use /data (Render disk mount target).
echo "=== Setting up database ==="
mkdir -p /data
npx prisma db push

echo "=== Starting server (standalone) ==="
# IMPORTANT: use node .next/standalone/server.js, NOT next start.
# next.config.ts has output: 'standalone' — Next.js 16 requires this.
# `next start` causes silent crashes on long-running requests.
PORT=${PORT:-10000} HOSTNAME=0.0.0.0 node .next/standalone/server.js
