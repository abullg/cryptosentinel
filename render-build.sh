#!/bin/bash
set -e
echo "=== Installing dependencies ==="
npm install --production=false
echo "=== Generating Prisma client ==="
npx prisma generate
echo "=== Building Next.js ==="
NODE_OPTIONS=--max-old-space-size=1024 npx next build
echo "=== Build complete ==="
