#!/bin/bash
set -e
echo "=== Installing dependencies ==="
npm install --production=false
echo "=== Generating Prisma client ==="
npx prisma generate
echo "=== Building Next.js ==="
NODE_OPTIONS=--max-old-space-size=1024 npx next build
echo "=== Copying static into standalone (required for output: standalone) ==="
# IMPORTANT: when output: 'standalone' is set in next.config.ts, Next.js builds
# the server bundle in .next/standalone but does NOT copy the static assets
# (JS chunks, CSS, public/) into it. The standalone server.js expects them at
# .next/standalone/.next/static and .next/standalone/public. Without this copy
# step, every chunk returns 404 and the browser shows "Page couldn't load".
cp -r .next/static .next/standalone/.next/
if [ -d public ]; then cp -r public .next/standalone/; fi
echo "=== Build complete ==="
