#!/bin/bash
set -e
echo "=== Setting up database ==="
mkdir -p /tmp
npx prisma db push --accept-data-loss
echo "=== Starting server ==="
npx next start -p ${PORT:-10000} -H 0.0.0.0
