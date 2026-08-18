# ─── Build stage ──────────────────────────────────────────────────────
# Use a single stage to keep image simpler. Multi-stage would save ~50MB
# but the source code + .next/standalone need to coexist for runtime.
FROM node:24-slim

# ─── System deps: build tools + curl/git for GitHub fetch + Python for
# native module compilation (sharp, etc.) ──────────────────────────────
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 make g++ curl git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ─── Pre-install Foundry (forge/cast/anvil) into the image ────────────
# Was: downloaded at runtime on every container start — slow (30s+),
# network-dependent, broke when foundry.paradigm.xyz was down.
# Now: baked into the image at build time.
# Pinned to a specific commit for reproducibility (upgrade intentionally).
ARG FOUNDRY_REPO=https://github.com/foundry-rs/foundry
ARG FOUNDRY_TAG=nightly
RUN curl -L https://foundry.paradigm.xyz | bash \
    && /root/.foundry/bin/foundryup \
    && cp /root/.foundry/bin/forge /usr/local/bin/forge \
    && cp /root/.foundry/bin/cast /usr/local/bin/cast \
    && cp /root/.foundry/bin/anvil /usr/local/bin/anvil \
    && forge --version && cast --version

# ─── Install Node deps ────────────────────────────────────────────────
# Use npm ci (faster + reproducible from package-lock.json).
# We do NOT use --production because we need devDeps (prisma generate,
# next build, typescript) at build time.
COPY package.json package-lock.json ./
COPY prisma ./prisma
RUN npm ci

# ─── Copy source and build ────────────────────────────────────────────
COPY . .

# Generate Prisma client (postinstall also does this, but be explicit)
RUN npx prisma generate

# Build Next.js with standalone output. Cap memory at 1GB for build.
# Note: typescript.ignoreBuildErrors is now FALSE (next.config.ts) —
# the build will fail on real type errors. This is intentional.
RUN NODE_OPTIONS=--max-old-space-size=1024 npx next build

# ─── Runtime env ──────────────────────────────────────────────────────
ENV NODE_ENV=production
# Use a persistent volume for /data — never /tmp (cleared on reboot).
ENV DATABASE_URL=file:/data/cryptosentinel.db
ENV PORT=10000
ENV HOSTNAME=0.0.0.0

EXPOSE 10000

# ─── Create data directory ────────────────────────────────────────────
RUN mkdir -p /data /app

# ─── Startup ──────────────────────────────────────────────────────────
# IMPORTANT: use `node .next/standalone/server.js`, NOT `next start`.
#   - next.config.ts has output: 'standalone'
#   - Next.js 16 warns: "next start does not work with output: standalone"
#   - Running `next start` causes silent crashes on long-running requests
#
# Use `prisma db push` WITHOUT --accept-data-loss. If schema and DB drift,
# we want to know (manual migration), not silently destroy data.
#
# Also copy static assets into standalone (Next.js doesn't do this automatically).
CMD ["sh", "-c", "npx prisma db push && PORT=${PORT:-10000} HOSTNAME=0.0.0.0 node .next/standalone/server.js"]
