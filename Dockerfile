FROM node:24-slim

RUN apt-get update && apt-get install -y python3 make g++ curl git && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json ./
COPY prisma ./prisma
COPY . .

RUN npm install
RUN npx prisma generate
RUN NODE_OPTIONS=--max-old-space-size=1024 npx next build

ENV NODE_ENV=production
ENV DATABASE_URL=file:/tmp/cryptosentinel.db
ENV PORT=10000
ENV HOSTNAME=0.0.0.0

EXPOSE 10000

# Install Foundry at runtime (forge) for real exploit testing
# + run prisma db push + start Next.js
#
# IMPORTANT: use `node .next/standalone/server.js`, NOT `next start`.
# next.config.ts has output: 'standalone', and Next.js 16 warns:
#   "next start" does not work with "output: standalone" configuration.
#   Use "node .next/standalone/server.js" instead.
# Running `next start` with standalone causes silent crashes on
# long-running requests (AI analysis times out after 100s, PM2 restarts
# the process, user sees 'stuck loading for 20 minutes').
CMD ["sh", "-c", "curl -L https://foundry.paradigm.xyz | bash && $HOME/.foundry/bin/foundryup && cp $HOME/.foundry/bin/forge /usr/local/bin/forge && npx prisma db push --accept-data-loss && PORT=${PORT:-10000} HOSTNAME=0.0.0.0 node .next/standalone/server.js"]
