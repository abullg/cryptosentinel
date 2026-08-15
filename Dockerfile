FROM node:24-slim

# Install system deps + curl (for foundryup) + git (for forge install)
RUN apt-get update && apt-get install -y python3 make g++ curl git && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json ./
COPY prisma ./prisma
COPY .next ./.next
COPY public ./public
COPY next.config.ts ./
COPY tsconfig.json ./

RUN npm install && npx prisma generate

ENV NODE_ENV=production
ENV DATABASE_URL=file:/tmp/cryptosentinel.db
ENV PORT=10000
ENV HOSTNAME=0.0.0.0

EXPOSE 10000

# Install Foundry at runtime (not build time) to avoid OOM during Docker build
# forge is used for real exploit testing of smart contract vulnerabilities
CMD ["sh", "-c", "curl -L https://foundry.paradigm.xyz | bash && export PATH=$HOME/.foundry/bin:$PATH && foundryup && cp $HOME/.foundry/bin/forge /usr/local/bin/ && npx prisma db push --accept-data-loss && npx next start -p ${PORT:-10000} -H 0.0.0.0"]
