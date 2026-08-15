FROM node:24-slim

# Install system deps + git (needed by forge install) + curl (for foundryup)
RUN apt-get update && apt-get install -y python3 make g++ curl git && rm -rf /var/lib/apt/lists/*

# Install Foundry — industry standard for smart contract exploit testing
# Used by Trail of Bits, OpenZeppelin, Code4rena, HackenProof auditors
RUN curl -L https://foundry.paradigm.xyz | bash && \
    /root/.foundry/bin/foundryup && \
    cp /root/.foundry/bin/forge /usr/local/bin/forge && \
    cp /root/.foundry/bin/cast /usr/local/bin/cast && \
    cp /root/.foundry/bin/anvil /usr/local/bin/anvil

ENV PATH="/root/.foundry/bin:$PATH"

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

CMD ["sh", "-c", "npx prisma db push --accept-data-loss && npx next start -p ${PORT:-10000} -H 0.0.0.0"]
