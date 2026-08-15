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
CMD ["sh", "-c", "curl -L https://foundry.paradigm.xyz | bash && $HOME/.foundry/bin/foundryup && cp $HOME/.foundry/bin/forge /usr/local/bin/forge && npx prisma db push --accept-data-loss && npx next start -p ${PORT:-10000} -H 0.0.0.0"]
