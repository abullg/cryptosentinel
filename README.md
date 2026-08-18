# CryptoSentinel

Production-grade smart contract & web application security audit platform.

## Quick start (development)

```bash
npm install
cp .env.example .env
# Fill in your OPENROUTER_API_KEY
npx prisma generate
npm run dev
```

Open http://localhost:3000.

## Stack

- **Frontend**: Next.js 16 (App Router), React 19, Tailwind 4, shadcn/ui
- **Backend**: Next.js API Routes, Prisma ORM (SQLite)
- **AI**: OpenRouter API (GLM 5.2 / DeepSeek V4 Pro)
- **Validation**: Foundry (forge) + cast for real exploit testing
- **Process**: PM2 + Caddy
- **Database**: SQLite (persistent volume at `/data`)

## Production deployment (VPS / Hostinger)

### One-time setup on the VPS

```bash
# 1. Install Node 24 + npm + pm2 + caddy
curl -fsSL https://deb.nodesource.com/setup_24.x | sudo bash -
sudo apt-get install -y nodejs caddy
sudo npm install -g pm2

# 2. Clone the repo
sudo mkdir -p /opt/cryptosentinel && sudo chown $USER:$USER /opt/cryptosentinel
git clone https://github.com/abullg/cryptosentinel.git /opt/cryptosentinel
cd /opt/cryptosentinel

# 3. Install deps + build
npm ci
npx prisma generate
NODE_OPTIONS=--max-old-space-size=2048 npx next build

# 4. Create persistent data directory
sudo mkdir -p /data /var/log/cryptosentinel
sudo chown -R $USER:$USER /data /var/log/cryptosentinel

# 5. Configure environment variables
sudo tee /etc/cryptosentinel.env << 'EOF'
DATABASE_URL=file:/data/cryptosentinel.db
OPENROUTER_API_KEY=sk-or-v1-your-key-here
GITHUB_TOKEN=ghp_your_token_here  # optional
CRYPTOSENTINEL_AUTH_TOKEN=your-strong-password-here  # REQUIRED for production!
CRYPTOSENTINEL_APP_URL=https://your-domain.com
NODE_ENV=production
PORT=3000
HOSTNAME=0.0.0.0
EOF
sudo chmod 600 /etc/cryptosentinel.env
# Load env vars before PM2 starts:
echo "set -a; source /etc/cryptosentinel.env; set +a" | sudo tee /etc/profile.d/cryptosentinel.sh

# 6. Generate a strong auth token
AUTH_TOKEN=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
sudo sed -i "s/^CRYPTOSENTINEL_AUTH_TOKEN=.*/CRYPTOSENTINEL_AUTH_TOKEN=$AUTH_TOKEN/" /etc/cryptosentinel.env

# 7. Apply DB schema (no --accept-data-loss!)
npx prisma db push

# 8. Start with PM2
pm2 start ecosystem.config.js --env production
pm2 save
pm2 startup  # follow the printed instructions

# 9. Install + configure Caddy
sudo cp Caddyfile /etc/caddy/Caddyfile
# Edit /etc/caddy/Caddyfile to use your domain instead of :81
sudo systemctl reload caddy
```

### Auto-deploy via GitHub Actions

1. Add the following **repository secrets** (Settings → Secrets and variables → Actions):
   - `VPS_HOST` — IP or hostname (e.g. `187.77.181.127`)
   - `VPS_USER` — SSH user (typically `root`)
   - `VPS_SSH_KEY` — private SSH key (run `ssh-keygen -t ed25519 -f deploy_key` locally, add the public key to `~/.ssh/authorized_keys` on the VPS)

2. Trigger the workflow:
   - Go to **Actions** tab → **Deploy to VPS** → **Run workflow**
   - Type `deploy` in the confirmation field

The workflow:
1. Checks out the repo
2. Builds + lints on GitHub's runner
3. SSHes to your VPS (auto-detects the SSH port — tries 22, 2222, 65022, etc.)
4. Rsyncs the code to `/opt/cryptosentinel`
5. Runs `npm ci`, `prisma generate`, `next build`, `prisma db push`
6. Reloads PM2 with the new code
7. Polls `/api/health` to verify the deploy succeeded

## Authentication

When `CRYPTOSENTINEL_AUTH_TOKEN` env var is set (min 8 chars), all `/api/*`
routes require authentication. Three ways to authenticate:

1. **Cookie** (preferred for browsers): POST `/api/login` with `{ "password": "<token>" }` — sets HttpOnly cookie for 7 days.
2. **Header**: `Authorization: Bearer <token>`
3. **Query**: `?token=<token>` (for SSE/EventSource which can't set headers)

If the env var is not set, the API is open (suitable for localhost dev only).

## Audit findings

See `AUDIT_FIXES.md` for the full list of issues found and fixed.

## License

Private.
