import { PrismaClient } from '@prisma/client'
import { existsSync, mkdirSync } from 'fs'

/**
 * Database configuration for Render deployment.
 *
 * Render provides persistent disk storage at /data (mounted disk).
 * SQLite database lives at /data/cryptosentinel.db and persists across
 * restarts and deploys — unlike Vercel's /tmp which was wiped on cold start.
 *
 * On Render free plan, /data is persistent within the service lifecycle.
 * For production, upgrade to a paid plan with a larger disk.
 */

// Ensure /data directory exists (Render mounts it automatically on paid plans)
try {
  if (!existsSync('/data')) {
    mkdirSync('/data', { recursive: true })
  }
} catch (e) {
  console.warn('Could not create /data directory:', e)
}

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined
}

const opts: ConstructorParameters<typeof PrismaClient>[0] = {
  log: ['error'],
}

export const db = globalForPrisma.prisma ?? new PrismaClient(opts)

if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = db
