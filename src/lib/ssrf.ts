/**
 * SSRF protection — used by /api/fetch-url to prevent the backend from
 * being used as a proxy to internal services.
 *
 * Audit fix MED-1: previously `/api/fetch-url` accepted ANY URL and
 * the backend would happily fetch it — including the AWS/GCP metadata
 * service (169.254.169.254), localhost, internal IPs, Docker API,
 * PostgreSQL, Redis, etc.
 *
 * This module blocks:
 *   - Loopback (127.0.0.0/8, ::1) — UNLESS GT_ALLOWLIST_ENABLED=true
 *   - Link-local (169.254.0.0/16 — includes AWS metadata)
 *   - Private ranges (10/8, 172.16/12, 192.168/16, fc00::/7)
 *   - Multicast / broadcast
 *   - Common sensitive ports (Docker API, DBs, etc.)
 *
 * GT allowlist (post Claude audit): for benchmark on self-hosted GT
 * docker containers (juice-shop, dvwa, canary, negative — see
 * tests/gt/docker-compose.yml), we need to allow localhost fetches.
 * This is safe BECAUSE:
 *   1. Egress iptables allowlist (see setup-gt-and-egress.yml) blocks
 *      ALL outbound except 53/80/443/22/123 + loopback. Even if
 *      prompt injection tells GLM to fetch attacker.test, the kernel
 *      rejects the connection.
 *   2. GT containers run on localhost only — no DNS, no external
 *      network dependency.
 *   3. Only enabled when GT_ALLOWLIST_ENABLED=true env is set —
 *      production deploy should NOT set this.
 *
 * Usage:
 *   const blocked = isSsrfBlocked(url);
 *   if (blocked) return NextResponse.json({ error: 'Forbidden URL' }, { status: 403 });
 */

import { isIP } from 'net';

const SENSITIVE_PORTS = new Set([
  22,    // SSH
  23,    // Telnet
  25,    // SMTP
  53,    // DNS
  110,   // POP3
  143,   // IMAP
  389,   // LDAP
  465,   // SMTPS
  6379,  // Redis
  3306,  // MySQL
  5432,  // PostgreSQL
  27017, // MongoDB
  9200,  // Elasticsearch
  9300,  // Elasticsearch
  11211, // Memcached
  61613, // ActiveMQ
  8161,  // ActiveMQ web
  15672, // RabbitMQ management
  8123,  // ClickHouse HTTP
  9000,  // PHP-FPM / SonarQube
  9042,  // Cassandra
  2375,  // Docker API (unencrypted)
  2376,  // Docker API (TLS)
  10250, // Kubernetes kubelet
  10255, // Kubernetes kubelet read-only
  6443,  // Kubernetes API
  // Allowed web ports: 80 (HTTP), 443 (HTTPS), 8080, 8443, 3000, 10000
]);

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'ip6-localhost',
  'ip6-loopback',
  'metadata.google.internal', // GCP metadata
  'metadata',
  'host.docker.internal',
]);

// GT (Ground Truth) allowlist — for self-hosted benchmark docker containers.
// Enable via GT_ALLOWLIST_ENABLED=true env. NEVER enable in production.
const GT_ALLOWLIST_HOSTNAMES = new Set([
  'localhost',
  '127.0.0.1',
  '::1',
  // GT docker container names (if accessed via docker network)
  'cs-juice-shop',
  'cs-dvwa',
  'cs-canary',
  'cs-negative',
  'cs-wrongsecrets',
  'cs-crapi-main',
  'cs-webgoat',
  'cs-vampi',  // VAmPI Python/Flask — added 2026-08-21
]);

// GT allowlist ports (matches tests/gt/docker-compose.yml port mappings)
const GT_ALLOWLIST_PORTS = new Set([
  3001, // juice-shop
  3002, // dvwa
  3003, // wrongsecrets (disabled but listed)
  3004, // crapi (disabled)
  3005, // webgoat (was disabled — now enabled)
  3006, // webgoat H2 console
  3007, // canary
  3008, // negative
  3009, // vampi — added 2026-08-21
]);

function isGtAllowlistEnabled(): boolean {
  return process.env.GT_ALLOWLIST_ENABLED === 'true';
}

function isGtAllowedTarget(hostname: string, port: number): boolean {
  if (!isGtAllowlistEnabled()) return false;
  // Only allow specific GT hostnames + ports — defense in depth
  if (!GT_ALLOWLIST_HOSTNAMES.has(hostname)) return false;
  if (!GT_ALLOWLIST_PORTS.has(port)) return false;
  return true;
}

function isPrivateV4(ip: string): boolean {
  // Expected format: a.b.c.d, validated by net.isIP
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) {
    return true; // malformed → treat as blocked
  }
  const [a, b] = parts;
  if (a === 0) return true;                   // 0.0.0.0/8 "this host"
  if (a === 10) return true;                  // 10.0.0.0/8 private
  if (a === 127) return true;                 // 127.0.0.0/8 loopback
  if (a === 169 && b === 254) return true;    // 169.254.0.0/16 link-local + cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 private
  if (a === 192 && b === 168) return true;    // 192.168.0.0/16 private
  if (a === 192 && b === 0 && parts[2] === 2) return true; // 192.0.2.0/24 documentation
  if (a === 198 && (b === 18 || b === 19)) return true;    // 198.18.0.0/15 benchmark
  if (a >= 224) return true;                  // 224+ multicast/reserved
  return false;
}

function isPrivateV6(ip: string): boolean {
  const lower = ip.toLowerCase();
  if (lower === '::1') return true;           // loopback
  if (lower === '::') return true;            // unspecified
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // unique local
  if (lower.startsWith('fe80')) return true;   // link-local
  if (lower.startsWith('ff')) return true;     // multicast
  // IPv4-mapped IPv6: ::ffff:a.b.c.d — extract and check
  const v4Mapped = lower.match(/::ffff:([0-9.]+)$/);
  if (v4Mapped) return isPrivateV4(v4Mapped[1]);
  // IPv4-compatible: ::a.b.c.d
  const v4Compat = lower.match(/^::([0-9.]+)$/);
  if (v4Compat) return isPrivateV4(v4Compat[1]);
  return false;
}

export interface SsrfCheckResult {
  blocked: boolean;
  reason?: string;
}

/**
 * Check if a URL should be blocked for SSRF protection.
 * Returns { blocked: false } if safe to fetch, or { blocked: true, reason } if not.
 *
 * Note: this does NOT perform DNS resolution (we'd need to do that at fetch
 * time to defeat DNS rebinding attacks). For now, hostname-based blocking
 * is the first line of defense. If you need stronger protection, use a
 * custom DNS resolver that:
 *   1. Resolves hostname
 *   2. Checks the IP against isPrivateV4/V6
 *   3. Connects to the resolved IP directly (with original Host header)
 */
export function isSsrfBlocked(rawUrl: string): SsrfCheckResult {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { blocked: true, reason: 'Invalid URL format' };
  }

  // Protocol — only http/https allowed (no file://, gopher://, ftp://, etc.)
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      blocked: true,
      reason: `Protocol "${parsed.protocol}" is not allowed. Only http and https are permitted.`,
    };
  }

  // Port — block sensitive ports (unless GT-allowed target)
  const port = parsed.port ? parseInt(parsed.port, 10) : parsed.protocol === 'https:' ? 443 : 80;
  const hostnameForGt = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (isGtAllowedTarget(hostnameForGt, port)) {
    // GT allowlist bypasses sensitive port check (defense: iptables egress)
    return { blocked: false };
  }
  if (SENSITIVE_PORTS.has(port)) {
    return {
      blocked: true,
      reason: `Port ${port} is on the SSRF blocklist (sensitive service).`,
    };
  }

  // Hostname — block obvious internal hostnames (unless GT-allowed)
  const hostname = hostnameForGt;

  if (isGtAllowedTarget(hostname, port)) {
    return { blocked: false };
  }

  if (BLOCKED_HOSTNAMES.has(hostname)) {
    return {
      blocked: true,
      reason: `Hostname "${hostname}" is on the SSRF blocklist.`,
    };
  }

  // IP literal — check if private (GT allowlist already returned above)
  const ipVersion = isIP(hostname);
  if (ipVersion === 4 && isPrivateV4(hostname)) {
    // GT allowlist already returned for 127.0.0.1, so this is a different private IP
    return {
      blocked: true,
      reason: `IP ${hostname} is a private/reserved address.`,
    };
  }
  if (ipVersion === 6 && isPrivateV6(hostname)) {
    return {
      blocked: true,
      reason: `IPv6 ${hostname} is a private/reserved address.`,
    };
  }

  // Subdomain of a blocked hostname (e.g. metadata.localhost)
  for (const blocked of BLOCKED_HOSTNAMES) {
    if (hostname.endsWith('.' + blocked)) {
      return {
        blocked: true,
        reason: `Hostname "${hostname}" is a subdomain of blocked "${blocked}".`,
      };
    }
  }

  return { blocked: false };
}
