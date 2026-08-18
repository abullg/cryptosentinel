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
 *   - Loopback (127.0.0.0/8, ::1)
 *   - Link-local (169.254.0.0/16 — includes AWS metadata)
 *   - Private ranges (10/8, 172.16/12, 192.168/16, fc00::/7)
 *   - Multicast / broadcast
 *   - Common sensitive ports (Docker API, DBs, etc.)
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
  443,   // HTTPS — allowed
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
  // Note: 80, 443, 8080, 8443, 3000, 10000 are allowed (web service ports)
]);

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'ip6-localhost',
  'ip6-loopback',
  'metadata.google.internal', // GCP metadata
  'metadata',
  'host.docker.internal',
]);

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

  // Port — block sensitive ports
  const port = parsed.port ? parseInt(parsed.port, 10) : parsed.protocol === 'https:' ? 443 : 80;
  if (SENSITIVE_PORTS.has(port)) {
    return {
      blocked: true,
      reason: `Port ${port} is on the SSRF blocklist (sensitive service).`,
    };
  }

  // Hostname — block obvious internal hostnames
  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, ''); // strip IPv6 brackets

  if (BLOCKED_HOSTNAMES.has(hostname)) {
    return {
      blocked: true,
      reason: `Hostname "${hostname}" is on the SSRF blocklist.`,
    };
  }

  // IP literal — check if private
  const ipVersion = isIP(hostname);
  if (ipVersion === 4 && isPrivateV4(hostname)) {
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
