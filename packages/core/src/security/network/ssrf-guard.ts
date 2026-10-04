/**
 * SSRF & Network Boundary Egress
 *
 * DNS resolution, IP range validation, DNS pinning, redirect re-validation,
 * IPv6/IPv4 variant handling, and strict wildcard domain matching.
 */

import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

export interface SsrfConfig {
  /** Allowed domains (exact or wildcard). */
  allowedDomains: string[];
  /** Allowed IP ranges (CIDR notation). */
  allowedIpRanges?: string[];
  /** Whether to pin DNS resolutions. @default true */
  pinDns?: boolean;
  /** Maximum redirect hops. @default 5 */
  maxRedirects?: number;
  /** Block cloud metadata endpoints. @default true */
  blockMetadata?: boolean;
}

export interface SsrfCheckResult {
  allowed: boolean;
  reason?: string;
  resolvedIp?: string;
  pinnedIp?: string;
}

// Cloud metadata endpoints
const METADATA_IPS = new Set([
  '169.254.169.254',  // AWS, GCP, Azure
  '169.254.169.253',  // GCP
  '192.0.0.170',      // Oracle
  '100.100.100.200',  // Alibaba
]);

// Blocked IP ranges (CIDR)
const BLOCKED_RANGES: Array<{ start: bigint; end: bigint }> = [
  // Loopback
  { start: ipToBigInt('127.0.0.0'), end: ipToBigInt('127.255.255.255') },
  // Private ranges
  { start: ipToBigInt('10.0.0.0'), end: ipToBigInt('10.255.255.255') },
  { start: ipToBigInt('172.16.0.0'), end: ipToBigInt('172.31.255.255') },
  { start: ipToBigInt('192.168.0.0'), end: ipToBigInt('192.168.255.255') },
  // Link-local
  { start: ipToBigInt('169.254.0.0'), end: ipToBigInt('169.254.255.255') },
  // Cloud metadata
  { start: ipToBigInt('169.254.169.254'), end: ipToBigInt('169.254.169.254') },
  // IPv6 loopback
  { start: ipToBigInt('::1'), end: ipToBigInt('::1') },
  // IPv6 unique local
  { start: ipToBigInt('fc00::'), end: ipToBigInt('fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff') },
  // IPv6 link-local
  { start: ipToBigInt('fe80::'), end: ipToBigInt('febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff') },
];

function ipToBigInt(ip: string): bigint {
  const parts = ip.split(':');
  if (parts.length > 2) {
    // IPv6
    let result = 0n;
    for (const part of ip.split(':')) {
      result = (result << 16n) | BigInt(parseInt(part || '0', 16));
    }
    return result;
  }
  // IPv4
  const octets = ip.split('.').map(Number);
  return ((BigInt(octets[0]!) << 24n) | (BigInt(octets[1]!) << 16n) |
          (BigInt(octets[2]!) << 8n) | BigInt(octets[3]!));
}

function isIpInBlockedRange(ip: string): boolean {
  const bigInt = ipToBigInt(ip);
  return BLOCKED_RANGES.some((range) => bigInt >= range.start && bigInt <= range.end);
}

/**
 * Normalize IP address: handle IPv4-mapped IPv6, octal, decimal, hex.
 */
export function normalizeIp(ip: string): string {
  // IPv4-mapped IPv6: ::ffff:127.0.0.1 → 127.0.0.1
  if (ip.startsWith('::ffff:')) {
    const ipv4 = ip.slice(7);
    if (isIP(ipv4) === 4) return ipv4;
  }

  // Decimal IP: 2130706433 → 127.0.0.1
  if (/^\d+$/.test(ip)) {
    const num = Number(ip);
    if (num >= 0 && num <= 4294967295) {
      return [
        (num >>> 24) & 0xff,
        (num >>> 16) & 0xff,
        (num >>> 8) & 0xff,
        num & 0xff,
      ].join('.');
    }
  }

  // Hex IP: 0x7f000001 → 127.0.0.1
  if (/^0x[0-9a-f]+$/i.test(ip)) {
    const num = parseInt(ip, 16);
    return [
      (num >>> 24) & 0xff,
      (num >>> 16) & 0xff,
      (num >>> 8) & 0xff,
      num & 0xff,
    ].join('.');
  }

  // Octal IP: 0177.0.0.1 → 127.0.0.1
  if (/^0[0-7]/.test(ip)) {
    const parts = ip.split('.').map((p) => parseInt(p, 8));
    return parts.join('.');
  }

  return ip;
}

/**
 * Strict wildcard domain matching.
 * `*.example.com` matches `sub.example.com` but NOT `evilexample.com` or `example.com.evil.net`.
 */
export function matchWildcardDomain(hostname: string, pattern: string): boolean {
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(1); // ".example.com"
    // Must be a subdomain: at least one label before the suffix
    return hostname.endsWith(suffix) && hostname.length > suffix.length;
  }
  return hostname === pattern;
}

/**
 * Check if a hostname matches any allowed domain pattern.
 */
export function isDomainAllowed(hostname: string, allowedDomains: string[]): boolean {
  const normalized = hostname.toLowerCase();
  return allowedDomains.some((domain) => matchWildcardDomain(normalized, domain));
}

/**
 * Strip user@host credentials from URL.
 */
export function stripUrlCredentials(url: string): { cleanUrl: string; hadCredentials: boolean } {
  try {
    const parsed = new URL(url);
    if (parsed.username || parsed.password) {
      parsed.username = '';
      parsed.password = '';
      return { cleanUrl: parsed.toString(), hadCredentials: true };
    }
  } catch {
    // Invalid URL
  }
  return { cleanUrl: url, hadCredentials: false };
}

/**
 * Full SSRF check: resolve DNS, validate IP, check domain allowlist.
 */
export async function checkSsrf(
  url: string,
  config: SsrfConfig,
): Promise<SsrfCheckResult> {
  // Strip credentials
  const { cleanUrl, hadCredentials } = stripUrlCredentials(url);
  if (hadCredentials) {
    return { allowed: false, reason: 'URLs with embedded credentials are not allowed' };
  }

  let hostname: string;
  try {
    const parsed = new URL(cleanUrl);
    hostname = parsed.hostname.toLowerCase();
  } catch {
    return { allowed: false, reason: 'Invalid URL' };
  }

  // Check domain allowlist
  if (!isDomainAllowed(hostname, config.allowedDomains)) {
    return { allowed: false, reason: `Domain "${hostname}" is not in the allowlist` };
  }

  // Resolve DNS
  let resolvedIp: string;
  try {
    const addresses = await lookup(hostname, { all: true });
    if (addresses.length === 0) {
      return { allowed: false, reason: 'DNS resolution failed' };
    }
    resolvedIp = addresses[0]!.address;
  } catch {
    return { allowed: false, reason: 'DNS resolution failed' };
  }

  // Normalize IP (handle IPv4-mapped IPv6, decimal, hex, octal)
  const normalizedIp = normalizeIp(resolvedIp);

  // Check against blocked ranges
  if (isIpInBlockedRange(normalizedIp)) {
    return { allowed: false, reason: `Resolved IP ${normalizedIp} is in a blocked range` };
  }

  // Check metadata endpoints
  if (config.blockMetadata !== false && METADATA_IPS.has(normalizedIp)) {
    return { allowed: false, reason: 'Cloud metadata endpoints are blocked' };
  }

  // DNS pinning
  const pinnedIp = config.pinDns === false ? undefined : normalizedIp;

  return { allowed: true, resolvedIp: normalizedIp, pinnedIp };
}

/**
 * Re-validate a redirect URL against SSRF checks.
 */
export async function checkRedirect(
  redirectUrl: string,
  config: SsrfConfig,
  hopCount: number = 0,
): Promise<SsrfCheckResult> {
  const maxRedirects = config.maxRedirects ?? 5;
  if (hopCount >= maxRedirects) {
    return { allowed: false, reason: `Too many redirects (max ${maxRedirects})` };
  }
  return checkSsrf(redirectUrl, config);
}
