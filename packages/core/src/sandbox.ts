/**
 * Capability Sandbox — the authorisation layer.
 *
 * Two responsibilities:
 *  1. Decide whether a tool may touch a path / host *before* it runs.
 *  2. Hand `run()` a sandboxed {@link ExecutionContext} whose `readFile` /
 *     `fetch` re-check every single call (defence in depth), plus a wall-clock
 *     timeout enforced with `Promise.race`.
 */

import { readFile as fsReadFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import { checkEgress, checkEgressSync } from './security/network/ssrf-guard.js';
import type { CapabilityConfig, ExecutionContext, InspectionResult } from './types.js';
import { CapabilityViolationError, VarkTimeoutError } from './types.js';

/** Fallback wall-clock budget when neither tool nor runtime declares one. */
export const DEFAULT_MAX_EXECUTION_MS = 10_000;

/** Keys that normally carry a filesystem path (`path`, `filePath`, `dir`, …). */
const PATH_KEY = /(?:path|file|dir|folder|source|dest|target)/i;

/** Values that are unambiguously filesystem paths regardless of their key. */
const PATH_VALUE = /^(?:\.{1,2}[\\/]|[\\/]|~[\\/]|[a-z]:[\\/])/i;

const URL_PATTERN = /\bhttps?:\/\/\S+/gi;

const DEPTH_LIMIT = 12;

/** Resolve to an absolute, forward-slash path so globs and targets compare directly. */
export function normalizePath(target: string): string {
  const absolute = resolve(target);
  return process.platform === 'win32' ? absolute.replace(/\\/g, '/') : absolute;
}

/**
 * Convert a glob pattern (`*`, double-star segments, `?`) to an anchored
 * RegExp. Single `*` never crosses `/`; a double-star segment also matches
 * zero directories; case-insensitive on win32.
 * Exported for `vark check`'s payload-pattern resolution (Node ≥ 20 has no
 * `fs.promises.glob`, which is Node 22+).
 */
export function globToRegExp(glob: string): RegExp {
  let out = '';
  let i = 0;
  while (i < glob.length) {
    const char = glob[i] ?? '';
    if (char === '*') {
      if (glob[i + 1] === '*') {
        if (glob[i + 2] === '/') {
          out += '(?:.*\\/)?'; // `a/**/b` matches `a/b` and `a/x/b`
          i += 3;
        } else {
          out += '.*';
          i += 2;
        }
      } else {
        out += '[^/]*';
        i += 1;
      }
      continue;
    }
    if (char === '?') {
      out += '[^/]';
      i += 1;
      continue;
    }
    out += char.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    i += 1;
  }
  const caseInsensitive = process.platform === 'win32';
  return new RegExp(`^${out}$`, caseInsensitive ? 'i' : '');
}

function isGlob(pattern: string): boolean {
  return pattern.includes('*') || pattern.includes('?');
}

/**
 * Match `target` against a grant list. Patterns may be globs
 * (`./workspace/*`, `./**\/logs\/**`) or plain prefixes (`./workspace`).
 * Both sides are resolved against `process.cwd()`, so `../` in a target
 * physically escapes the grant and therefore fails to match.
 */
export function checkPathAllowed(target: string, allow?: string[]): InspectionResult {
  if (!allow || allow.length === 0) return { safe: true };

  const normalized = normalizePath(target);
  const grants = allow.map((grant) => normalizePath(grant.trim())).filter(Boolean);

  for (const grant of grants) {
    if (isGlob(grant)) {
      if (globToRegExp(grant).test(normalized)) return { safe: true };
    } else if (normalized === grant || normalized.startsWith(`${grant}/`)) {
      return { safe: true };
    }
  }

  return {
    safe: false,
    reason:
      `path "${target}" is outside the filesystem capability grants ` +
      `(${allow.join(', ')})`,
  };
}

function parseHost(url: string): { hostname: string; host: string } | undefined {
  try {
    const parsed = new URL(url);
    return { hostname: parsed.hostname.toLowerCase(), host: parsed.host.toLowerCase() };
  } catch {
    return undefined;
  }
}

/** Match a URL against `network.allowedHosts`. Supports `*.example.com`. */
export function checkHostAllowed(url: string, allowedHosts: string[]): InspectionResult {
  const parsed = parseHost(url);
  if (!parsed) return { safe: false, reason: `unverifiable outbound URL "${url}"` };
  const { hostname, host } = parsed;

  for (const raw of allowedHosts) {
    const grant = raw.trim().toLowerCase();
    if (!grant) continue;
    if (grant.startsWith('*.')) {
      const suffix = grant.slice(1); // ".example.com"
      if (hostname.length > suffix.length && hostname.endsWith(suffix)) return { safe: true };
    } else if (hostname === grant || host === grant) {
      return { safe: true };
    }
  }

  return {
    safe: false,
    reason: `host of "${url}" is not in the network capability grants (${allowedHosts.join(', ')})`,
  };
}

function networkPolicy(
  capabilities?: CapabilityConfig,
): ({ mode: 'allow' } | { mode: 'deny' } | { mode: 'allowlist'; allowedHosts: string[] }) & {
  allowPrivate: boolean;
} {
  const network = capabilities?.network;
  const allowPrivate = typeof network === 'object' && network?.allowPrivate === true;
  if (network === false) return { mode: 'deny', allowPrivate };
  if (network && typeof network === 'object') {
    const allowedHosts = network.allowedHosts ?? [];
    if (allowedHosts.length === 0) {
      // No allowlist: deny by default. An explicit `allowPrivate` without a
      // host list means "unrestricted including local/private targets".
      return allowPrivate ? { mode: 'allow', allowPrivate } : { mode: 'deny', allowPrivate };
    }
    return { mode: 'allowlist', allowedHosts, allowPrivate };
  }
  return { mode: 'allow', allowPrivate };
}

function isPathLike(key: string, value: string): boolean {
  return PATH_KEY.test(key) || PATH_VALUE.test(value);
}

/**
 * Audit every argument value against the tool's capabilities.
 *
 * Path-shaped values are matched against `filesystem.allow`; URL-shaped values
 * are matched against `network`. Returns the first violation, if any.
 */
export function inspectArguments(args: unknown, capabilities?: CapabilityConfig): InspectionResult {
  const allow = capabilities?.filesystem?.allow;
  const policy = networkPolicy(capabilities);

  const walk = (value: unknown, key: string, depth: number): InspectionResult => {
    if (depth > DEPTH_LIMIT) return { safe: true };

    if (typeof value === 'string') {
      if (allow && allow.length > 0 && isPathLike(key, value)) {
        const verdict = checkPathAllowed(value, allow);
        if (!verdict.safe) return verdict;
      }
      URL_PATTERN.lastIndex = 0;
      for (const url of value.match(URL_PATTERN) ?? []) {
        if (policy.mode === 'deny') {
          return { safe: false, reason: `outbound network is disabled, refusing "${url}"` };
        }
        if (policy.mode === 'allowlist') {
          const verdict = checkHostAllowed(url, policy.allowedHosts);
          if (!verdict.safe) return verdict;
        }
        // Baseline SSRF policy — applies in every mode, including open
        // egress: metadata endpoints, private ranges, loopback names,
        // embedded credentials, non-http(s) schemes.
        const egress = checkEgressSync(url, { allowPrivate: policy.allowPrivate });
        if (!egress.allowed) {
          return { safe: false, reason: egress.reason ?? `egress refused for "${url}"` };
        }
      }
      return { safe: true };
    }

    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i += 1) {
        const verdict = walk(value[i], key, depth + 1);
        if (!verdict.safe) return verdict;
      }
      return { safe: true };
    }

    if (typeof value === 'object' && value !== null) {
      for (const [childKey, child] of Object.entries(value)) {
        const verdict = walk(child, depth === 0 ? childKey : `${key}.${childKey}`, depth + 1);
        if (!verdict.safe) return verdict;
      }
    }

    return { safe: true };
  };

  return walk(args, 'args', 0);
}

/** Throwing variant of {@link checkPathAllowed}. */
export function assertPathAllowed(target: string, capabilities?: CapabilityConfig): void {
  const verdict = checkPathAllowed(target, capabilities?.filesystem?.allow);
  if (!verdict.safe) throw new CapabilityViolationError(verdict.reason ?? 'filesystem capability violation');
}

/** Throwing variant of the network policy check. */
export function assertNetworkAllowed(url: string, capabilities?: CapabilityConfig): void {
  const policy = networkPolicy(capabilities);
  if (policy.mode === 'deny') {
    throw new CapabilityViolationError(`outbound network is disabled, refusing "${url}"`);
  }
  if (policy.mode === 'allowlist') {
    const verdict = checkHostAllowed(url, policy.allowedHosts);
    if (!verdict.safe) {
      throw new CapabilityViolationError(verdict.reason ?? 'network capability violation');
    }
  }
  // Baseline SSRF policy — enforced even for unrestricted egress.
  const egress = checkEgressSync(url, { allowPrivate: policy.allowPrivate });
  if (!egress.allowed) {
    throw new CapabilityViolationError(egress.reason ?? `egress refused for "${url}"`);
  }
}

/** Redirect statuses followed (each target re-validated through the guard). */
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/** Redirect hops before the request is refused outright. */
const MAX_FETCH_REDIRECTS = 5;

/** Bodies that can be replayed on a followed redirect. */
function isReplayableBody(body: BodyInit | null | undefined): boolean {
  if (body === undefined || body === null) return true;
  if (typeof body === 'string') return true;
  if (body instanceof URLSearchParams) return true;
  if (typeof Blob !== 'undefined' && body instanceof Blob) return false; // consumed on read
  if (ArrayBuffer.isView(body) || body instanceof ArrayBuffer) return false;
  return false;
}

/**
 * `fetch` with redirect revalidation: `redirect: 'manual'` on every hop,
 * each `Location` pushed back through the capability + baseline egress
 * guards before it is followed — a redirect can never reach an internal or
 * metadata target that the original URL could not.
 */
async function fetchWithRevalidation(
  url: string,
  init: RequestInit | undefined,
  capabilities: CapabilityConfig | undefined,
): Promise<Response> {
  let current = url;
  let method = (init?.method ?? 'GET').toUpperCase();
  let body: BodyInit | null | undefined = init?.body;

  for (let hop = 0; hop <= MAX_FETCH_REDIRECTS; hop += 1) {
    const response = await globalThis.fetch(current, {
      ...init,
      method,
      body: body ?? undefined,
      redirect: 'manual',
    });
    if (!REDIRECT_STATUSES.has(response.status)) return response;

    const location = response.headers.get('location');
    if (!location) return response; // 3xx without a target — hand it back
    if (hop === MAX_FETCH_REDIRECTS) {
      throw new CapabilityViolationError(`egress exceeded ${MAX_FETCH_REDIRECTS} redirects`);
    }
    // Cannot replay a consumed stream body — return the 3xx unfollowed
    // rather than replaying or bypassing the guard.
    if (!isReplayableBody(body)) return response;

    let next: string;
    try {
      next = new URL(location, current).toString();
    } catch {
      throw new CapabilityViolationError(`unverifiable redirect target "${location}"`);
    }
    assertNetworkAllowed(next, capabilities);
    const policy = networkPolicy(capabilities);
    const egress = await checkEgress(next, { allowPrivate: policy.allowPrivate });
    if (!egress.allowed) {
      throw new CapabilityViolationError(egress.reason ?? `redirect target refused: "${next}"`);
    }

    // Method handling follows the fetch spec: 303 → GET; 301/302 on a
    // non-GET/HEAD request → GET; 307/308 preserve method and body.
    if (
      response.status === 303 ||
      ((response.status === 301 || response.status === 302) && method !== 'GET' && method !== 'HEAD')
    ) {
      method = 'GET';
      body = undefined;
    }
    try {
      await response.body?.cancel();
    } catch {
      // already consumed or unreadable — nothing to release
    }
    current = next;
  }
  throw new CapabilityViolationError(`egress exceeded ${MAX_FETCH_REDIRECTS} redirects`);
}

/** Build the privileged host services handed to `run()`. */
export function createSandbox(capabilities?: CapabilityConfig): ExecutionContext['sandbox'] {
  return {
    async readFile(path: string): Promise<string> {
      assertPathAllowed(path, capabilities);
      return fsReadFile(resolve(path), 'utf8');
    },
    async fetch(url: string, init?: RequestInit): Promise<Response> {
      // Sync policy + literal-address guard first (fail fast, no DNS).
      assertNetworkAllowed(url, capabilities);
      // DNS stage — fail-closed: an unresolvable name is refused.
      const policy = networkPolicy(capabilities);
      const egress = await checkEgress(url, { allowPrivate: policy.allowPrivate });
      if (!egress.allowed) {
        throw new CapabilityViolationError(egress.reason ?? `egress refused for "${url}"`);
      }
      return fetchWithRevalidation(url, init, capabilities);
    },
  };
}

/**
 * Race `task` against a wall-clock budget. Rejects with
 * {@link VarkTimeoutError} when the budget elapses.
 */
export async function withTimeout<T>(task: () => Promise<T>, maxExecutionMs: number): Promise<T> {
  const budget = Number.isFinite(maxExecutionMs) && maxExecutionMs > 0
    ? maxExecutionMs
    : DEFAULT_MAX_EXECUTION_MS;

  const started = task();
  // If the timeout wins the race the task must still be observed, otherwise a
  // late rejection would surface as an unhandled promise rejection.
  started.catch(() => undefined);

  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      started,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(
          () => reject(new VarkTimeoutError(`execution exceeded ${budget}ms (maxExecutionMs)`)),
          budget,
        );
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
