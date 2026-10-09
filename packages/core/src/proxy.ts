/**
 * Corporate forward-proxy transport for `ctx.sandbox.fetch`.
 *
 * Enterprises that force egress through a forward proxy (Squid, Zscaler,
 * Bluecoat, …) block direct outbound sockets — a sandboxed agent then cannot
 * reach any allowed host. This module gives the sandbox the standard
 * curl-compatible behaviour:
 *
 *  1. `VarkConfig.proxy.url` when set (explicit wins over everything);
 *  2. otherwise `HTTP_PROXY` / `HTTPS_PROXY` + `NO_PROXY` from the
 *     environment (`useEnv: false` opts out; `proxy: false` disables
 *     proxying entirely and forces direct egress);
 *  3. otherwise direct (today's behaviour — no proxy config changes nothing
 *     unless the process already exports proxy vars).
 *
 * `http://` targets are sent to the proxy in absolute-form; `https://`
 * targets get a `CONNECT` tunnel and TLS is negotiated end-to-end to the
 * origin, so the proxy can only see *where* the agent talks, never *what*
 * it says. Capability allowlists and the SSRF baseline still run before any
 * socket is opened — a proxy is a transport, never an authorisation.
 */

import { request as httpRequest, type IncomingMessage } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { connect as tlsConnect, type TLSSocket } from 'node:tls';
import type { Socket } from 'node:net';
import { Readable } from 'node:stream';
import type { ProxyConfig } from './types.js';

/** A proxy endpoint ready for use (credentials stripped into `auth`). */
export interface ResolvedProxy {
  url: URL;
  /** `Proxy-Authorization` value derived from the proxy URL's userinfo. */
  auth?: string;
}

/** Split a comma-separated bypass list (`NO_PROXY`, `proxy.noProxy`). */
function splitList(value: string): string[] {
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

/** Parse one `NO_PROXY` entry into a host and optional port. */
function parseBypassEntry(raw: string): { host: string; port?: number } {
  let entry = raw.trim().toLowerCase();
  if (entry.startsWith('*.')) entry = entry.slice(2);
  if (entry.startsWith('.')) entry = entry.slice(1);
  if (entry.startsWith('[')) {
    const end = entry.indexOf(']');
    if (end > -1) {
      const host = entry.slice(1, end);
      const rest = entry.slice(end + 1);
      const port = rest.startsWith(':') ? Number(rest.slice(1)) : undefined;
      return port !== undefined && Number.isFinite(port) ? { host, port } : { host };
    }
  }
  const colon = entry.lastIndexOf(':');
  // Exactly one colon = host:port; bare IPv6 (several colons) stays intact.
  if (colon > -1 && entry.indexOf(':') === colon && /^\d+$/.test(entry.slice(colon + 1))) {
    return { host: entry.slice(0, colon), port: Number(entry.slice(colon + 1)) };
  }
  return { host: entry };
}

/**
 * `NO_PROXY` matching: exact host, any subdomain (`corp.com` matches
 * `api.corp.com`), optional `:port`, `*` bypasses everything.
 */
export function matchesNoProxy(hostname: string, port: number, entries: string[]): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  for (const raw of entries) {
    const entry = parseBypassEntry(raw);
    if (!entry.host) continue;
    if (entry.host === '*') return true;
    if (entry.port !== undefined && entry.port !== port) continue;
    if (host === entry.host || host.endsWith(`.${entry.host}`)) return true;
  }
  return false;
}

/** First non-empty value among the given environment variables. */
function pickEnv(keys: string[]): string | undefined {
  for (const key of keys) {
    const value = process.env[key];
    if (value !== undefined && value.trim().length > 0) return value.trim();
  }
  return undefined;
}

/**
 * Decide how (or whether) `target` should be proxied.
 * Returns `undefined` for direct egress; throws on a *misconfigured* proxy
 * (fail-closed — silently going direct would bypass corporate policy).
 */
export function resolveProxyFor(
  target: string | URL,
  config?: ProxyConfig | false,
): ResolvedProxy | undefined {
  if (config === false) return undefined;
  const url = new URL(target);

  const useEnv = config?.useEnv !== false;
  const noProxyEntries =
    config?.noProxy !== undefined
      ? Array.isArray(config.noProxy)
        ? config.noProxy
        : splitList(config.noProxy)
      : useEnv
        ? splitList(process.env.NO_PROXY ?? process.env.no_proxy ?? '')
        : [];
  const defaultPort = url.protocol === 'https:' ? 443 : 80;
  if (matchesNoProxy(url.hostname, url.port ? Number(url.port) : defaultPort, noProxyEntries)) {
    return undefined;
  }

  let raw: string | undefined;
  let explicit = false;
  if (config?.url !== undefined && config.url.trim().length > 0) {
    raw = config.url.trim();
    explicit = true;
  } else if (useEnv) {
    raw =
      url.protocol === 'https:'
        ? pickEnv(['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy'])
        : pickEnv(['HTTP_PROXY', 'http_proxy']);
  }
  if (raw === undefined) return undefined;

  const normalized = raw.includes('://') ? raw : `http://${raw}`;
  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new Error(
      `invalid proxy ${explicit ? 'url' : `URL in environment ("${raw}")`} — expected e.g. http://proxy.corp:3128`,
    );
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(
      `unsupported proxy scheme "${parsed.protocol}" — only http:// and https:// forward proxies are supported`,
    );
  }

  const auth =
    parsed.username !== '' || parsed.password !== ''
      ? `Basic ${Buffer.from(`${decodeURIComponent(parsed.username)}:${decodeURIComponent(parsed.password)}`).toString('base64')}`
      : undefined;
  parsed.username = '';
  parsed.password = '';
  return { url: parsed, ...(auth ? { auth } : {}) };
}

/** Statuses that must never carry a body (Response constructor rejects them). */
const NULL_BODY_STATUSES = new Set([101, 204, 205, 304]);

/** Map a Node response onto the fetch `Response` shape (streamed, not buffered). */
function toFetchResponse(res: IncomingMessage, isHead: boolean): Response {
  const headers = new Headers();
  for (const [key, value] of Object.entries(res.headers)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) {
      for (const item of value) headers.append(key, item);
    } else {
      headers.append(key, String(value));
    }
  }
  const status = res.statusCode ?? 502;
  const statusText = res.statusMessage ?? '';
  if (isHead || NULL_BODY_STATUSES.has(status)) {
    res.resume(); // drain so the socket can be released
    return new Response(null, { status, statusText, headers });
  }
  return new Response(Readable.toWeb(res) as unknown as BodyInit, { status, statusText, headers });
}

type HopHeaders = Record<string, string>;

/** Absolute-form hop: `http://` target straight to the proxy. */
function httpViaProxy(
  target: URL,
  proxy: ResolvedProxy,
  method: string,
  headers: HopHeaders,
  bytes: Buffer | undefined,
  signal: AbortSignal | undefined,
): Promise<Response> {
  const viaTls = proxy.url.protocol === 'https:';
  const hopHeaders: HopHeaders = {
    ...headers,
    ...(proxy.auth ? { 'proxy-authorization': proxy.auth } : {}),
  };
  return new Promise((resolve, reject) => {
    const req = (viaTls ? httpsRequest : httpRequest)(
      {
        hostname: proxy.url.hostname,
        port: proxy.url.port || (viaTls ? 443 : 80),
        method,
        path: target.toString(),
        headers: hopHeaders,
        ...(signal ? { signal } : {}),
        ...(viaTls ? { servername: proxy.url.hostname } : {}),
      },
      (res) => resolve(toFetchResponse(res, method === 'HEAD')),
    );
    req.on('error', (error: NodeJS.ErrnoException) =>
      reject(new Error(`proxy ${proxy.url.host} request failed: ${error.message}`, { cause: error })),
    );
    if (bytes) req.end(bytes);
    else req.end();
  });
}

/** Open a CONNECT tunnel through the proxy to `authority`. */
function openTunnel(
  target: URL,
  proxy: ResolvedProxy,
  signal: AbortSignal | undefined,
): Promise<Socket> {
  const viaTls = proxy.url.protocol === 'https:';
  const authority = `${target.hostname}:${target.port || 443}`;
  return new Promise((resolve, reject) => {
    const req = (viaTls ? httpsRequest : httpRequest)({
      hostname: proxy.url.hostname,
      port: proxy.url.port || (viaTls ? 443 : 80),
      method: 'CONNECT',
      path: authority,
      headers: {
        host: authority,
        ...(proxy.auth ? { 'proxy-authorization': proxy.auth } : {}),
      },
      ...(signal ? { signal } : {}),
      ...(viaTls ? { servername: proxy.url.hostname } : {}),
    });
    req.on('connect', (res: IncomingMessage, socket: Socket) => {
      if (res.statusCode !== 200) {
        socket.destroy();
        const status = `${res.statusCode}${res.statusMessage ? ` ${res.statusMessage}` : ''}`;
        const hint =
          res.statusCode === 407 ? ' — put credentials in the proxy URL' : '';
        reject(new Error(`proxy CONNECT to ${authority} refused: ${status}${hint}`));
        return;
      }
      resolve(socket);
    });
    req.on('error', (error: Error) =>
      reject(new Error(`proxy ${proxy.url.host} CONNECT failed: ${error.message}`, { cause: error })),
    );
    req.end();
  });
}

/** Negotiate TLS over the tunnel (verified against the origin's cert). */
function secureTunnel(socket: Socket, servername: string): Promise<TLSSocket> {
  return new Promise((resolve, reject) => {
    const secure = tlsConnect({ socket, servername }, () => resolve(secure));
    secure.on('error', (error) => {
      socket.destroy();
      reject(new Error(`TLS through proxy tunnel to ${servername} failed: ${error.message}`, { cause: error }));
    });
  });
}

/** Origin-form request over the established TLS tunnel. */
function requestOverTunnel(
  target: URL,
  method: string,
  headers: HopHeaders,
  bytes: Buffer | undefined,
  signal: AbortSignal | undefined,
  socket: TLSSocket,
): Promise<Response> {
  return new Promise((resolve, reject) => {
    const req = httpsRequest(
      {
        hostname: target.hostname,
        port: target.port || 443,
        servername: target.hostname,
        method,
        path: `${target.pathname}${target.search}`,
        headers,
        createConnection: () => socket,
        ...(signal ? { signal } : {}),
      },
      (res) => resolve(toFetchResponse(res, method === 'HEAD')),
    );
    req.on('error', (error: Error) => reject(error));
    if (bytes) req.end(bytes);
    else req.end();
  });
}

/**
 * Drop-in replacement for `fetch` that routes through the corporate proxy
 * when one is configured (explicitly or via `HTTP_PROXY`/`HTTPS_PROXY`).
 * Without a proxy it *is* `globalThis.fetch` — zero behaviour change.
 */
export async function proxiedFetch(
  url: string | URL,
  init?: RequestInit,
  proxy?: ProxyConfig | false,
): Promise<Response> {
  const target = new URL(url);
  const resolved = resolveProxyFor(target, proxy);
  if (!resolved) return globalThis.fetch(url, init);
  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    // Non-http(s) schemes: let `fetch` produce its usual refusal.
    return globalThis.fetch(url, init);
  }

  // Normalise headers and body through Request — FormData, Blob,
  // URLSearchParams and streams serialise exactly as they do on the
  // direct path (undici's own encoder does the work).
  const method = (init?.method ?? 'GET').toUpperCase();
  const hasBody = init?.body !== undefined && init?.body !== null;
  const normalized = new Request(target, {
    method,
    ...(init?.headers ? { headers: init.headers } : {}),
    ...(hasBody ? { body: init!.body as BodyInit } : {}),
    duplex: 'half',
  } as RequestInit & { duplex?: 'half' });
  const bytes = hasBody ? Buffer.from(await normalized.arrayBuffer()) : undefined;

  const headers: HopHeaders = {};
  normalized.headers.forEach((value, key) => {
    headers[key] = value;
  });
  headers.host = target.host; // the proxy routes on Host, not on our URL bar
  if (bytes) headers['content-length'] = String(bytes.length);

  const signal = init?.signal ?? undefined;
  if (target.protocol === 'https:') {
    const tunnel = await openTunnel(target, resolved, signal);
    const secure = await secureTunnel(tunnel, target.hostname);
    return requestOverTunnel(target, method, headers, bytes, signal, secure);
  }
  return httpViaProxy(target, resolved, method, headers, bytes, signal);
}
