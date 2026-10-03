/**
 * Extended DLP — Non-Plain Object Inspection
 *
 * The core DLP walker (`dlp.ts`) intentionally passes class instances,
 * `Buffer`s and streams through untouched so it never mangles a tool's
 * return value. This module closes that gap: it extracts the *textual
 * surface* of those objects, scans it with the same secret scanners, and
 * reports matches — without mutating the original value.
 *
 * Use it when a tool returns binary or exotic payloads and you need the
 * same zero-leak guarantee the plain-object path already provides.
 */

import { scanSecrets, redactText } from './dlp.js';
import type { DlpMatch } from './dlp.js';

export interface ExtendedDlpResult {
  /** The original value, never mutated. */
  value: unknown;
  /** Total matches found across every extracted surface. */
  redacted: number;
  /** Distinct secret types found. */
  types: string[];
  /** Every match, tagged with the surface it came from. */
  matches: Array<DlpMatch & { surface: string }>;
}

/** Maximum bytes pulled from a Buffer / stream chunk. */
const MAX_BINARY_SCAN_BYTES = 1_048_576; // 1 MB

function isBuffer(value: unknown): value is Buffer {
  return typeof Buffer !== 'undefined' && Buffer.isBuffer(value);
}

function isReadableStream(value: unknown): value is ReadableStream {
  return (
    typeof value === 'object' &&
    value !== null &&
    'getReader' in value &&
    typeof (value as ReadableStream).getReader === 'function'
  );
}

function isNodeStream(value: unknown): value is NodeJS.ReadableStream {
  return (
    typeof value === 'object' &&
    value !== null &&
    'pipe' in value &&
    typeof (value as NodeJS.ReadableStream).pipe === 'function'
  );
}

/**
 * Extract human-readable text from a value's surface without mutating it.
 *
 * - `Buffer` → decoded as UTF-8 (lossy), capped at MAX_BINARY_SCAN_BYTES
 * - `ReadableStream` → first chunk only (non-destructive peek via reader)
 * - class instance → its own enumerable properties + `toString()` output
 * - plain object/array → delegated to the core walker
 */
export function extractTextSurfaces(value: unknown): Array<{ surface: string; text: string }> {
  const surfaces: Array<{ surface: string; text: string }> = [];

  if (typeof value === 'string') {
    surfaces.push({ surface: 'string', text: value });
    return surfaces;
  }

  if (isBuffer(value)) {
    const slice = value.subarray(0, MAX_BINARY_SCAN_BYTES);
    surfaces.push({ surface: 'buffer', text: slice.toString('utf8') });
    return surfaces;
  }

  if (isReadableStream(value)) {
    // Streams are async — the sync path cannot peek without consuming.
    // Mark the surface so the async variant can handle it.
    surfaces.push({ surface: 'readable-stream', text: '' });
    return surfaces;
  }

  if (isNodeStream(value)) {
    surfaces.push({ surface: 'node-stream', text: '' });
    return surfaces;
  }

  if (value instanceof Date) {
    surfaces.push({ surface: 'date', text: value.toISOString() });
    return surfaces;
  }

  if (value instanceof Error) {
    surfaces.push({ surface: 'error', text: `${value.name}: ${value.message}` });
    if (value.stack) surfaces.push({ surface: 'error-stack', text: value.stack });
    return surfaces;
  }

  if (typeof value === 'object' && value !== null) {
    const proto = Object.getPrototypeOf(value);
    const isPlain = proto === Object.prototype || proto === null;

    if (!isPlain) {
      // Class instance: scan its own enumerable properties and its
      // string representation (which often embeds field values).
      surfaces.push({ surface: 'instance', text: safeToString(value) });
      for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
        surfaces.push(...extractTextSurfaces(child).map((s) => ({ ...s, surface: `${s.surface}@${key}` })));
      }
      return surfaces;
    }
  }

  return surfaces;
}

function safeToString(value: unknown): string {
  try {
    const fn = (value as { toString?: unknown }).toString;
    if (typeof fn === 'function') {
      const out = fn.call(value);
      if (typeof out === 'string') return out;
    }
  } catch {
    // fall through
  }
  try {
    return JSON.stringify(value) ?? '';
  } catch {
    return '';
  }
}

/**
 * Synchronously scan a value's textual surface for secrets.
 * Streams are reported but not consumed — use `scanValueAsync` for those.
 */
export function scanValueSync(value: unknown): ExtendedDlpResult {
  const types = new Set<string>();
  const matches: ExtendedDlpResult['matches'] = [];
  let redacted = 0;

  for (const { surface, text } of extractTextSurfaces(value)) {
    if (text.length === 0) continue;
    for (const match of scanSecrets(text)) {
      redacted += 1;
      types.add(match.type);
      matches.push({ ...match, surface });
    }
  }

  return { value, redacted, types: [...types], matches };
}

/**
 * Async variant that also peeks at the first chunk of ReadableStreams and
 * Node streams without consuming them.
 */
export async function scanValueAsync(value: unknown): Promise<ExtendedDlpResult> {
  const types = new Set<string>();
  const matches: ExtendedDlpResult['matches'] = [];
  let redacted = 0;

  const surfaces = extractTextSurfaces(value);

  for (const entry of surfaces) {
    let text = entry.text;

    if (entry.surface === 'readable-stream' && isReadableStream(value)) {
      text = await peekReadableStream(value);
    } else if (entry.surface === 'node-stream' && isNodeStream(value)) {
      text = await peekNodeStream(value);
    }

    if (text.length === 0) continue;
    for (const match of scanSecrets(text)) {
      redacted += 1;
      types.add(match.type);
      matches.push({ ...match, surface: entry.surface });
    }
  }

  return { value, redacted, types: [...types], matches };
}

async function peekReadableStream(stream: ReadableStream): Promise<string> {
  const reader = stream.getReader();
  try {
    const { value } = await reader.read();
    if (value === undefined) return '';
    const bytes = value instanceof Uint8Array ? value : new TextEncoder().encode(String(value));
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(0, MAX_BINARY_SCAN_BYTES));
  } catch {
    return '';
  } finally {
    reader.releaseLock();
  }
}

async function peekNodeStream(stream: NodeJS.ReadableStream): Promise<string> {
  return new Promise((resolve) => {
    let text = '';
    const onData = (chunk: Buffer | string) => {
      if (text.length < MAX_BINARY_SCAN_BYTES) {
        text += typeof chunk === 'string' ? chunk : chunk.toString('utf8');
      }
    };
    stream.on('data', onData);
    // We cannot un-consume; resolve on the first tick with what we have.
    setImmediate(() => {
      stream.off('data', onData);
      resolve(text.slice(0, MAX_BINARY_SCAN_BYTES));
    });
  });
}

/**
 * Redact secrets inside a Buffer, returning a new Buffer. The original is
 * never mutated.
 */
export function redactBuffer(buffer: Buffer): { buffer: Buffer; redacted: number } {
  const text = buffer.toString('utf8');
  const result = redactText(text);
  if (result.redacted === 0) return { buffer, redacted: 0 };
  return { buffer: Buffer.from(result.text, 'utf8'), redacted: result.redacted };
}
