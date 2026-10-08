/**
 * Persistent Audit Sink
 *
 * The core `AuditLogger` keeps its trail in memory with an optional `sink`
 * callback. This module turns that callback into a first-class pluggable
 * interface with production-ready defaults:
 *
 *   - `FileAuditSink`   — append-only JSON Lines to a file (default)
 *   - `StreamAuditSink` — any writable stream (stdout, gRPC, webhook)
 *   - `MultiAuditSink`  — fan-out to several sinks with error isolation
 *
 * Sinks are best-effort by default: a failing sink never breaks the guard
 * pipeline. Errors are reported through the optional `onError` callback.
 * Constructed with `failClosed: true`, a sink surfaces persistence failures
 * to its caller instead — pair with `audit.failClosed` on the runtime for
 * refuse-until-the-trail-is-durable behaviour.
 */

import { appendFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { AuditEntry } from './types.js';

export interface AuditSink {
  /** Human-readable sink name for error reporting. */
  readonly name: string;
  /** Persist one audit entry. Implementations must never throw. */
  write(entry: AuditEntry): void | Promise<void>;
  /** Flush any buffered writes. */
  flush?(): Promise<void>;
  /** Release resources. */
  close?(): Promise<void>;
}

export interface AuditSinkOptions {
  /** Called when a sink fails. Defaults to swallowing the error. */
  onError?: (error: Error, sinkName: string) => void;
  /**
   * Surface persistence failures to the caller instead of swallowing them
   * (pair with `audit.failClosed` on the runtime for refuse-until-durable
   * behaviour). The async file sink throws the *previous* failure on the
   * next `write()` while re-attempting the current entry, so a recovered
   * disk restores service automatically.
   */
  failClosed?: boolean;
}

/**
 * Append-only JSON Lines file sink. Creates parent directories on first write.
 * Writes are serialised through an internal promise queue so concurrent
 * appends never interleave.
 */
export class FileAuditSink implements AuditSink {
  readonly name = 'file';
  readonly #path: string;
  readonly #onError: NonNullable<AuditSinkOptions['onError']>;
  readonly #failClosed: boolean;
  #queue: Promise<void> = Promise.resolve();
  #closed = false;
  #failed = false;
  #lastError?: Error;

  constructor(path: string, options: AuditSinkOptions = {}) {
    this.#path = path;
    this.#onError = options.onError ?? (() => undefined);
    this.#failClosed = options.failClosed ?? false;
  }

  get filePath(): string {
    return this.#path;
  }

  write(entry: AuditEntry): void {
    if (this.#closed) return;
    if (this.#failClosed && this.#failed) {
      const previous = this.#lastError;
      this.#failed = false;
      this.#lastError = undefined;
      // Enqueue the current entry first — it doubles as the probe (a
      // successful append keeps us healthy, a failure re-arms) — then
      // surface the previous failure so the caller can refuse this call.
      this.#enqueue(entry);
      throw previous ?? new Error(`${this.name} sink write failed`);
    }
    this.#enqueue(entry);
  }

  #enqueue(entry: AuditEntry): void {
    const line = `${JSON.stringify(entry)}\n`;
    this.#queue = this.#queue
      .then(async () => {
        await mkdir(dirname(this.#path), { recursive: true });
        await appendFile(this.#path, line, 'utf8');
      })
      .catch((error: unknown) => {
        const err = error instanceof Error ? error : new Error(String(error));
        this.#failed = true;
        this.#lastError = err;
        this.#onError(err, this.name);
      });
  }

  async flush(): Promise<void> {
    await this.#queue;
  }

  async close(): Promise<void> {
    this.#closed = true;
    await this.flush();
  }
}

/**
 * Write entries to any Node writable stream (stdout, a socket, a gRPC
 * stream). Entries are JSON Lines. Backpressure is respected via `write()`
 * return value; the sink never writes after `close()`.
 */
export class StreamAuditSink implements AuditSink {
  readonly name = 'stream';
  readonly #stream: NodeJS.WritableStream;
  readonly #onError: NonNullable<AuditSinkOptions['onError']>;
  readonly #failClosed: boolean;
  #closed = false;

  constructor(stream: NodeJS.WritableStream, options: AuditSinkOptions = {}) {
    this.#stream = stream;
    this.#onError = options.onError ?? (() => undefined);
    this.#failClosed = options.failClosed ?? false;
  }

  write(entry: AuditEntry): void {
    if (this.#closed) return;
    try {
      this.#stream.write(`${JSON.stringify(entry)}\n`);
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      this.#onError(err, this.name);
      if (this.#failClosed) throw err;
    }
  }

  async flush(): Promise<void> {
    if (typeof (this.#stream as unknown as { flush?: unknown }).flush === 'function') {
      await Promise.resolve((this.#stream as unknown as { flush: () => Promise<void> }).flush());
    }
  }

  async close(): Promise<void> {
    this.#closed = true;
    const stream = this.#stream as unknown as { end?: () => void };
    if (typeof stream.end === 'function') stream.end();
  }
}

/**
 * Fan-out to multiple sinks. A failure in one sink is isolated — the others
 * still receive the entry.
 */
export class MultiAuditSink implements AuditSink {
  readonly name = 'multi';
  readonly #sinks: AuditSink[];
  readonly #onError: NonNullable<AuditSinkOptions['onError']>;
  readonly #failClosed: boolean;

  constructor(sinks: AuditSink[], options: AuditSinkOptions = {}) {
    this.#sinks = sinks;
    this.#onError = options.onError ?? (() => undefined);
    this.#failClosed = options.failClosed ?? false;
  }

  write(entry: AuditEntry): void {
    let firstError: Error | undefined;
    for (const sink of this.#sinks) {
      try {
        sink.write(entry);
      } catch (error) {
        const err = error instanceof Error ? error : new Error(String(error));
        this.#onError(err, sink.name);
        firstError ??= err;
      }
    }
    // Fan-out isolation still holds for persistence (every sink was given
    // the entry); with failClosed the caller learns that at least one
    // destination is broken.
    if (this.#failClosed && firstError) throw firstError;
  }

  async flush(): Promise<void> {
    await Promise.all(this.#sinks.map((sink) => Promise.resolve(sink.flush?.()).catch(() => undefined)));
  }

  async close(): Promise<void> {
    await Promise.all(this.#sinks.map((sink) => Promise.resolve(sink.close?.()).catch(() => undefined)));
  }
}

/**
 * Build a default sink from configuration. When no path is given the sink
 * writes to `process.stdout` so audit telemetry is visible by default.
 */
export function createDefaultAuditSink(
  options: { path?: string; stream?: NodeJS.WritableStream } & AuditSinkOptions = {},
): AuditSink {
  if (options.path) return new FileAuditSink(options.path, options);
  if (options.stream) return new StreamAuditSink(options.stream, options);
  return new StreamAuditSink(process.stdout, options);
}
