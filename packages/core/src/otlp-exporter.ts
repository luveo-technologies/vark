/**
 * OpenTelemetry (OTLP/HTTP) audit exporter.
 *
 * Ships hash-chained audit records to any OTLP collector (Jaeger, Tempo,
 * Datadog, Honeycomb, an OTel Collector gateway, …) as log records, so the
 * security trail lands in the same observability stack as the rest of the
 * platform. Zero dependencies: the OTLP/HTTP JSON protocol is small enough
 * to speak directly over the built-in `fetch` (Node ≥ 20).
 *
 * It implements `AuditSink`, so it drops straight into the runtime config
 * (alone or inside `MultiAuditSink` next to a file sink):
 *
 * ```ts
 * const otlp = new OtlpAuditExporter({ endpoint: 'http://otel-collector:4318/v1/logs' });
 * const runtime = new VarkRuntime({ audit: { sink: (entry) => otlp.write(entry) } });
 * // …
 * await otlp.close(); // final flush on shutdown
 * ```
 *
 * Encoding follows the OTLP logs JSON mapping: one `ExportLogsServiceRequest`
 * per POST, `resourceLogs → scopeLogs → logRecords`, int64 fields as JSON
 * strings, vark-specific fields under the `vark.*` attribute namespace.
 * Records are batched (`maxBatchSize` / `flushIntervalMs`); the periodic
 * timer is `unref`'d so telemetry never holds the event loop open.
 */

import type { AuditEntry, GateDecision } from './types.js';
import type { AuditSink, AuditSinkOptions } from './audit-sink.js';

/** Default OTLP/HTTP logs endpoint of a local collector. */
export const DEFAULT_OTLP_LOGS_ENDPOINT = 'http://localhost:4318/v1/logs';

/** One OTLP attribute (JSON encoding of `KeyValue`). */
export interface OtlpAttribute {
  key: string;
  value:
    | { stringValue: string }
    | { intValue: string }
    | { doubleValue: number }
    | { arrayValue: { values: OtlpAttribute['value'][] } };
}

/** One OTLP log record (JSON encoding of `LogRecord`). */
export interface OtlpLogRecord {
  timeUnixNano: string;
  severityText: 'INFO' | 'WARN';
  body: { stringValue: string };
  attributes: OtlpAttribute[];
}

export interface OtlpExporterOptions extends AuditSinkOptions {
  /** Full OTLP/HTTP logs endpoint. @default 'http://localhost:4318/v1/logs' */
  endpoint?: string;
  /** `service.name` resource attribute. @default 'vark' */
  serviceName?: string;
  /** Extra HTTP headers (collector auth tokens, tenancy headers). */
  headers?: Record<string, string>;
  /** Buffer size that triggers an automatic export. @default 64 */
  maxBatchSize?: number;
  /** Periodic export interval in ms; `0` disables the timer. @default 5_000 */
  flushIntervalMs?: number;
  /** Attach the redacted argument snapshot (`sanitizedInputs`) as an attribute — accurate but potentially large. @default false */
  includeSanitizedInputs?: boolean;
}

const str = (value: string): OtlpAttribute['value'] => ({ stringValue: value });
const int = (value: number): OtlpAttribute['value'] => ({ intValue: String(Math.trunc(value)) });
const dbl = (value: number): OtlpAttribute['value'] => ({ doubleValue: value });

/** `AuditEntry` → OTLP log record (public so pipelines can pre-map entries). */
export function toOtlpLogRecord(
  entry: AuditEntry,
  includeSanitizedInputs = false,
): OtlpLogRecord {
  const millis = Date.parse(entry.timestamp);
  const timeUnixNano = String(BigInt(Number.isNaN(millis) ? Date.now() : millis) * 1_000_000n);

  const attributes: OtlpAttribute[] = [
    { key: 'vark.decision', value: str(entry.decision) },
    { key: 'vark.session_id', value: str(entry.sessionId) },
    { key: 'vark.tool', value: str(entry.tool) },
    { key: 'vark.seq', value: int(entry.seq) },
    { key: 'vark.execution_time_ms', value: dbl(entry.executionTimeMs) },
    { key: 'vark.inspection_ms', value: dbl(entry.inspectionMs) },
    { key: 'vark.input_redactions', value: int(entry.inputRedactions) },
    { key: 'vark.output_redactions', value: int(entry.outputRedactions) },
    { key: 'vark.injection_sanitized', value: int(entry.injectionSanitized) },
    { key: 'vark.tokens_saved', value: int(entry.tokensSaved) },
    { key: 'vark.hash', value: str(entry.hash) },
    { key: 'vark.prev_hash', value: str(entry.prevHash) },
  ];
  if (entry.blockedBy) attributes.push({ key: 'vark.blocked_by', value: str(entry.blockedBy) });
  if (entry.findings.length > 0) {
    attributes.push({ key: 'vark.findings', value: { arrayValue: { values: entry.findings.map(str) } } });
  }
  if (includeSanitizedInputs) {
    attributes.push({ key: 'vark.sanitized_inputs', value: str(JSON.stringify(entry.sanitizedInputs)) });
  }

  return {
    timeUnixNano,
    severityText: severityFor(entry.decision),
    body: { stringValue: entry.reason ?? entry.decision },
    attributes,
  };
}

/** Refusals are security events — they export at WARN so collectors alert on them. */
function severityFor(decision: GateDecision): 'INFO' | 'WARN' {
  return decision === 'ALLOWED' ? 'INFO' : 'WARN';
}

export class OtlpAuditExporter implements AuditSink {
  readonly name = 'otlp';
  readonly #endpoint: string;
  readonly #resourceAttributes: OtlpAttribute[];
  readonly #headers: Record<string, string>;
  readonly #maxBatchSize: number;
  readonly #flushIntervalMs: number;
  readonly #includeSanitizedInputs: boolean;
  readonly #onError: NonNullable<AuditSinkOptions['onError']>;
  readonly #failClosed: boolean;
  #buffer: OtlpLogRecord[] = [];
  #timer?: ReturnType<typeof setInterval>;
  #closed = false;
  #failed = false;
  #lastError?: Error;
  #inFlight: Promise<void> = Promise.resolve();

  constructor(options: OtlpExporterOptions = {}) {
    this.#endpoint = options.endpoint ?? DEFAULT_OTLP_LOGS_ENDPOINT;
    this.#resourceAttributes = [{ key: 'service.name', value: str(options.serviceName ?? 'vark') }];
    this.#headers = options.headers ?? {};
    this.#maxBatchSize = options.maxBatchSize ?? 64;
    this.#flushIntervalMs = options.flushIntervalMs ?? 5_000;
    this.#includeSanitizedInputs = options.includeSanitizedInputs ?? false;
    this.#onError = options.onError ?? (() => undefined);
    this.#failClosed = options.failClosed ?? false;
  }

  /** Records waiting in the buffer (not yet exported). */
  get pending(): number {
    return this.#buffer.length;
  }

  /** True after the most recent export attempt failed (fail-closed pairing). */
  get failed(): boolean {
    return this.#failed;
  }

  write(entry: AuditEntry): void {
    if (this.#closed) return;
    if (this.#failClosed && this.#failed) {
      const previous = this.#lastError;
      this.#failed = false;
      this.#lastError = undefined;
      // Buffer the current record and probe: the export attempt either
      // succeeds (service restored) or re-arms the failure. Either way the
      // caller learns about the PREVIOUS failure right now.
      this.#buffer.push(toOtlpLogRecord(entry, this.#includeSanitizedInputs));
      this.#armTimer();
      void this.#pump().catch(() => undefined);
      throw previous ?? new Error(`${this.name} sink export failed`);
    }
    this.#buffer.push(toOtlpLogRecord(entry, this.#includeSanitizedInputs));
    this.#armTimer();
    if (this.#buffer.length >= this.#maxBatchSize) {
      void this.#pump().catch(() => undefined);
    }
  }

  /** Export everything currently buffered. */
  async flush(): Promise<void> {
    await this.#pump();
  }

  async close(): Promise<void> {
    if (this.#timer) {
      clearInterval(this.#timer);
      this.#timer = undefined;
    }
    await this.flush();
    this.#closed = true;
  }

  /** Serialised export pump — batches never POST concurrently. */
  async #pump(): Promise<void> {
    this.#inFlight = this.#inFlight.then(() => this.#drain());
    return this.#inFlight;
  }

  async #drain(): Promise<void> {
    while (this.#buffer.length > 0) {
      const batch = this.#buffer.splice(0, this.#maxBatchSize);
      try {
        await this.#post(batch);
        this.#failed = false;
        this.#lastError = undefined;
      } catch (error) {
        const err = error instanceof Error ? error : new Error(String(error));
        this.#failed = true;
        this.#lastError = err;
        this.#onError(err, this.name);
        break; // keep draining from a working endpoint, not a broken one
      }
    }
  }

  async #post(batch: OtlpLogRecord[]): Promise<void> {
    const payload = {
      resourceLogs: [
        {
          resource: { attributes: this.#resourceAttributes },
          scopeLogs: [{ scope: { name: 'vark.audit' }, logRecords: batch }],
        },
      ],
    };
    const response = await fetch(this.#endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...this.#headers },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      throw new Error(`OTLP export failed: HTTP ${response.status} ${response.statusText}`);
    }
  }

  #armTimer(): void {
    if (this.#timer || this.#flushIntervalMs <= 0) return;
    this.#timer = setInterval(() => {
      void this.#pump().catch(() => undefined);
    }, this.#flushIntervalMs);
    // Telemetry must never keep the process alive.
    this.#timer.unref?.();
  }
}
