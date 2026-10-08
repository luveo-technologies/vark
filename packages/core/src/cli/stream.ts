/**
 * `--output-format streaming-json` — NDJSON output for log-shipper ingestion.
 *
 * Every event is exactly one JSON object per line on stdout, written the
 * moment it happens (results stream as each item completes instead of after
 * the whole batch), so `tail -f`, Vector, Fluent Bit, or a SIEM pipeline can
 * ingest decisions without parsing human-oriented output. Text output (the
 * default) is byte-for-byte unchanged.
 *
 * Event envelope, discriminated by `type`:
 *  - `{ type: 'result',  command, ... }`   one line per item (payload file,
 *    policy assertion, session row, scan run)
 *  - `{ type: 'summary', command, ok, ... }` always the final line of a
 *    successful run; `ok` mirrors the process exit verdict
 *  - `{ type: 'error',   command, message }` a failure that would have gone
 *    to stderr in text mode
 *
 * Exit codes are identical to text mode — the format only changes rendering,
 * never the security verdict.
 */

/** Supported values for `--output-format`. */
export type OutputFormat = 'text' | 'streaming-json';

/**
 * Validate a raw `--output-format` value.
 *
 * Returns `'text'` for `undefined` (the default) and throws on anything
 * outside the accepted set so typos fail loudly instead of silently
 * producing human output in a machine pipeline.
 */
export function resolveOutputFormat(raw: string | undefined): OutputFormat {
  if (raw === undefined || raw === 'text') return 'text';
  if (raw === 'streaming-json') return 'streaming-json';
  throw new Error(`unknown output format "${raw}" (expected: text | streaming-json)`);
}

/** One NDJSON event. `command` names the emitting subcommand. */
export interface StreamEvent {
  type: 'result' | 'summary' | 'error';
  command: string;
  [key: string]: unknown;
}

/** Write a single event as one line on stdout. */
export function writeEvent(event: StreamEvent): void {
  process.stdout.write(`${JSON.stringify(event)}\n`);
}
