/**
 * Cryptographic Audit Logger.
 *
 * Every tool invocation appends one immutable record to a hash-chained,
 * append-only trail: `hash(n) = SHA-256(canonical(record[n] + prevHash))`.
 *
 * - **Tamper-evident** — editing, reordering or dropping a record breaks the
 *   chain and `verify()` reports the exact `seq` where it happened.
 * - **Tamper-resistant** (optional) — pass `hmacKey` and each link is signed
 *   with HMAC-SHA256, so an attacker without the key cannot rebuild a valid
 *   chain.
 * - **Append-only** — records are frozen on write; there is no update API.
 */

import { createHash, createHmac } from 'node:crypto';

import type { AuditEntry, AuditLoggerConfig, BlockedBy, GateDecision } from './types.js';

/** Hash of the entry before the first entry. */
export const GENESIS_HASH = '0'.repeat(64);

/**
 * Deterministic JSON: object keys sorted, `undefined`/functions dropped,
 * cycles collapsed. Two structurally equal values always produce the same
 * bytes — the prerequisite for hashing and for loop fingerprints.
 */
export function stableStringify(value: unknown): string {
  const seen = new WeakSet<object>();

  const walk = (node: unknown): string => {
    if (node === null) return 'null';
    switch (typeof node) {
      case 'number':
        return Number.isFinite(node) ? String(node) : 'null';
      case 'boolean':
        return String(node);
      case 'string':
        return JSON.stringify(node);
      case 'bigint':
        return JSON.stringify(String(node));
      case 'undefined':
      case 'function':
      case 'symbol':
        return 'null';
      default:
        break;
    }

    const object = node as object;
    if (seen.has(object)) return '"[Circular]"';
    seen.add(object);

    if (Array.isArray(object)) return `[${object.map(walk).join(',')}]`;
    if (object instanceof Date) return JSON.stringify(object.toISOString());

    const body = Object.entries(object as Record<string, unknown>)
      .filter(([, child]) => child !== undefined && typeof child !== 'function' && typeof child !== 'symbol')
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([key, child]) => `${JSON.stringify(key)}:${walk(child)}`)
      .join(',');

    return `{${body}}`;
  };

  return walk(value);
}

/** Fields the caller supplies; the logger adds `seq`, `timestamp` and hashes. */
export interface AuditAppendInput {
  sessionId: string;
  tool: string;
  decision: GateDecision;
  blockedBy?: BlockedBy;
  reason?: string;
  sanitizedInputs: unknown;
  inputRedactions?: number;
  outputRedactions?: number;
  injectionSanitized?: number;
  executionTimeMs: number;
  inspectionMs?: number;
  tokensSaved?: number;
  findings?: string[];
}

export interface AuditVerifyResult {
  ok: boolean;
  checked: number;
  /** `seq` of the first record that failed validation. */
  brokenAt?: number;
}

export class AuditLogger {
  readonly #config: AuditLoggerConfig;
  #entries: AuditEntry[] = [];
  #seq = 0;
  #prevHash = GENESIS_HASH;

  constructor(config: AuditLoggerConfig = {}) {
    this.#config = config;
  }

  /** Append one record. Returns `undefined` when auditing is disabled. */
  append(input: AuditAppendInput): AuditEntry | undefined {
    if (this.#config.enabled === false) return undefined;

    const seq = this.#seq + 1;
    const body = {
      seq,
      timestamp: new Date().toISOString(),
      sessionId: input.sessionId,
      tool: input.tool,
      decision: input.decision,
      ...(input.blockedBy ? { blockedBy: input.blockedBy } : {}),
      ...(input.reason ? { reason: input.reason } : {}),
      sanitizedInputs: input.sanitizedInputs,
      inputRedactions: input.inputRedactions ?? 0,
      outputRedactions: input.outputRedactions ?? 0,
      injectionSanitized: input.injectionSanitized ?? 0,
      executionTimeMs: Number(input.executionTimeMs.toFixed(4)),
      inspectionMs: Number((input.inspectionMs ?? 0).toFixed(4)),
      tokensSaved: input.tokensSaved ?? 0,
      findings: input.findings ?? [],
      prevHash: this.#prevHash,
    };

    const hash = this.sign(body);
    const entry = Object.freeze({ ...body, hash }) as AuditEntry;

    this.#seq = seq;
    this.#prevHash = hash;
    this.#entries.push(entry);
    this.#trim();
    this.#config.sink?.(entry);

    return entry;
  }

  /** Deterministic digest of a record body (public so `verify()` can reuse it). */
  sign(body: Record<string, unknown>): string {
    const canonical = stableStringify(body);
    if (this.#config.hmacKey) {
      return createHmac('sha256', this.#config.hmacKey).update(canonical).digest('hex');
    }
    return createHash('sha256').update(canonical).digest('hex');
  }

  /** The trail, oldest first (a copy; records themselves are frozen). */
  trail(): AuditEntry[] {
    return [...this.#entries];
  }

  /** Append-only JSON Lines export — safe to `>> audit.jsonl`. */
  toJSONL(): string {
    return this.#entries.map((entry) => JSON.stringify(entry)).join('\n');
  }

  /** Decision histogram, e.g. `{ ALLOWED: 7, LOOP_BLOCKED: 1 }`. */
  summary(): Partial<Record<GateDecision, number>> {
    const counts: Partial<Record<GateDecision, number>> = {};
    for (const entry of this.#entries) {
      counts[entry.decision] = (counts[entry.decision] ?? 0) + 1;
    }
    return counts;
  }

  /** Recompute the whole chain. Trimming keeps this valid (it starts from `entries[0]`). */
  verify(): AuditVerifyResult {
    const entries = this.#entries;
    const first = entries[0];
    if (!first) return { ok: true, checked: 0 };

    let prevHash = first.prevHash;
    let expectedSeq = first.seq;

    for (const entry of entries) {
      if (entry.seq !== expectedSeq || entry.prevHash !== prevHash) {
        return { ok: false, checked: expectedSeq - first.seq, brokenAt: entry.seq };
      }
      const { hash, ...body } = entry;
      if (this.sign(body) !== hash) {
        return { ok: false, checked: expectedSeq - first.seq, brokenAt: entry.seq };
      }
      prevHash = hash;
      expectedSeq += 1;
    }

    return { ok: true, checked: entries.length };
  }

  get size(): number {
    return this.#entries.length;
  }

  get lastHash(): string {
    return this.#prevHash;
  }

  /** Test-only: start a brand new trail. */
  reset(): void {
    this.#entries = [];
    this.#seq = 0;
    this.#prevHash = GENESIS_HASH;
  }

  #trim(): void {
    const max = this.#config.maxEntries ?? 10_000;
    if (max > 0 && this.#entries.length > max) {
      this.#entries = this.#entries.slice(this.#entries.length - max);
    }
  }
}
