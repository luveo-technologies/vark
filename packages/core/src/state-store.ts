/**
 * Pluggable session state store.
 *
 * The anomaly guard (loop / velocity / budget accounting, session freeze)
 * keeps its per-session state behind this interface. The default
 * {@link MemoryStateStore} preserves today's single-process behaviour; a
 * shared store (see `RedisStateStore`) makes the limits hold **across
 * instances** — N replicas of the same deployment share one session window
 * instead of each enforcing its own copy of the budget.
 *
 * Concurrency model: optimistic compare-and-swap. `load()` returns the
 * record plus an opaque `version`; `save()` persists only when the stored
 * version is unchanged (`undefined` expected version = create only when
 * absent). On conflict the guard reloads and re-evaluates, so decisions are
 * always made against fresh state and no instance silently overwrites
 * another's accounting.
 */

import type { AnomalyCause } from './anomaly-guard.js';

/** Serialized per-session guard state (JSON-safe; the unit of persistence). */
export interface SessionRecord {
  id: string;
  createdAt: number;
  lastSeen: number;
  totalCalls: number;
  tokens: number;
  halted: boolean;
  haltReason: string;
  /** Why the session was halted. Empty string while open. */
  haltCause: AnomalyCause | '';
  frozen: boolean;
  frozenReason: string;
  /** Velocity window: ms timestamps + fingerprints of accounted calls. */
  calls: Array<{ at: number; fingerprint: string }>;
  /** Identical-call counters per fingerprint. */
  identical: Record<string, number>;
}

export interface LoadedSession {
  record: SessionRecord;
  /** Opaque, store-owned version used for compare-and-swap. */
  version: number;
}

export interface StateStore {
  load(id: string): Promise<LoadedSession | undefined>;
  /**
   * Compare-and-swap write: persists `record` only when the stored version
   * still equals `expectedVersion` (`undefined` = create only when absent).
   * Returns `false` on conflict — the caller reloads and retries.
   */
  save(id: string, record: SessionRecord, expectedVersion: number | undefined): Promise<boolean>;
  delete(id: string): Promise<void>;
  clear(): Promise<void>;
  /** Every known session id. Required by `sessions()` / `sweepExpired()`. */
  list(): Promise<string[]>;
  /**
   * Optional eviction hook for capped in-memory stores: drop least-recently
   * used sessions until at most `max` remain (the just-created session is
   * newest, so it always survives). External stores size themselves with
   * TTLs instead and omit this.
   */
  evictOldest?(max: number): void | Promise<void>;
}

/** Default single-process store — insertion order doubles as LRU order. */
export class MemoryStateStore implements StateStore {
  readonly #entries = new Map<string, { record: SessionRecord; version: number }>();

  async load(id: string): Promise<LoadedSession | undefined> {
    const entry = this.#entries.get(id);
    if (!entry) return undefined;
    // Re-insert so Map insertion order doubles as least-recently-used order.
    this.#entries.delete(id);
    this.#entries.set(id, entry);
    // Hand out a clone: callers may retry a failed CAS, and a second caller
    // must never observe (or double-commit) another caller's in-flight edits.
    return { record: structuredClone(entry.record), version: entry.version };
  }

  async save(id: string, record: SessionRecord, expectedVersion: number | undefined): Promise<boolean> {
    const current = this.#entries.get(id);
    if (expectedVersion === undefined) {
      if (current) return false; // create-only-when-absent
      this.#entries.set(id, { record: structuredClone(record), version: 1 });
      return true;
    }
    if (!current || current.version !== expectedVersion) return false;
    current.record = structuredClone(record);
    current.version += 1;
    return true;
  }

  async delete(id: string): Promise<void> {
    this.#entries.delete(id);
  }

  async clear(): Promise<void> {
    this.#entries.clear();
  }

  async list(): Promise<string[]> {
    return [...this.#entries.keys()];
  }

  evictOldest(max: number): void {
    while (this.#entries.size > max) {
      const oldest = this.#entries.keys().next();
      if (oldest.done || oldest.value === undefined) break;
      this.#entries.delete(oldest.value);
    }
  }
}
