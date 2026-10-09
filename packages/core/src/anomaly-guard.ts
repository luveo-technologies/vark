/**
 * Stateful Agent Loop & Anomaly Guard.
 *
 * Holds a per-session execution window so the runtime can refuse runaway
 * agents instead of watching them spin:
 *
 *  - **Loop detection** — the same `tool + args` fingerprint may only be used
 *    `maxIdenticalCalls` times (default 3) per session; the 4th is refused.
 *  - **Velocity limit** — more than `maxCallsPerMinute` calls (default 30) in a
 *    sliding `windowMs` window, a `maxTotalCalls` lifetime budget, or a
 *    `maxSessionTokens` token budget **halts the session**: every later call
 *    is refused with `VELOCITY_EXCEEDED` / `BUDGET_EXCEEDED` instead of being
 *    re-evaluated.
 *
 * The mission calls this "killing the process"; vark refuses to call
 * `process.exit()` because a security guard must not crash its host. Halting
 * the session is the safe equivalent — the agent can no longer make progress,
 * while the operator keeps a live process and a readable audit trail.
 *
 * Session state lives behind a pluggable {@link StateStore}: the default
 * `MemoryStateStore` is today's single-process behaviour, while a shared
 * store (e.g. `RedisStateStore`) makes the limits hold across N replicas of
 * the same deployment. All mutating operations are optimistic
 * compare-and-swap with bounded reload-and-retry; if the store itself
 * fails, the guard throws and the runtime refuses the call
 * (`EXECUTION_ERROR`) — a broken state store fails closed, never open.
 */

import { stableStringify } from './audit-logger.js';
import { estimateTokens } from './compressor.js';
import { MemoryStateStore } from './state-store.js';
import type { SessionRecord, StateStore } from './state-store.js';
import type { AnomalyGuardConfig } from './types.js';

const DEFAULTS = {
  maxIdenticalCalls: 3,
  maxCallsPerMinute: 30,
  windowMs: 60_000,
  maxTotalCalls: 1_000,
  maxSessionTokens: 250_000,
  maxSessions: 1_000,
} as const;

/** Reload-and-retry budget for compare-and-swap conflicts before failing closed. */
const CAS_RETRIES = 8;

export interface AnomalySessionStats {
  sessionId: string;
  totalCalls: number;
  callsInWindow: number;
  /** Uses of the proposed fingerprint (`check`/`record`) or of the most recent one (`stats`). */
  identicalCalls: number;
  tokens: number;
  halted: boolean;
  haltReason: string;
  /** Administratively locked via `freeze()`. Refuses everything until reset. */
  frozen: boolean;
  frozenReason: string;
}

export interface AnomalyVerdict {
  safe: boolean;
  reason?: string;
  /**
   * Which check refused the call. Set on every refusal; undefined when safe.
   * - `'loop'` → identical-call limit hit (refused, session stays open)
   * - `'velocity'` → calls-per-minute exceeded (session halted)
   * - `'budget'` → lifetime call or token budget exhausted (session halted)
   * - `'frozen'` → session administratively locked (stays locked)
   */
  cause?: AnomalyCause;
  stats: AnomalySessionStats;
}

/** Which anomaly check refused a call. */
export type AnomalyCause = 'loop' | 'velocity' | 'budget' | 'frozen';

/** `tool` + canonical arguments — the identity of "the same call". */
export function callFingerprint(toolName: string, args: unknown): string {
  return `${toolName}(${stableStringify(args)})`;
}

export class AnomalyGuard {
  readonly maxIdenticalCalls: number;
  readonly maxCallsPerMinute: number;
  readonly windowMs: number;
  readonly maxTotalCalls: number;
  readonly maxSessionTokens: number;
  readonly maxSessions: number;
  readonly sessionTTLMs: number;
  readonly freezeOnInjectionBlock: boolean;
  readonly enabled: boolean;
  /** Where per-session state lives (memory by default, pluggable/shared). */
  readonly store: StateStore;

  constructor(config: AnomalyGuardConfig = {}) {
    this.maxIdenticalCalls = config.maxIdenticalCalls ?? DEFAULTS.maxIdenticalCalls;
    this.maxCallsPerMinute = config.maxCallsPerMinute ?? DEFAULTS.maxCallsPerMinute;
    this.windowMs = config.windowMs ?? DEFAULTS.windowMs;
    this.maxTotalCalls = config.maxTotalCalls ?? DEFAULTS.maxTotalCalls;
    this.maxSessionTokens = config.maxSessionTokens ?? DEFAULTS.maxSessionTokens;
    this.maxSessions = config.maxSessions ?? DEFAULTS.maxSessions;
    this.sessionTTLMs = config.sessionTTLMs ?? 0;
    this.freezeOnInjectionBlock = config.freezeOnInjectionBlock ?? false;
    this.enabled = config.enabled !== false;
    this.store = config.store ?? new MemoryStateStore();
  }

  /**
   * Evaluate a call against the session window **without** consuming a slot.
   * Used by the dry-run `runtime.check()`.
   */
  async check(sessionId: string, toolName: string, args: unknown): Promise<AnomalyVerdict> {
    const loaded = await this.#loadOrCreate(sessionId);
    return this.#evaluate(loaded.record, toolName, args, false);
  }

  /**
   * Evaluate and then always account for the attempt (even when refused), so
   * an attacker cannot reset a velocity limit by making blocked calls.
   */
  async record(sessionId: string, toolName: string, args: unknown): Promise<AnomalyVerdict> {
    for (let attempt = 0; ; attempt++) {
      const loaded = await this.#loadOrCreate(sessionId);
      const verdict = this.#evaluate(loaded.record, toolName, args, true);
      const created = loaded.version === undefined;
      const saved = await this.store.save(sessionId, loaded.record, loaded.version);
      if (saved) {
        if (created) await this.store.evictOldest?.(this.maxSessions);
        return verdict;
      }
      if (attempt >= CAS_RETRIES) {
        throw new Error(
          `anomaly guard: session "${sessionId}" state contention after ${CAS_RETRIES + 1} attempts — failing closed`,
        );
      }
      // Conflict: another instance updated the session. Reload and
      // re-evaluate against its state so no accounting is lost.
    }
  }

  /** Charge output tokens against the session budget (called after execution). */
  async addUsage(sessionId: string, tokens: number): Promise<void> {
    await this.#mutate(sessionId, (session) => {
      session.tokens += Math.max(0, tokens);
    });
  }

  async stats(sessionId: string): Promise<AnomalySessionStats | undefined> {
    const loaded = await this.store.load(sessionId);
    if (!loaded) return undefined;
    const last = loaded.record.calls[loaded.record.calls.length - 1];
    const fingerprint = last?.fingerprint ?? '';
    const uses = fingerprint ? (loaded.record.identical[fingerprint] ?? 0) : 0;
    return this.#snapshot(loaded.record, fingerprint, uses);
  }

  async sessions(): Promise<string[]> {
    return this.store.list();
  }

  /** Reset one session (or every session when `sessionId` is omitted). Also unfreezes. */
  async reset(sessionId?: string): Promise<void> {
    if (sessionId === undefined) await this.store.clear();
    else await this.store.delete(sessionId);
  }

  /**
   * Administratively lock a session: every later call is refused with cause
   * `'frozen'` until `reset()` clears it. Returns false when the session
   * does not exist (nothing is created).
   */
  async freeze(sessionId: string, reason = 'session frozen by operator'): Promise<boolean> {
    return this.#mutate(sessionId, (session) => {
      session.frozen = true;
      session.frozenReason = reason;
      session.lastSeen = Date.now();
    });
  }

  /** Lift a freeze without wiping counters. Returns false when not frozen. */
  async unfreeze(sessionId: string): Promise<boolean> {
    const loaded = await this.store.load(sessionId);
    if (!loaded || !loaded.record.frozen) return false;
    loaded.record.frozen = false;
    loaded.record.frozenReason = '';
    loaded.record.lastSeen = Date.now();
    await this.#saveLoaded(sessionId, loaded);
    return true;
  }

  /**
   * Drop idle sessions older than `sessionTTLMs`. Halted and frozen sessions
   * are always retained — evicting them would silently resurrect a stopped
   * agent. Returns the number of sessions evicted. No-op when TTL is off.
   */
  async sweepExpired(now: number = Date.now()): Promise<number> {
    if (this.sessionTTLMs <= 0) return 0;
    let evicted = 0;
    for (const id of await this.store.list()) {
      const loaded = await this.store.load(id);
      if (!loaded) continue;
      if (loaded.record.halted || loaded.record.frozen) continue;
      if (now - loaded.record.lastSeen > this.sessionTTLMs) {
        await this.store.delete(id);
        evicted += 1;
      }
    }
    return evicted;
  }

  /** Load (or seed a transient record for) a session. Transient = not yet saved. */
  async #loadOrCreate(id: string): Promise<{ record: SessionRecord; version: number | undefined }> {
    const loaded = await this.store.load(id);
    if (loaded) {
      loaded.record.lastSeen = Date.now();
      return loaded;
    }
    return { record: this.#seed(id, Date.now()), version: undefined };
  }

  #seed(id: string, now: number): SessionRecord {
    return {
      id,
      createdAt: now,
      lastSeen: now,
      totalCalls: 0,
      tokens: 0,
      halted: false,
      haltReason: '',
      haltCause: '',
      frozen: false,
      frozenReason: '',
      calls: [],
      identical: {},
    };
  }

  async #evaluate(
    session: SessionRecord,
    toolName: string,
    args: unknown,
    consume: boolean,
  ): Promise<AnomalyVerdict> {
    const fingerprint = callFingerprint(toolName, args);
    const tokenCost = estimateTokens(fingerprint);
    const identicalBefore = session.identical[fingerprint] ?? 0;

    const refuse = (reason: string, halt = false, cause: AnomalyCause = 'loop'): AnomalyVerdict => {
      if (halt && !session.halted) {
        session.halted = true;
        session.haltReason = reason;
        session.haltCause = cause;
      }
      // Frozen sessions never consume: a lock must not grow counters.
      if (consume && !session.halted && !session.frozen) this.#commit(session, fingerprint, tokenCost);
      return { safe: false, reason, cause, stats: this.#snapshot(session, fingerprint, identicalBefore) };
    };

    if (!this.enabled) {
      if (consume) this.#commit(session, fingerprint, tokenCost);
      return { safe: true, stats: this.#snapshot(session, fingerprint, identicalBefore) };
    }

    if (session.frozen) {
      return refuse(`session "${session.id}" is frozen: ${session.frozenReason}`, false, 'frozen');
    }

    if (session.halted) {
      const cause: AnomalyCause = session.haltCause === '' ? 'loop' : session.haltCause;
      return refuse(`session "${session.id}" is halted: ${session.haltReason}`, false, cause);
    }

    const callsInWindow = this.#pruneWindow(session);
    if (callsInWindow >= this.maxCallsPerMinute) {
      return refuse(
        `velocity limit exceeded: ${callsInWindow} calls in ${this.windowMs}ms ` +
          `(maxCallsPerMinute=${this.maxCallsPerMinute})`,
        true,
        'velocity',
      );
    }

    if (session.totalCalls + 1 > this.maxTotalCalls) {
      return refuse(
        `session call budget exhausted: ${session.totalCalls}/${this.maxTotalCalls} calls`,
        true,
        'budget',
      );
    }

    if (session.tokens + tokenCost > this.maxSessionTokens) {
      return refuse(
        `session token budget exhausted: ${session.tokens}/${this.maxSessionTokens} tokens`,
        true,
        'budget',
      );
    }

    if (identicalBefore >= this.maxIdenticalCalls) {
      return refuse(
        `infinite loop detected: call #${identicalBefore + 1} repeats identical tool+arguments ` +
          `(maxIdenticalCalls=${this.maxIdenticalCalls} per session, "${session.id}") ` +
          `fingerprint ${fingerprint.slice(0, 96)}`,
        false,
        'loop',
      );
    }

    if (consume) this.#commit(session, fingerprint, tokenCost);
    return { safe: true, stats: this.#snapshot(session, fingerprint, identicalBefore + (consume ? 1 : 0)) };
  }

  /**
   * Mutate an existing session with CAS retry. Returns false (without
   * creating anything) when the session does not exist.
   */
  async #mutate(id: string, mutate: (session: SessionRecord) => void): Promise<boolean> {
    for (let attempt = 0; attempt <= CAS_RETRIES; attempt++) {
      const loaded = await this.store.load(id);
      if (!loaded) return false;
      mutate(loaded.record);
      if (await this.#saveLoaded(id, loaded)) return true;
    }
    throw new Error(
      `anomaly guard: session "${id}" state contention after ${CAS_RETRIES + 1} attempts — failing closed`,
    );
  }

  async #saveLoaded(id: string, loaded: { record: SessionRecord; version: number }): Promise<boolean> {
    return this.store.save(id, loaded.record, loaded.version);
  }

  #commit(session: SessionRecord, fingerprint: string, tokenCost: number): void {
    const now = Date.now();
    session.totalCalls += 1;
    session.tokens += tokenCost;
    session.calls.push({ at: now, fingerprint });
    session.identical[fingerprint] = (session.identical[fingerprint] ?? 0) + 1;
    session.lastSeen = now;
  }

  #pruneWindow(session: SessionRecord): number {
    const cutoff = Date.now() - this.windowMs;
    while (session.calls.length > 0 && (session.calls[0]?.at ?? 0) < cutoff) session.calls.shift();
    return session.calls.length;
  }

  #snapshot(session: SessionRecord, fingerprint: string, identicalCalls: number): AnomalySessionStats {
    return {
      sessionId: session.id,
      totalCalls: session.totalCalls,
      callsInWindow: session.calls.length,
      identicalCalls: fingerprint ? identicalCalls : 0,
      tokens: session.tokens,
      halted: session.halted,
      haltReason: session.haltReason,
      frozen: session.frozen,
      frozenReason: session.frozenReason,
    };
  }
}
