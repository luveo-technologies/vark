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
 *    is refused with `LOOP_BLOCKED` instead of being re-evaluated.
 *
 * The mission calls this "killing the process"; vark refuses to call
 * `process.exit()` because a security guard must not crash its host. Halting
 * the session is the safe equivalent — the agent can no longer make progress,
 * while the operator keeps a live process and a readable audit trail.
 */

import { stableStringify } from './audit-logger.js';
import { estimateTokens } from './compressor.js';
import type { AnomalyGuardConfig } from './types.js';

const DEFAULTS = {
  maxIdenticalCalls: 3,
  maxCallsPerMinute: 30,
  windowMs: 60_000,
  maxTotalCalls: 1_000,
  maxSessionTokens: 250_000,
  maxSessions: 1_000,
} as const;

export interface AnomalySessionStats {
  sessionId: string;
  totalCalls: number;
  callsInWindow: number;
  /** Uses of the proposed fingerprint (`check`/`record`) or of the most recent one (`stats`). */
  identicalCalls: number;
  tokens: number;
  halted: boolean;
  haltReason: string;
}

export interface AnomalyVerdict {
  safe: boolean;
  reason?: string;
  stats: AnomalySessionStats;
}

interface CallRecord {
  at: number;
  fingerprint: string;
}

interface SessionState {
  id: string;
  createdAt: number;
  lastSeen: number;
  totalCalls: number;
  tokens: number;
  halted: boolean;
  haltReason: string;
  calls: CallRecord[];
  identical: Map<string, number>;
}

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
  readonly enabled: boolean;

  readonly #sessions = new Map<string, SessionState>();

  constructor(config: AnomalyGuardConfig = {}) {
    this.maxIdenticalCalls = config.maxIdenticalCalls ?? DEFAULTS.maxIdenticalCalls;
    this.maxCallsPerMinute = config.maxCallsPerMinute ?? DEFAULTS.maxCallsPerMinute;
    this.windowMs = config.windowMs ?? DEFAULTS.windowMs;
    this.maxTotalCalls = config.maxTotalCalls ?? DEFAULTS.maxTotalCalls;
    this.maxSessionTokens = config.maxSessionTokens ?? DEFAULTS.maxSessionTokens;
    this.maxSessions = config.maxSessions ?? DEFAULTS.maxSessions;
    this.enabled = config.enabled !== false;
  }

  /**
   * Evaluate a call against the session window **without** consuming a slot.
   * Used by the dry-run `runtime.check()`.
   */
  check(sessionId: string, toolName: string, args: unknown): AnomalyVerdict {
    const session = this.#session(sessionId);
    return this.#evaluate(session, toolName, args, false);
  }

  /**
   * Evaluate and then always account for the attempt (even when refused), so
   * an attacker cannot reset a velocity limit by making blocked calls.
   */
  record(sessionId: string, toolName: string, args: unknown): AnomalyVerdict {
    const session = this.#session(sessionId);
    const verdict = this.#evaluate(session, toolName, args, true);
    return verdict;
  }

  /** Charge output tokens against the session budget (called after execution). */
  addUsage(sessionId: string, tokens: number): void {
    const session = this.#sessions.get(sessionId);
    if (session) session.tokens += Math.max(0, tokens);
  }

  stats(sessionId: string): AnomalySessionStats | undefined {
    const session = this.#sessions.get(sessionId);
    if (!session) return undefined;
    const last = session.calls[session.calls.length - 1];
    const fingerprint = last?.fingerprint ?? '';
    const uses = fingerprint ? (session.identical.get(fingerprint) ?? 0) : 0;
    return this.#snapshot(session, fingerprint, uses);
  }

  sessions(): string[] {
    return [...this.#sessions.keys()];
  }

  /** Reset one session (or every session when `sessionId` is omitted). */
  reset(sessionId?: string): void {
    if (sessionId === undefined) this.#sessions.clear();
    else this.#sessions.delete(sessionId);
  }

  #evaluate(
    session: SessionState,
    toolName: string,
    args: unknown,
    consume: boolean,
  ): AnomalyVerdict {
    const fingerprint = callFingerprint(toolName, args);
    const tokenCost = estimateTokens(fingerprint);
    const identicalBefore = session.identical.get(fingerprint) ?? 0;

    const refuse = (reason: string, halt = false): AnomalyVerdict => {
      if (halt && !session.halted) {
        session.halted = true;
        session.haltReason = reason;
      }
      if (consume && !session.halted) this.#commit(session, fingerprint, tokenCost);
      return { safe: false, reason, stats: this.#snapshot(session, fingerprint, identicalBefore) };
    };

    if (!this.enabled) {
      if (consume) this.#commit(session, fingerprint, tokenCost);
      return { safe: true, stats: this.#snapshot(session, fingerprint, identicalBefore) };
    }

    if (session.halted) {
      return refuse(`session "${session.id}" is halted: ${session.haltReason}`, false);
    }

    const callsInWindow = this.#pruneWindow(session);
    if (callsInWindow >= this.maxCallsPerMinute) {
      return refuse(
        `velocity limit exceeded: ${callsInWindow} calls in ${this.windowMs}ms ` +
          `(maxCallsPerMinute=${this.maxCallsPerMinute})`,
        true,
      );
    }

    if (session.totalCalls + 1 > this.maxTotalCalls) {
      return refuse(
        `session call budget exhausted: ${session.totalCalls}/${this.maxTotalCalls} calls`,
        true,
      );
    }

    if (session.tokens + tokenCost > this.maxSessionTokens) {
      return refuse(
        `session token budget exhausted: ${session.tokens}/${this.maxSessionTokens} tokens`,
        true,
      );
    }

    if (identicalBefore >= this.maxIdenticalCalls) {
      return refuse(
        `infinite loop detected: call #${identicalBefore + 1} repeats identical tool+arguments ` +
          `(maxIdenticalCalls=${this.maxIdenticalCalls} per session, "${session.id}") ` +
          `fingerprint ${fingerprint.slice(0, 96)}`,
      );
    }

    if (consume) this.#commit(session, fingerprint, tokenCost);
    return { safe: true, stats: this.#snapshot(session, fingerprint, identicalBefore + (consume ? 1 : 0)) };
  }

  #commit(session: SessionState, fingerprint: string, tokenCost: number): void {
    const now = Date.now();
    session.totalCalls += 1;
    session.tokens += tokenCost;
    session.calls.push({ at: now, fingerprint });
    session.identical.set(fingerprint, (session.identical.get(fingerprint) ?? 0) + 1);
    session.lastSeen = now;
  }

  #pruneWindow(session: SessionState): number {
    const cutoff = Date.now() - this.windowMs;
    while (session.calls.length > 0 && (session.calls[0]?.at ?? 0) < cutoff) session.calls.shift();
    return session.calls.length;
  }

  #snapshot(session: SessionState, fingerprint: string, identicalCalls: number): AnomalySessionStats {
    return {
      sessionId: session.id,
      totalCalls: session.totalCalls,
      callsInWindow: session.calls.length,
      identicalCalls: fingerprint ? identicalCalls : 0,
      tokens: session.tokens,
      halted: session.halted,
      haltReason: session.haltReason,
    };
  }

  #session(id: string): SessionState {
    const now = Date.now();
    const existing = this.#sessions.get(id);
    if (existing) {
      existing.lastSeen = now;
      // Re-insert so Map insertion order doubles as least-recently-used order.
      this.#sessions.delete(id);
      this.#sessions.set(id, existing);
      return existing;
    }

    const session: SessionState = {
      id,
      createdAt: now,
      lastSeen: now,
      totalCalls: 0,
      tokens: 0,
      halted: false,
      haltReason: '',
      calls: [],
      identical: new Map(),
    };
    this.#sessions.set(id, session);

    while (this.#sessions.size > this.maxSessions) {
      const oldest = this.#sessions.keys().next();
      if (oldest.done || oldest.value === undefined) break;
      this.#sessions.delete(oldest.value);
    }

    return session;
  }
}
