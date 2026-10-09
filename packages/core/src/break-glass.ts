/**
 * Break-glass mode — a deliberate, time-boxed, fully audited operator
 * override for when Vark's *operational* gates are what's taking production
 * down (approver rota offline, a session frozen by a bad config, an
 * incident where a human has decided the agent must proceed).
 *
 * Scopes:
 * - `hitl`    — skip approval waits (gate 4b) for mapped/escalated tools.
 * - `anomaly` — ignore session freeze/halt/loop refusals (gate 1); counters
 *   keep recording, so the trail still shows what the session did.
 *
 * **Detection gates are never bypassed**: capability sandbox, circuit
 * breaker, schema validation, DLP, injection filter, execution timeout and
 * audit durability all stay armed. Break-glass opens the doors between
 * humans and the system; it does not blind the system to attackers.
 *
 * Every transition (`enabled`, `disabled`, `expired`) is emitted through
 * `onEvent` — the runtime appends each one to the hash-chained audit trail —
 * and every call executed under the override carries a `BREAK_GLASS` finding.
 */

export type BreakGlassScope = 'hitl' | 'anomaly';

export type BreakGlassEventType = 'enabled' | 'disabled' | 'expired';

export interface BreakGlassEnableOptions {
  /** Why the override is happening — recorded verbatim. */
  reason: string;
  /** Who initiated it (operator id). */
  by: string;
  /** How long it lasts, ms. @default defaultDurationMs, capped at maxDurationMs. */
  durationMs?: number;
  /** Operational gates to bypass. @default ['hitl', 'anomaly'] */
  scopes?: BreakGlassScope[];
}

export interface BreakGlassSession {
  id: string;
  reason: string;
  by: string;
  scopes: BreakGlassScope[];
  enabledAt: number;
  expiresAt: number;
}

export interface BreakGlassStatus {
  active: boolean;
  session?: BreakGlassSession;
  /** Milliseconds until expiry (0 when inactive). */
  remainingMs: number;
}

export interface BreakGlassEvent {
  type: BreakGlassEventType;
  session: BreakGlassSession;
}

export interface BreakGlassConfig {
  /** Longest single override. @default 900_000 (15 min) */
  maxDurationMs?: number;
  /** Duration when none is given. @default 300_000 (5 min) */
  defaultDurationMs?: number;
  /** Receives every transition (runtime wires this into the audit trail). */
  onEvent?: (event: BreakGlassEvent) => void;
}

export class BreakGlassManager {
  readonly #maxDurationMs: number;
  readonly #defaultDurationMs: number;
  readonly #onEvent?: (event: BreakGlassEvent) => void;
  #session: BreakGlassSession | undefined;
  #timer: ReturnType<typeof setTimeout> | undefined;

  constructor(config: BreakGlassConfig = {}) {
    this.#maxDurationMs = config.maxDurationMs ?? 900_000;
    this.#defaultDurationMs = config.defaultDurationMs ?? 300_000;
    this.#onEvent = config.onEvent;
  }

  /**
   * Activate the override. Throws when one is already active (disable the
   * old one first — each activation is its own audited decision) and when
   * `reason`/`by` are missing.
   */
  enable(options: BreakGlassEnableOptions): BreakGlassSession {
    if (this.#session) {
      throw new Error(
        `break-glass is already active (${this.#session.id} by ${this.#session.by}) — disable it before re-enabling`,
      );
    }
    if (!options.reason?.trim()) throw new Error('break-glass requires a reason (audited)');
    if (!options.by?.trim()) throw new Error('break-glass requires `by` (who initiated it — audited)');

    const scopes = options.scopes?.length ? [...new Set(options.scopes)] : (['hitl', 'anomaly'] as BreakGlassScope[]);
    for (const scope of scopes) {
      if (scope !== 'hitl' && scope !== 'anomaly') {
        throw new Error(`unknown break-glass scope "${scope}" — expected "hitl" or "anomaly"`);
      }
    }

    const now = Date.now();
    const requested = options.durationMs ?? this.#defaultDurationMs;
    if (!Number.isFinite(requested) || requested <= 0) {
      throw new Error(`break-glass durationMs must be a positive number (got ${String(options.durationMs)})`);
    }
    const durationMs = Math.min(requested, this.#maxDurationMs);

    const session: BreakGlassSession = {
      id: `bg_${now}_${Math.random().toString(36).slice(2, 8)}`,
      reason: options.reason,
      by: options.by,
      scopes,
      enabledAt: now,
      expiresAt: now + durationMs,
    };
    this.#session = session;

    this.#timer = setTimeout(() => {
      if (this.#session?.id !== session.id) return;
      this.#session = undefined;
      this.#timer = undefined;
      this.#onEvent?.({ type: 'expired', session });
    }, durationMs);
    // Never keep the process alive just to expire an override.
    this.#timer.unref?.();

    this.#onEvent?.({ type: 'enabled', session });
    return session;
  }

  /** End the override early. Returns false when none is active. */
  disable(): BreakGlassSession | undefined {
    if (!this.#session) return undefined;
    const session = this.#session;
    this.#session = undefined;
    if (this.#timer !== undefined) {
      clearTimeout(this.#timer);
      this.#timer = undefined;
    }
    this.#onEvent?.({ type: 'disabled', session });
    return session;
  }

  /** Is an override active, and does it cover this scope? */
  isBypassing(scope: BreakGlassScope): boolean {
    return this.#session !== undefined && this.#session.scopes.includes(scope);
  }

  get active(): boolean {
    return this.#session !== undefined;
  }

  status(): BreakGlassStatus {
    if (!this.#session) return { active: false, remainingMs: 0 };
    return {
      active: true,
      session: this.#session,
      remainingMs: Math.max(0, this.#session.expiresAt - Date.now()),
    };
  }
}
