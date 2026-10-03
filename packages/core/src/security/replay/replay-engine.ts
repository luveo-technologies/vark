/**
 * Deterministic Replay Engine
 *
 * Records tool execution context (mocked inputs, environmental state, time
 * seeds) to allow exact 1:1 deterministic replay for post-mortem forensics.
 * Captures the full execution context so incidents can be reproduced
 * precisely.
 */

export interface ReplayContext {
  /** Unique replay identifier. */
  replayId: string;
  /** Session that was replayed. */
  sessionId: string;
  /** Tool name. */
  tool: string;
  /** Tool arguments. */
  args: unknown;
  /** Tool result. */
  result: unknown;
  /** Execution time in ms. */
  executionTimeMs: number;
  /** Timestamp of the original execution. */
  timestamp: number;
  /** Time seed for deterministic Date.now() replay. */
  timeSeed: number;
  /** Environment variables snapshot (sanitized). */
  envSnapshot: Record<string, string>;
  /** Mocked function calls made during execution. */
  mockCalls: MockCall[];
  /** Random seed for deterministic Math.random() replay. */
  randomSeed: number;
}

export interface MockCall {
  /** Function name. */
  functionName: string;
  /** Arguments passed. */
  args: unknown[];
  /** Return value. */
  returnValue: unknown;
  /** Timestamp relative to execution start. */
  relativeTimeMs: number;
}

export interface ReplayConfig {
  /** Whether to capture environment variables. @default true */
  captureEnv?: boolean;
  /** Whether to capture mock calls. @default true */
  captureMocks?: boolean;
  /** Maximum number of replays to store. @default 1000 */
  maxReplays?: number;
  /** Custom random seed generator. */
  randomSeed?: () => number;
}

/**
 * Records and replays tool execution contexts for deterministic forensics.
 */
export class ReplayEngine {
  readonly #config: Required<ReplayConfig>;
  readonly #replays = new Map<string, ReplayContext>();
  readonly #sessionReplays = new Map<string, string[]>();
  #randomSeedCounter = 0;

  constructor(config: ReplayConfig = {}) {
    this.#config = {
      captureEnv: config.captureEnv ?? true,
      captureMocks: config.captureMocks ?? true,
      maxReplays: config.maxReplays ?? 1000,
      randomSeed: config.randomSeed ?? (() => {
        this.#randomSeedCounter += 1;
        return this.#randomSeedCounter * 1_000_003;
      }),
    };
  }

  /** Record an execution context for later replay. */
  record(context: Omit<ReplayContext, 'replayId' | 'timeSeed' | 'randomSeed'>): ReplayContext {
    const replayId = `replay_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
    const timeSeed = Date.now();
    const randomSeed = this.#config.randomSeed();

    const replay: ReplayContext = {
      ...context,
      replayId,
      timeSeed,
      randomSeed,
    };

    this.#replays.set(replayId, replay);

    // Track by session.
    const sessionIds = this.#sessionReplays.get(context.sessionId) ?? [];
    sessionIds.push(replayId);
    this.#sessionReplays.set(context.sessionId, sessionIds);

    // Enforce max replays limit.
    if (this.#replays.size > this.#config.maxReplays) {
      const oldest = this.#replays.keys().next().value;
      if (oldest) this.#replays.delete(oldest);
    }

    return replay;
  }

  /** Get a replay by ID. */
  getReplay(replayId: string): ReplayContext | undefined {
    return this.#replays.get(replayId);
  }

  /** Get all replays for a session. */
  getSessionReplays(sessionId: string): ReplayContext[] {
    const ids = this.#sessionReplays.get(sessionId) ?? [];
    return ids.map((id) => this.#replays.get(id)!).filter(Boolean);
  }

  /**
   * Replay an execution with deterministic time and random seeds.
   * Returns the replay context with seeded values.
   */
  prepareReplay(replayId: string): ReplayContext | undefined {
    const replay = this.#replays.get(replayId);
    if (!replay) return undefined;

    // Return a copy with deterministic seeds applied.
    return {
      ...replay,
      timeSeed: replay.timeSeed,
      randomSeed: replay.randomSeed,
    };
  }

  /** Delete a replay. */
  deleteReplay(replayId: string): boolean {
    const replay = this.#replays.get(replayId);
    if (!replay) return false;
    this.#replays.delete(replayId);
    const sessionIds = this.#sessionReplays.get(replay.sessionId);
    if (sessionIds) {
      const idx = sessionIds.indexOf(replayId);
      if (idx >= 0) sessionIds.splice(idx, 1);
    }
    return true;
  }

  /** Clear all replays. */
  clear(): void {
    this.#replays.clear();
    this.#sessionReplays.clear();
  }

  /** Clear replays for a session. */
  clearSession(sessionId: string): void {
    const ids = this.#sessionReplays.get(sessionId);
    if (ids) {
      for (const id of ids) this.#replays.delete(id);
      this.#sessionReplays.delete(sessionId);
    }
  }

  get replayCount(): number {
    return this.#replays.size;
  }

  get sessionCount(): number {
    return this.#sessionReplays.size;
  }
}

/**
 * Deterministic time source for replay. Returns the seeded time instead
 * of the current time during replay.
 */
export class DeterministicTimeSource {
  readonly #seed: number;
  readonly #startReal: number;

  constructor(seed: number) {
    this.#seed = seed;
    this.#startReal = Date.now();
  }

  /** Get the current time (seeded during replay). */
  now(): number {
    return this.#seed + (Date.now() - this.#startReal);
  }

  /** Get the seed value. */
  get seed(): number {
    return this.#seed;
  }
}

/**
 * Deterministic random source for replay. Returns seeded values instead
 * of truly random values during replay.
 */
export class DeterministicRandomSource {
  readonly #seed: number;
  #state: number;

  constructor(seed: number) {
    this.#seed = seed;
    this.#state = seed;
  }

  /** Get a random number between 0 and 1 (seeded during replay). */
  random(): number {
    // Linear congruential generator for deterministic randomness.
    this.#state = (this.#state * 1_103_515_245 + 12_345) & 0x7fff_ffff;
    return this.#state / 0x7fff_ffff;
  }

  /** Get the seed value. */
  get seed(): number {
    return this.#seed;
  }
}
