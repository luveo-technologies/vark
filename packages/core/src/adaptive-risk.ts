/**
 * Adaptive per-tool risk scoring (gate 1 adjunct / gate 4b escalation).
 *
 * Every tool starts from a **base score** (explicit `risk.tools` entry or
 * `risk.defaultScore`) and adapts from **observed outcomes**:
 *
 * - a gate refusal adds `blockPenalty` (capped at 100),
 * - a clean run subtracts `recoveryPerCleanRun`, floored at the base —
 *   history escalates, recovery only returns to the configured inherent
 *   risk,
 * - signals age out after `signalTtlMs`, so scrutiny relaxes when behaviour
 *   improves — the "adaptive" part.
 *
 * Tiers (`low` → `medium` → `high` → `critical`) come from the combined
 * score. When `risk.escalateTier` is configured (and a HITL gate exists),
 * a tool whose tier reaches the threshold pauses for approval even though
 * nobody mapped it in `hitl.tools` — risk-driven escalation on top of the
 * static mapping.
 */

export type RiskTier = 'low' | 'medium' | 'high' | 'critical';

export interface RiskSignal {
  at: number;
  /** Positive = penalty, negative = recovery. */
  delta: number;
  reason: string;
}

export interface RiskAssessment {
  tool: string;
  /** Combined score, 0–100. */
  score: number;
  tier: RiskTier;
  /** Score from configuration alone (no history). */
  base: number;
  /** Current net contribution of live signals. */
  penalty: number;
  /** Human-readable factors behind `penalty`. */
  reasons: string[];
}

export interface AdaptiveRiskConfig {
  /** Explicit per-tool base scores (0–100). */
  tools?: Record<string, number>;
  /** Base score for tools without an entry. @default 0 */
  defaultScore?: number;
  /** After this long, a signal stops counting. @default 300_000 (5 min) */
  signalTtlMs?: number;
  /** Penalty added per gate refusal. @default 25 */
  blockPenalty?: number;
  /** Score given back per clean run. @default 5 */
  recoveryPerCleanRun?: number;
  /** Tier cut points (score ≥ threshold). @default 25/50/75 */
  tierThresholds?: { medium: number; high: number; critical: number };
  /**
   * When set, tools at/above this tier pause for HITL approval even if
   * unmapped in `hitl.tools` (requires a `hitl` gate in the runtime).
   * @default unset (escalation off)
   */
  escalateTier?: RiskTier;
}

const TIER_ORDER: RiskTier[] = ['low', 'medium', 'high', 'critical'];

export function tierForScore(score: number, thresholds?: AdaptiveRiskConfig['tierThresholds']): RiskTier {
  const t = thresholds ?? { medium: 25, high: 50, critical: 75 };
  if (score >= t.critical) return 'critical';
  if (score >= t.high) return 'high';
  if (score >= t.medium) return 'medium';
  return 'low';
}

/** Is `tier` at or above `threshold`? */
export function tierAtLeast(tier: RiskTier, threshold: RiskTier): boolean {
  return TIER_ORDER.indexOf(tier) >= TIER_ORDER.indexOf(threshold);
}

export class AdaptiveRiskAssessor {
  readonly #config: Required<Omit<AdaptiveRiskConfig, 'tools' | 'escalateTier'>> & {
    tools: Record<string, number>;
    escalateTier?: RiskTier;
  };
  readonly #signals = new Map<string, RiskSignal[]>();

  constructor(config: AdaptiveRiskConfig = {}) {
    this.#config = {
      tools: config.tools ?? {},
      defaultScore: config.defaultScore ?? 0,
      signalTtlMs: config.signalTtlMs ?? 300_000,
      blockPenalty: config.blockPenalty ?? 25,
      recoveryPerCleanRun: config.recoveryPerCleanRun ?? 5,
      tierThresholds: config.tierThresholds ?? { medium: 25, high: 50, critical: 75 },
      escalateTier: config.escalateTier,
    };
  }

  get escalateTier(): RiskTier | undefined {
    return this.#config.escalateTier;
  }

  /** Base score for a tool from configuration (no history). */
  baseScore(tool: string): number {
    const configured = this.#config.tools[tool];
    return configured ?? this.#config.defaultScore;
  }

  /** Record a gate refusal against the tool (positive penalty). */
  recordBlock(tool: string, reason: string): void {
    this.#push(tool, {
      at: Date.now(),
      delta: this.#config.blockPenalty,
      reason: `refused: ${reason}`,
    });
  }

  /** Record a completed clean run (recovery toward the base). */
  recordCleanRun(tool: string): void {
    this.#push(tool, {
      at: Date.now(),
      delta: -this.#config.recoveryPerCleanRun,
      reason: 'clean run',
    });
  }

  /**
   * Current assessment: base + live (unexpired) signals, clamped to
   * 0–100 and floored at the base — history can only escalate a tool
   * above its configured inherent risk; clean runs walk it back down to
   * (never below) the base.
   */
  assess(tool: string): RiskAssessment {
    const base = this.baseScore(tool);
    const signals = this.#live(tool);
    const combined = base + signals.reduce((sum, s) => sum + s.delta, 0);
    const score = Math.min(100, Math.max(base, combined));
    const penalty = score - base;
    return {
      tool,
      score,
      tier: tierForScore(score, this.#config.tierThresholds),
      base,
      penalty,
      reasons: signals.map((s) => s.reason),
    };
  }

  /** Drop signals for one tool (or all tools when omitted). */
  reset(tool?: string): void {
    if (tool === undefined) this.#signals.clear();
    else this.#signals.delete(tool);
  }

  #push(tool: string, signal: RiskSignal): void {
    const list = this.#signals.get(tool) ?? [];
    list.push(signal);
    this.#signals.set(tool, list);
  }

  /** Live signals (TTL-pruned, in insertion order). */
  #live(tool: string): RiskSignal[] {
    const list = this.#signals.get(tool);
    if (!list) return [];
    const cutoff = Date.now() - this.#config.signalTtlMs;
    const live = list.filter((s) => s.at >= cutoff);
    if (live.length === list.length) return live;
    this.#signals.set(tool, live);
    return live;
  }
}
