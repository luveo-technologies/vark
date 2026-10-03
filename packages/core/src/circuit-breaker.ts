/**
 * Circuit Breaker — sub-millisecond payload firewall.
 *
 * Every string that reaches a tool is tested against pre-compiled regular
 * expressions *before* the tool body runs. Inspection is allocation-light and
 * short-circuits on the first hit, keeping a full walk of a typical argument
 * payload well under 1 ms (see {@link benchmarkInspection}).
 */

import type { CircuitBreakerConfig, InspectionResult } from './types.js';

interface PayloadPattern {
  id: string;
  /** Human readable refusal shown to the agent/operator. */
  reason: string;
  regex: RegExp;
}

/** Characters and idioms that let a string escape into a shell. */
const SHELL_PATTERNS: readonly PayloadPattern[] = [
  { id: 'cmd-separator', reason: 'command separator (;)', regex: /;/ },
  { id: 'cmd-chain-and', reason: 'command chaining (&&)', regex: /&&/ },
  { id: 'pipe', reason: 'pipe operator (|)', regex: /\|/ },
  { id: 'cmd-substitution', reason: 'command substitution ($())', regex: /\$\(/ },
  { id: 'backtick-substitution', reason: 'command substitution (backticks)', regex: /`/ },
  { id: 'env-expansion', reason: 'environment expansion (${})', regex: /\$\{/ },
  { id: 'eval', reason: 'dynamic evaluation (eval)', regex: /\beval\s*\(/i },
  { id: 'rm-rf', reason: 'destructive command (rm -rf)', regex: /rm\s+-{1,2}[a-z]*(?:r[a-z]*f|f[a-z]*r)/i },
  { id: 'remote-pipe-shell', reason: 'remote payload piped into a shell', regex: /\b(?:curl|wget)\b[^|]*\|\s*(?:ba|z|k)?sh\b/i },
  { id: 'subshell', reason: 'subshell execution (bash -c)', regex: /\b(?:ba|z|k)?sh\s+-c\b/i },
  { id: 'redirect-dev-null', reason: 'output redirection to /dev/null', regex: />\s*\/dev\/null/i },
  { id: 'chmod-exec', reason: 'make-then-run (chmod +x)', regex: /\bchmod\s+(?:\+|-)\s*[a-z]*x/i },
];

/** Paths that never belong in an agent tool argument. */
const PATH_PATTERNS: readonly PayloadPattern[] = [
  { id: 'traversal', reason: 'path traversal (..)', regex: /(?:^|[\\/])\.\.(?=[\\/]|$)/ },
  { id: 'etc-passwd', reason: 'sensitive system file (/etc/passwd)', regex: /(?:^|[\\/])etc[\\/]passwd/i },
  { id: 'etc-shadow', reason: 'sensitive system file (/etc/shadow)', regex: /(?:^|[\\/])etc[\\/]shadow/i },
  { id: 'root-home', reason: 'sensitive system path (/root)', regex: /(?:^|[\\/])root(?=[\\/]|$)/i },
  { id: 'procfs', reason: 'sensitive system path (/proc)', regex: /(?:^|[\\/])proc(?=[\\/]|$)/i },
  { id: 'dotenv', reason: 'sensitive environment file (.env)', regex: /(?:^|[\\/])\.env(?![\w-])/ },
  { id: 'ssh-key', reason: 'sensitive key material (~/.ssh)', regex: /(?:^|[\\/])\.ssh(?=[\\/]|$)/i },
  { id: 'windows-dir', reason: 'sensitive system path (C:\\Windows)', regex: /^[a-z]:[\\/]windows(?=[\\/]|$)/i },
];

/** Guard against pathological nesting depth when walking arbitrary payloads. */
const MAX_DEPTH = 12;

function testPatterns(
  value: string,
  patterns: readonly PayloadPattern[],
  argName: string,
): InspectionResult {
  for (const pattern of patterns) {
    if (pattern.regex.test(value)) {
      return {
        safe: false,
        reason: `payload rejected in "${argName}": ${pattern.reason}`,
      };
    }
  }
  return { safe: true };
}

/**
 * Walk `args` and refuse anything that looks like shell injection, path
 * traversal, or that trips one of the configured custom rules.
 *
 * Custom rules receive the argument path (`command`, `filters.path`,
 * `tags[0]`, …) so they can be scoped to a single field.
 */
export function inspectPayload(
  args: unknown,
  config?: CircuitBreakerConfig,
  rootName = 'args',
): InspectionResult {
  const blockShell = config?.blockShellInjection ?? true;
  const blockPath = config?.blockPathTraversal ?? true;
  const customRules = config?.customRules ?? [];
  const shellPatterns = blockShell ? SHELL_PATTERNS : [];
  const pathPatterns = blockPath ? PATH_PATTERNS : [];

  const walk = (value: unknown, argName: string, depth: number): InspectionResult => {
    if (depth > MAX_DEPTH) return { safe: true };

    for (const rule of customRules) {
      const verdict = rule(argName, value);
      if (typeof verdict === 'string' && verdict.length > 0) {
        return { safe: false, reason: verdict };
      }
      if (verdict === true) {
        return { safe: false, reason: `custom rule rejected "${argName}"` };
      }
    }

    if (typeof value === 'string') {
      let result = testPatterns(value, shellPatterns, argName);
      if (result.safe) result = testPatterns(value, pathPatterns, argName);
      if (!result.safe) return result;
      return { safe: true };
    }

    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i += 1) {
        const result = walk(value[i], `${argName}[${i}]`, depth + 1);
        if (!result.safe) return result;
      }
      return { safe: true };
    }

    if (typeof value === 'object' && value !== null) {
      for (const [key, child] of Object.entries(value)) {
        const result = walk(child, depth === 0 ? key : `${argName}.${key}`, depth + 1);
        if (!result.safe) return result;
      }
    }

    return { safe: true };
  };

  return walk(args, rootName, 0);
}

/** Alias of {@link inspectPayload} for terse call sites. */
export const inspect = inspectPayload;

export interface InspectionBenchmark {
  iterations: number;
  avgMs: number;
  p50Ms: number;
  p99Ms: number;
  /** Worst single sample — includes GC / OS scheduler pauses. */
  maxMs: number;
  safe: boolean;
  reason?: string;
}

function percentile(sorted: number[], fraction: number): number {
  if (sorted.length === 0) return 0;
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(fraction * sorted.length) - 1));
  return sorted[index] ?? 0;
}

/**
 * Micro-benchmark used to prove the sub-millisecond budget. Runs `payload`
 * through {@link inspectPayload} `iterations` times after a warm-up pass and
 * reports the distribution (`avg` / `p50` / `p99`) plus the worst sample.
 */
export function benchmarkInspection(
  payload: unknown,
  config?: CircuitBreakerConfig,
  iterations = 10_000,
): InspectionBenchmark {
  // Warm-up so JIT compilation does not pollute the first measurement.
  for (let i = 0; i < 200; i += 1) inspectPayload(payload, config);

  const samples: number[] = new Array<number>(iterations);
  let result: InspectionResult = { safe: true };

  for (let i = 0; i < iterations; i += 1) {
    const start = performance.now();
    result = inspectPayload(payload, config);
    samples[i] = performance.now() - start;
  }

  const sorted = [...samples].sort((a, b) => a - b);
  const benchmark: InspectionBenchmark = {
    iterations,
    avgMs: samples.reduce((sum, sample) => sum + sample, 0) / iterations,
    p50Ms: percentile(sorted, 0.5),
    p99Ms: percentile(sorted, 0.99),
    maxMs: sorted[sorted.length - 1] ?? 0,
    safe: result.safe,
  };
  if (result.reason !== undefined) benchmark.reason = result.reason;
  return benchmark;
}
