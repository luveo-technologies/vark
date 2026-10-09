/**
 * Structural policy diff — powers `vark policy diff` and drift detection.
 *
 * Walks two parsed policies and reports every leaf difference with a JSON
 * path, so CI (or a reviewer) can see exactly *what changed*: a tightened
 * budget, a new tool grant, a flipped test expectation. Array indices are
 * addressable (`tests[2].shouldAllow`), added/removed keys are reported
 * against their side, and value comparison is strict (`JSON`-normalized
 * primitives via `Object.is` semantics on the parsed side).
 *
 * The diff is deliberately policy-shaped, not a generic JSON merge library:
 * no patch/apply, no order-insensitive sets — just an honest ledger of
 * before → after.
 */

export interface PolicyDiffEntry {
  /** JSON path, e.g. `config.anomaly.maxIdenticalCalls` or `tools[1].name`. */
  path: string;
  kind: 'added' | 'removed' | 'changed';
  before?: unknown;
  after?: unknown;
}

const PRIMITIVES = new Set(['string', 'number', 'boolean']);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isPrimitive(value: unknown): boolean {
  return value === null || PRIMITIVES.has(typeof value);
}

/**
 * Diff `before` against `after`, entries sorted by path for stable output.
 * Identical documents produce an empty array.
 */
export function diffPolicy(before: unknown, after: unknown): PolicyDiffEntry[] {
  const entries: PolicyDiffEntry[] = [];

  const walk = (a: unknown, b: unknown, path: string): void => {
    if (Object.is(a, b)) return;

    if (Array.isArray(a) && Array.isArray(b)) {
      const shared = Math.min(a.length, b.length);
      for (let i = 0; i < shared; i += 1) walk(a[i], b[i], `${path}[${i}]`);
      for (let i = shared; i < a.length; i += 1) {
        entries.push({ path: `${path}[${i}]`, kind: 'removed', before: a[i] });
      }
      for (let i = shared; i < b.length; i += 1) {
        entries.push({ path: `${path}[${i}]`, kind: 'added', after: b[i] });
      }
      return;
    }

    if (isPlainObject(a) && isPlainObject(b)) {
      const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
      for (const key of [...keys].sort()) {
        const childPath = path ? `${path}.${key}` : key;
        const inA = Object.hasOwn(a, key);
        const inB = Object.hasOwn(b, key);
        if (!inA) entries.push({ path: childPath, kind: 'added', after: b[key] });
        else if (!inB) entries.push({ path: childPath, kind: 'removed', before: a[key] });
        else walk(a[key], b[key], childPath);
      }
      return;
    }

    if (isPrimitive(a) && isPrimitive(b)) {
      if (!Object.is(a, b)) {
        entries.push({ path, kind: 'changed', before: a, after: b });
      }
      return;
    }

    // Shape mismatch (object vs array vs primitive) — one changed entry.
    entries.push({ path, kind: 'changed', before: a, after: b });
  };

  walk(before, after, '');
  return entries.sort((x, y) => x.path.localeCompare(y.path));
}
