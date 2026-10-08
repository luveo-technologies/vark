/**
 * Shared terminal output helpers for the vark CLI.
 *
 * Plain, static, dependency-free formatting: progress bars, banners, tables
 * and timing helpers. No animation, no screen clearing, no cursor rewriting —
 * every command prints straight lines that work identically on a TTY and in CI.
 */

import pkg from 'picocolors';
const { dim, bold, green, red, yellow } = pkg;

/** `██████░░░░ 3/5 (60%)` */
export function progressBar(done: number, total: number, width = 20): string {
  const ratio = total <= 0 ? 0 : Math.min(1, Math.max(0, done / total));
  const filled = Math.round(ratio * width);
  const bar = '█'.repeat(filled) + '░'.repeat(width - filled);
  const pct = `${Math.round(ratio * 100)}%`;
  return `${bar} ${done}/${total} (${pct})`;
}

/** Human elapsed time: `342ms` / `1.24s`. */
export function formatElapsed(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

/** Compact vark banner printed above every command's output. */
export function printBanner(subtitle: string): void {
  console.log(bold('🛡  vark') + dim(`  ·  ${subtitle}`));
  console.log(dim('─'.repeat(60)));
}

/** Boxed summary footer: `✔ 4 passed · ✘ 1 failed · 0.42s`. */
export function printSummaryLine(parts: string[], elapsedMs?: number): void {
  const suffix = elapsedMs !== undefined ? dim(`  ·  ${formatElapsed(elapsedMs)}`) : '';
  console.log(`\n${parts.join('  ·  ')}${suffix}`);
}

/**
 * Chain visualisation: one dot per record, capped for huge trails.
 * `●●●●●✗○○○  (✗ = first broken link)`
 */
export function chainDots(
  total: number,
  brokenAtSeq?: number,
  maxDots = 60,
): string {
  if (total <= 0) return dim('(empty trail)');
  const dots: string[] = [];
  const step = total > maxDots ? total / maxDots : 1;
  for (let i = 0; i < Math.min(total, maxDots); i += 1) {
    const seq = Math.floor(i * step) + 1;
    if (brokenAtSeq !== undefined && seq >= brokenAtSeq) {
      dots.push('✗');
      break;
    }
    dots.push('●');
  }
  if (total > maxDots) dots.push(dim(`…${total}`));
  return dots.join('');
}

// ── gate pipeline view ──────────────────────────────────────────────────────

export type GateStatus = 'pass' | 'fail' | 'skip' | 'pending';

export interface GateState {
  /** Short gate id, e.g. `breaker`, `in-dlp`. */
  id: string;
  /** Human label, e.g. `Circuit Breaker`. */
  label: string;
  status: GateStatus;
  /** One-line detail shown under the gate. */
  detail?: string;
  /** Marker shown on failed gates. @default '← BLOCKED' */
  marker?: string;
}

function gateGlyph(status: GateStatus): string {
  switch (status) {
    case 'pass':
      return green('●');
    case 'fail':
      return red('✖');
    case 'skip':
      return dim('○');
    case 'pending':
      return dim('◌');
  }
}

/**
 * Render the 8-gate pipeline as it fires:
 *
 *   ● anomaly      ok · 3 calls in window
 *   ● sandbox      path ./a.json inside ./workspace/*
 *   ✖ breaker      command separator (;)      ← BLOCKED
 *   ○ in-dlp       skipped (short-circuit)
 *   …
 */
export function renderPipeline(states: GateState[]): string {
  const rows: string[] = [];
  for (let i = 0; i < states.length; i += 1) {
    const gate = states[i]!;
    const connector = i === states.length - 1 ? ' ' : '│';
    const head = `  ${gateGlyph(gate.status)} ${gate.label.padEnd(16)}`;
    const detail = gate.detail ? dim(gate.detail) : '';
    const marker = gate.status === 'fail' ? red(`  ${gate.marker ?? '← BLOCKED'}`) : '';
    rows.push(`${head} ${detail}${marker}`);
    if (i < states.length - 1) rows.push(dim(`  ${connector}`));
  }
  return rows.join('\n');
}

/** Simple column table: `table([['a','b'],…])` with auto widths. */
export function table(
  rows: Array<Array<string | number>>,
  options: { gap?: number; head?: boolean } = {},
): string {
  if (rows.length === 0) return '';
  const gap = ' '.repeat(options.gap ?? 3);
  const widths: number[] = [];
  for (const row of rows) {
    row.forEach((cell, i) => {
      // eslint-disable-next-line no-control-regex -- ANSI SGR sequences are control chars by definition
      const len = String(cell).replace(/\u001b\[[0-9;]*m/g, '').length;
      widths[i] = Math.max(widths[i] ?? 0, len);
    });
  }
  const lines = rows.map((row, r) => {
    const line = row
      .map((cell, i) => {
        const raw = String(cell);
        // eslint-disable-next-line no-control-regex -- ANSI SGR sequences are control chars by definition
        const plain = raw.replace(/\u001b\[[0-9;]*m/g, '');
        return raw + ' '.repeat(Math.max(0, (widths[i] ?? 0) - plain.length));
      })
      .join(gap);
    return options.head && r === 0 ? bold(line) : line;
  });
  return lines.join('\n');
}

/** Horizontal histogram bar: `ALLOWED      ████████░░ 6`. */
export function histoBar(label: string, count: number, max: number, width = 12): string {
  const filled = max <= 0 ? 0 : Math.round((count / max) * width);
  return `${label.padEnd(18)} ${green('█'.repeat(filled))}${dim('░'.repeat(width - filled))} ${count}`;
}

/** Decision → colored chip. */
export function decisionChip(decision: string): string {
  if (decision === 'ALLOWED') return green('ALLOWED ');
  if (decision === 'LOOP_BLOCKED' || decision === 'TIMEOUT' || decision === 'VELOCITY_EXCEEDED' || decision === 'BUDGET_EXCEEDED') {
    return yellow(decision.padEnd(8));
  }
  return red(decision.padEnd(8));
}
