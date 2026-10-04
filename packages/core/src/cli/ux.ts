/**
 * Shared terminal UX for the vark CLI.
 *
 * Dependency-free: spinner, progress bar, banners and timing helpers.
 * Everything degrades gracefully when stdout is not a TTY (CI, pipes) —
 * no animation, no cursor rewriting, just plain lines.
 */

import pkg from 'picocolors';
const { cyan, dim, bold } = pkg;

/** True when we can safely animate (TTY, not CI, sane terminal). */
export function isAnimated(): boolean {
  return (
    Boolean(process.stdout.isTTY) &&
    !process.env['CI'] &&
    !process.env['NO_COLOR'] &&
    process.env['TERM'] !== 'dumb'
  );
}

const FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

export interface Spinner {
  /** Replace the label while running. */
  update(label: string): void;
  /** Stop with a success line. */
  succeed(message?: string): void;
  /** Stop with a failure line. */
  fail(message?: string): void;
  /** Stop silently (caller prints its own summary). */
  stop(): void;
}

/**
 * Start an animated spinner. In non-TTY mode it prints nothing until
 * `succeed()` / `fail()` (single line), keeping CI logs clean.
 */
export function spinner(label: string): Spinner {
  if (!isAnimated()) {
    return {
      update: () => undefined,
      succeed: (message?: string) => console.log(dim(`  ✓ ${message ?? label}`)),
      fail: (message?: string) => console.log(`  ✗ ${message ?? label}`),
      stop: () => undefined,
    };
  }

  let frame = 0;
  let current = label;
  const timer = setInterval(() => {
    process.stdout.write(`\r${cyan(FRAMES[frame % FRAMES.length])} ${current}`);
    frame += 1;
  }, 80);

  const clear = (): void => {
    clearInterval(timer);
    process.stdout.write('\r\x1b[K');
  };

  return {
    update: (next: string) => {
      current = next;
    },
    succeed: (message?: string) => {
      clear();
      console.log(`  ${cyan('✓')} ${message ?? current}`);
    },
    fail: (message?: string) => {
      clear();
      console.log(`  ✗ ${message ?? current}`);
    },
    stop: () => {
      clear();
    },
  };
}

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
