/**
 * `vark bench` — circuit-breaker micro-benchmark with a live TUI table.
 *
 * Runs `benchmarkInspection` over a representative attack payload and
 * asserts the p99 sub-millisecond budget, printing avg/p50/p99/max plus a
 * verdict line CI can gate on (exit 1 when over budget).
 */

import { benchmarkInspection } from '../../circuit-breaker.js';
import { printBanner, printSummaryLine, table } from '../ux.js';
import pkg from 'picocolors';
const { green, red, dim, bold } = pkg;

export interface BenchOptions {
  iterations?: number;
}

export interface BenchReport {
  iterations: number;
  avgMs: number;
  p50Ms: number;
  p99Ms: number;
  maxMs: number;
  withinBudget: boolean;
}

const ATTACK_PAYLOAD = {
  command: 'cat file.txt; rm -rf /',
  path: '../../etc/passwd',
  note: 'routine backup task',
};

export function runBench(options: BenchOptions = {}): BenchReport {
  const iterations = options.iterations ?? 20_000;
  const bench = benchmarkInspection(ATTACK_PAYLOAD, undefined, iterations);
  return {
    iterations: bench.iterations,
    avgMs: bench.avgMs,
    p50Ms: bench.p50Ms,
    p99Ms: bench.p99Ms,
    maxMs: bench.maxMs,
    withinBudget: bench.p99Ms < 1,
  };
}

export function printBenchReport(report: BenchReport, elapsedMs?: number): void {
  printBanner(`bench  ·  ${report.iterations.toLocaleString('en-US')} inspections`);

  const cell = (v: number): string =>
    v < 1 ? green(v.toFixed(4)) : red(v.toFixed(4));
  console.log(
    table(
      [
        ['metric', 'ms', 'budget'],
        ['avg', cell(report.avgMs), dim('< 1.0000')],
        ['p50', cell(report.p50Ms), dim('< 1.0000')],
        ['p99', cell(report.p99Ms), dim('< 1.0000')],
        ['max', dim(report.maxMs.toFixed(4)), dim('GC/scheduler')],
      ],
      { head: true },
    ),
  );

  printSummaryLine(
    [
      report.withinBudget
        ? green('✔ p99 inside the sub-millisecond budget')
        : red('✘ p99 OVER budget'),
      dim(`payload: shell + traversal + benign note`),
    ],
    elapsedMs,
  );

  if (!report.withinBudget) process.exitCode = 1;
}

/** One-line assertion helper used by CI gates. */
export function assertBenchBudget(report: BenchReport): void {
  if (!report.withinBudget) {
    throw new Error(`benchmark budget exceeded: p99=${report.p99Ms.toFixed(4)}ms >= 1ms`);
  }
  console.log(bold(green(`✔ benchmark budget holds (p99=${report.p99Ms.toFixed(4)}ms)`)));
}
