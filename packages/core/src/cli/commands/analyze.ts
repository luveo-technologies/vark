/**
 * `vark canary|pii|entropy|compress` — single-shot security analyzers.
 *
 * Each command exercises a real engine module against a file and renders an
 * engaging report: honeytoken trap demo, PII anonymization preview, entropy
 * + reflection verdict, and CTP compression savings.
 */

import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { CanaryManager } from '../../security/canary/honeytoken.js';
import { createPiiAnonymizer } from '../../security/pii/pii-anonymizer.js';
import { scanEntropyAndReflection } from '../../security/reflection/entropy-scanner.js';
import { analyzeCompression } from '../../compressor.js';
import { printBanner, printSummaryLine, progressBar, table } from '../ux.js';
import pkg from 'picocolors';
const { green, red, yellow, dim, bold, cyan } = pkg;

async function readText(input: string): Promise<{ source: string; text: string }> {
  try {
    const path = resolve(input);
    return { source: path, text: await readFile(path, 'utf8') };
  } catch {
    return { source: '<arg>', text: input };
  }
}

// ── 1. canary demo ────────────────────────────────────────────────────────────

export function runCanaryDemo(): { seeded: number; detected: boolean; locked: boolean } {
  const canary = new CanaryManager({ tokensPerSession: 3 });
  const tokens = canary.seedSession('demo-session');

  // Simulate a tool output that embeds one honeytoken, then an agent
  // echoing it back into the next tool input (the classic exfil loop).
  const nextInput = `Use ${tokens[0]!.value} to authenticate`;
  const event = canary.scanInput('demo-session', nextInput);

  return {
    seeded: tokens.length,
    detected: event !== null,
    locked: canary.isSessionLocked('demo-session'),
  };
}

export function printCanaryDemo(result: { seeded: number; detected: boolean; locked: boolean }): void {
  printBanner('canary  ·  honeytoken trap demo');
  console.log(`  ${green('●')} seeded ${result.seeded} session-bound honeytokens into tool output`);
  console.log(`  ${green('●')} agent echoed a honeytoken back into the next input`);
  console.log(
    `  ${result.detected ? red('✖') : green('●')} echo ${result.detected ? 'DETECTED' : 'missed'} → session ${
      result.locked ? red('LOCKED') : green('open')
    }`,
  );
  printSummaryLine(
    result.detected && result.locked
      ? [green('✔ trap works — exfil loop halted')]
      : [red('✘ trap failed')],
  );
  if (!(result.detected && result.locked)) process.exitCode = 1;
}

// ── 2. pii ────────────────────────────────────────────────────────────────────

export async function runPiiScan(input: string): Promise<{ matches: number; preview: string }> {
  const { text } = await readText(input);
  const anonymizer = createPiiAnonymizer('cli');
  const result = anonymizer.anonymize(text);
  return { matches: result.matches.length, preview: result.anonymized.slice(0, 600) };
}

export function printPiiResult(
  source: string,
  result: { matches: number; preview: string },
  elapsedMs?: number,
): void {
  printBanner(`pii  ·  ${source}`);
  console.log(`  detected: ${result.matches > 0 ? yellow(String(result.matches)) : green('0')} PII spans`);
  if (result.matches > 0) {
    console.log(dim('  ── anonymized preview ──'));
    console.log(`  ${result.preview}`);
  }
  printSummaryLine(
    [result.matches > 0 ? yellow(`⚠ ${result.matches} masked as [USER_REF_*]`) : green('✔ clean')],
    elapsedMs,
  );
}

// ── 3. entropy ────────────────────────────────────────────────────────────────

export async function runEntropyScan(
  input: string,
  context: string[] = [],
): Promise<{ entropy: number; similarity: number; flagged: boolean; reason?: string }> {
  const { text } = await readText(input);
  return scanEntropyAndReflection(text, { systemContext: context });
}

export function printEntropyResult(
  source: string,
  result: { entropy: number; similarity: number; flagged: boolean; reason?: string },
  elapsedMs?: number,
): void {
  printBanner(`entropy  ·  ${source}`);
  const bar = (v: number, max: number): string => {
    const filled = Math.round(Math.min(1, v / max) * 20);
    return `${'█'.repeat(filled)}${'░'.repeat(20 - filled)}`;
  };
  console.log(`  entropy     ${cyan(bar(result.entropy, 8))} ${result.entropy.toFixed(2)} bits/char`);
  console.log(`  similarity  ${cyan(bar(result.similarity, 1))} ${Math.round(result.similarity * 100)}% vs system context`);
  if (result.flagged) {
    console.log(`\n  ${red('✘ FLAGGED')} — ${result.reason ?? 'potential prompt leak'}`);
    printSummaryLine([red('✘ reflection risk — review before re-injecting')], elapsedMs);
    process.exitCode = 1;
  } else {
    printSummaryLine([green('✔ no reflection risk detected')], elapsedMs);
  }
}

// ── 4. compress ───────────────────────────────────────────────────────────────

export async function runCompress(
  schemaPath: string,
  name: string,
  description: string,
): Promise<{ compact: string; original: number; compacted: number; saved: number; pct: number }> {
  const { text } = await readText(schemaPath);
  const schema = JSON.parse(text) as Record<string, unknown>;
  const report = analyzeCompression(name, description, schema as Record<string, never>);
  return {
    compact: report.compact,
    original: report.originalTokens,
    compacted: report.compactTokens,
    saved: report.savedTokens,
    pct: report.savedPercent,
  };
}

export function printCompressResult(result: {
  compact: string;
  original: number;
  compacted: number;
  saved: number;
  pct: number;
}): void {
  printBanner('compress  ·  Compact Tool Protocol');
  console.log(`  ${dim('before:')} ${result.original} tokens of JSON Schema`);
  console.log(`  ${dim('after:')}  ${bold(result.compact)}`);
  console.log(`  ${dim('after:')}  ${result.compacted} tokens`);
  printSummaryLine(
    [
      green(`✔ ${result.pct.toFixed(1)}% smaller`),
      dim(progressBar(result.compacted, result.original)),
      dim(`${result.saved} tokens recovered per request`),
    ],
  );
}

/** Quick stats table for `vark session stats` (built from an audit log). */
export function printSessionStats(
  sessions: Array<{ id: string; calls: number; blocked: number }>,
): void {
  printBanner('sessions  ·  derived from the audit trail');
  if (sessions.length === 0) {
    console.log(dim('  (no sessions in this trail)'));
    return;
  }
  console.log(
    '  ' +
      table(
        [
          ['session', 'calls', 'blocked', 'block %'],
          ...sessions.map((s) => [
            s.id,
            String(s.calls),
            s.blocked > 0 ? red(String(s.blocked)) : dim('0'),
            dim(`${s.calls > 0 ? Math.round((s.blocked / s.calls) * 100) : 0}%`),
          ]),
        ],
        { head: true },
      )
        .split('\n')
        .join('\n  '),
  );
}
