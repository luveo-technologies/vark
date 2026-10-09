/**
 * `vark scan` — scan raw text through the detection stages with a live
 * per-stage pipeline visualisation.
 *
 * Unlike `check` (which dry-runs a registered tool), `scan` takes arbitrary
 * text — a prompt, a tool argument, a fetched page — and shows exactly which
 * detection stage fires: normalization → circuit breaker → DLP → injection.
 *
 * `--direction` selects the side of the tool boundary: `input` (default)
 * scans arguments/prompts with all gates; `output` scans text a tool
 * returned, where the circuit breaker intentionally does not apply and
 * DLP + injection are the police.
 */

import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { inspectPayload } from '../../circuit-breaker.js';
import { scanSecrets } from '../../dlp.js';
import { scanIndirectInjection } from '../../indirect-injection.js';
import { scanSemanticInjection } from '../../security/injection/semantic-injection.js';
import { normalizeAndDecode } from '../../security/sanitization/normalizer.js';
import type { GateState } from '../ux.js';
import { printBanner, printSummaryLine, renderPipeline } from '../ux.js';
import pkg from 'picocolors';
const { green, red, dim } = pkg;

export interface ScanStageResult {
  id: string;
  label: string;
  fired: boolean;
  detail: string;
}

/**
 * Which side of the tool boundary the text sits on:
 * - `input`  — tool arguments / prompts (gate 3 circuit breaker applies)
 * - `output` — text a tool returned (gates 6–7: DLP + injection; the
 *   breaker intentionally does not gate outputs — tool output is data)
 */
export type ScanDirection = 'input' | 'output';

export interface ScanOptions {
  direction?: ScanDirection;
}

export interface ScanResult {
  source: string;
  direction: ScanDirection;
  originalLength: number;
  decodedVariants: number;
  stages: ScanStageResult[];
  triggered: boolean;
}

async function loadText(input: string): Promise<{ source: string; text: string }> {
  if (input === '-') {
    // stdin
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
    return { source: '<stdin>', text: Buffer.concat(chunks).toString('utf8') };
  }
  try {
    const path = resolve(input);
    const text = await readFile(path, 'utf8');
    return { source: path, text };
  } catch {
    // Not a file — treat the argument itself as the text to scan
    return { source: '<arg>', text: input };
  }
}

export async function runScan(input: string, options: ScanOptions = {}): Promise<ScanResult> {
  const direction: ScanDirection = options.direction ?? 'input';
  const { source, text } = await loadText(input);

  // Stage 0 — normalization (always "runs", reports what it found)
  const variants = normalizeAndDecode(text);
  const normalized = variants[0] ?? text;
  const changed = normalized !== text || variants.length > 1;

  // Scan every decoded variant; the breaker sees what the attacker hides.
  // Output direction skips it: gate 3 inspects tool INPUTS — text a tool
  // returned is data to the breaker, and gates 6–7 (DLP + injection) below
  // are what police it.
  let breakerHit: string | undefined;
  if (direction === 'input') {
    for (const variant of variants) {
      const verdict = inspectPayload({ input: variant }, undefined, 'input');
      if (!verdict.safe && verdict.reason) {
        breakerHit = verdict.reason;
        break;
      }
    }
  }

  // DLP over the raw + normalized text
  const dlpHits = new Set<string>();
  for (const variant of variants) {
    for (const match of scanSecrets(variant)) dlpHits.add(match.type);
  }

  // Injection: regex detectors + semantic clusters
  const injection = scanIndirectInjection(normalized);
  const semantic = scanSemanticInjection(normalized);
  const injectionDetail = [
    ...injection.reasons.slice(0, 2),
    ...semantic.matches.slice(0, 2).map((m) => `${m.cluster} (${Math.round(m.score * 100)}%)`),
  ];

  const stages: ScanStageResult[] = [
    {
      id: 'normalize',
      label: 'Normalizer',
      fired: changed,
      detail: changed
        ? `${variants.length} decoded variants (NFKC, entities, encodings)`
        : 'clean — no obfuscation layers',
    },
    {
      id: 'breaker',
      label: 'Circuit Breaker',
      fired: breakerHit !== undefined,
      detail:
        direction === 'output'
          ? 'n/a — gate 3 inspects tool inputs; outputs are gated by DLP + injection'
          : (breakerHit ?? 'no shell/traversal signatures'),
    },
    {
      id: 'dlp',
      label: 'Secret Scanner',
      fired: dlpHits.size > 0,
      detail: dlpHits.size > 0 ? [...dlpHits].join(', ') : 'no secrets detected',
    },
    {
      id: 'injection',
      label: 'Injection Filter',
      fired: injection.triggered || semantic.triggered,
      detail:
        injectionDetail.length > 0 ? injectionDetail.join('; ') : 'no injection signals',
    },
  ];

  return {
    source,
    direction,
    originalLength: text.length,
    decodedVariants: variants.length,
    stages,
    triggered: stages.some((s) => s.id !== 'normalize' && s.fired),
  };
}

export function printScanResult(result: ScanResult, elapsedMs?: number): void {
  printBanner(`scan  ·  ${result.direction}  ·  ${result.source} (${result.originalLength} chars)`);

  const states: GateState[] = result.stages.map((s) => ({
    id: s.id,
    label: s.label,
    status: s.fired && s.id !== 'normalize' ? 'fail' : 'pass',
    detail: s.detail,
    marker: '← DETECTED',
  }));
  // Normalizer is informational — never a block
  const normalizer = states[0];
  if (normalizer && result.stages[0]?.fired) {
    normalizer.detail = `⚠ ${normalizer.detail}`;
  }

  console.log(renderPipeline(states));

  const verdict = result.triggered ? red('✘ THREAT DETECTED') : green('✔ CLEAN');
  printSummaryLine([verdict, dim(`${result.decodedVariants} variants scanned`)], elapsedMs);

  if (result.triggered) process.exitCode = 1;
}
