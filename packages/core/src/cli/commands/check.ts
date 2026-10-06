/**
 * `vark check` command handler
 *
 * Dry-run evaluate captured tool payload files against Vark security gates
 * without executing target system actions.
 */

import { glob } from 'node:fs/promises';
import { readFile } from 'node:fs/promises';
import { extname, resolve } from 'node:path';
import { VarkRuntime } from '../../runtime.js';
import type { VarkConfig } from '../../types.js';
import pkg from 'picocolors';
const { green, red, yellow, bold, dim } = pkg;
import { printBanner, printSummaryLine, progressBar } from '../ux.js';

export interface CheckPayload {
  tool: string;
  args: unknown;
  identity?: string;
}

export interface CheckResult {
  file: string;
  tool: string;
  success: boolean;
  blockedBy?: string;
  reason?: string;
}

export async function runCheck(
  pattern: string,
  config: VarkConfig = {},
): Promise<CheckResult[]> {
  // Resolve files from pattern
  const files = await resolveFiles(pattern);
  if (files.length === 0) {
    throw new Error(`No files found matching pattern: ${pattern}`);
  }

  // Create runtime with default config
  const runtime = new VarkRuntime(config);

  // We need to register a generic tool that can handle any tool name
  // Since we don't know the tools in advance, we'll use a catch-all approach
  // by registering tools dynamically or using the check method directly

  const results: CheckResult[] = [];

  for (const file of files) {
    const payload = await loadPayload(file);
    const result = await runSingleCheck(runtime, file, payload);
    results.push(result);
  }

  return results;
}

async function resolveFiles(pattern: string): Promise<string[]> {
  const resolvedPattern = resolve(pattern);
  const files = [];
  for await (const file of glob(resolvedPattern)) {
    files.push(resolve(file));
  }
  return files;
}

async function loadPayload(file: string): Promise<unknown> {
  const content = await readFile(file, 'utf8');
  const ext = extname(file).toLowerCase();

  if (ext !== '.json') {
    throw new Error(`Unsupported file format: ${ext} (payload files must be JSON)`);
  }
  try {
    return JSON.parse(content);
  } catch (error) {
    throw new Error(`Failed to parse ${file}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

interface CheckPayloadInternal {
  tool: string;
  args: unknown;
  identity?: string;
}

async function runSingleCheck(
  runtime: VarkRuntime,
  file: string,
  payload: unknown,
): Promise<CheckResult> {
  // Validate payload structure
  const payloadObj = payload as CheckPayloadInternal;

  if (!payloadObj || typeof payloadObj !== 'object') {
    return {
      file,
      tool: 'unknown',
      success: false,
      blockedBy: 'EXECUTION_ERROR',
      reason: 'Payload must be an object with "tool" and "args" properties',
    };
  }

  const { tool, args, identity } = payloadObj as CheckPayloadInternal;

  if (!tool || typeof tool !== 'string') {
    return {
      file,
      tool: 'unknown',
      success: false,
      blockedBy: 'EXECUTION_ERROR',
      reason: 'Payload must have a "tool" string property',
    };
  }

  // Use the check method for dry-run evaluation
  const checkOptions = identity ? { sessionId: identity } : undefined;
  const result = runtime.check(tool, args, checkOptions);

  if (result.safe) {
    return {
      file,
      tool,
      success: true,
    };
  } else {
    return {
      file,
      tool,
      success: false,
      blockedBy: result.blockedBy,
      reason: result.reason,
    };
  }
}

export interface PrintCheckOptions {
  elapsedMs?: number;
  verbose?: boolean;
}

export function printCheckResults(results: CheckResult[], opts: PrintCheckOptions = {}): void {
  printBanner('check  ·  dry-run payloads against the 8 gates');

  const passed = results.filter((r) => r.success).length;
  const failed = results.length - passed;

  for (const result of results) {
    if (result.success) {
      console.log(`${green('[PASS]')} ${result.file} → ${bold(result.tool)}`);
    } else {
      console.log(
        `${red('[BLOCKED]')} ${result.file} → ${bold(result.tool)}`,
      );
      if (result.blockedBy) {
        console.log(`  ${yellow('Gate:')} ${red(result.blockedBy)}`);
      }
      if (result.reason) {
        console.log(`  ${yellow('Reason:')} ${result.reason}`);
      }
      if (opts.verbose && result.blockedBy) {
        const hint = VERBOSE_HINTS[result.blockedBy];
        if (hint) console.log(`  ${dim(`hint: ${hint} (vark explain ${result.blockedBy})`)}`);
      }
    }
  }

  printSummaryLine(
    [
      failed === 0
        ? green(`✔ ${passed} passed`)
        : `${green(`✔ ${passed} passed`)}  ${red(`✘ ${failed} blocked`)}`,
      dim(progressBar(passed, results.length)),
    ],
    opts.elapsedMs,
  );

  if (failed > 0) {
    process.exitCode = 1;
  }
}

/** One-line remediation pointers shown under `--verbose` refusals. */
const VERBOSE_HINTS: Record<string, string> = {
  LOOP_BLOCKED: 'vary the arguments or raise maxIdenticalCalls',
  CAPABILITY_VIOLATION: 'widen the filesystem grant or network allowlist',
  CIRCUIT_BREAKER: 'pass argv arrays, never shell strings',
  DLP_REDACTED: 'rotate the credential; it never reached the tool',
  INDIRECT_INJECTION: 'treat tool output as untrusted input',
  TIMEOUT: 'raise maxExecutionMs or split the work',
  EXECUTION_ERROR: 'compare args against the tool schema',
};