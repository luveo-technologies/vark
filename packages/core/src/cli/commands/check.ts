/**
 * `vark check` command handler
 *
 * Dry-run evaluate captured tool payload files against Vark security gates
 * without executing target system actions.
 */

import { readdir, readFile, stat } from 'node:fs/promises';
import { extname, resolve } from 'node:path';
import { VarkRuntime } from '../../runtime.js';
import { globToRegExp } from '../../sandbox.js';
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
  const registered = new Set<string>();
  const results: CheckResult[] = [];

  for (const file of files) {
    let payload: unknown;
    try {
      payload = await loadPayload(file);
    } catch (error) {
      // A malformed file fails its own entry — the rest of the batch still runs.
      results.push({
        file,
        tool: 'unknown',
        success: false,
        blockedBy: 'EXECUTION_ERROR',
        reason: error instanceof Error ? error.message : String(error),
      });
      continue;
    }
    // Register a permissive stand-in for every tool name in the batch so
    // gates 1–3 evaluate the real arguments. Stand-ins use an empty-object
    // schema, take grants from `-c` config, and can never execute: check()
    // is a dry run and never calls run().
    const toolName =
      payload !== null && typeof payload === 'object' && 'tool' in payload
        ? (payload as { tool?: unknown }).tool
        : undefined;
    if (typeof toolName === 'string' && toolName.length > 0 && !registered.has(toolName)) {
      registered.add(toolName);
      runtime.tool({
        name: toolName,
        description: `Stand-in registered by vark check for ${file}.`,
        schema: { type: 'object' },
        run: async () => {
          throw new Error('stand-in tool must never execute');
        },
      });
    }
    const result = await runSingleCheck(runtime, file, payload);
    results.push(result);
  }

  return results;
}

/** Characters that make a path segment a glob pattern rather than a literal. */
const GLOB_MAGIC = /[*?[\]{}]/;

/**
 * Expand a payload pattern into absolute file paths.
 *
 * Node's `fs.promises.glob` is v22+ and CI runs the test matrix on Node 20,
 * so this walks the literal base directory (everything before the first
 * magic segment) and matches the glob remainder with the same matcher the
 * capability sandbox uses. Plain paths short-circuit to a stat — no walk.
 */
async function resolveFiles(pattern: string): Promise<string[]> {
  const resolvedPattern = resolve(pattern);

  if (!GLOB_MAGIC.test(resolvedPattern)) {
    try {
      return (await stat(resolvedPattern)).isFile() ? [resolvedPattern] : [];
    } catch {
      return [];
    }
  }

  const separator = resolvedPattern.includes('\\') ? '\\' : '/';
  const segments = resolvedPattern.split(/[/\\]+/);
  const magicAt = segments.findIndex((segment) => GLOB_MAGIC.test(segment));
  if (magicAt === -1) return [];

  const base = segments.slice(0, magicAt).join(separator) || separator;
  // The matcher normalises to forward slashes; globToRegExp is
  // case-insensitive on win32, so backslash remainders match too.
  const remainder = segments.slice(magicAt).join('/');

  let candidates: string[];
  try {
    candidates = await walkFiles(base);
  } catch {
    return []; // missing base directory → runCheck reports 'No files found'
  }

  const matches = globToRegExp(remainder);
  return candidates
    .filter((file) =>
      matches.test(file.slice(base.length).replace(/^[\\/]+/, '').replace(/\\/g, '/')),
    )
    .sort();
}

/** Recursively collect regular files (symlinks count when they resolve to one). */
async function walkFiles(dir: string, out: string[] = []): Promise<string[]> {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = resolve(dir, entry.name);
    if (entry.isDirectory()) {
      await walkFiles(full, out);
    } else if (entry.isFile()) {
      out.push(full);
    } else if (entry.isSymbolicLink()) {
      try {
        if ((await stat(full)).isFile()) out.push(full);
      } catch {
        // broken link — skip
      }
    }
  }
  return out;
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
    throw new Error(
      `Failed to parse ${file}: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    );
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
  VELOCITY_EXCEEDED: 'session halted: raise maxCallsPerMinute or resetSession() after review',
  BUDGET_EXCEEDED: 'session halted: raise the call/token budget or resetSession()',
  CAPABILITY_VIOLATION: 'widen the filesystem grant or network allowlist',
  CIRCUIT_BREAKER: 'pass argv arrays, never shell strings',
  DLP_REDACTED: 'rotate the credential; it never reached the tool',
  INDIRECT_INJECTION: 'treat tool output as untrusted input',
  TIMEOUT: 'raise maxExecutionMs or split the work',
  DESCRIPTOR_PIN_VIOLATION: 're-wrap tools to accept the new descriptor, or investigate the server',
  SESSION_FROZEN: 'review the audit trail, then resetSession() to unfreeze',
  HITL_DENIED: 'approve via the HitlGate or raise hitl.timeoutMs',
  EXECUTION_ERROR: 'compare args against the tool schema',
};