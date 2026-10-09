/**
 * `vark policy test` command handler
 *
 * Execute unit test assertions against custom declarative policy files.
 */

import { access, readFile, writeFile } from 'node:fs/promises';
import { extname, resolve } from 'node:path';
import { VarkRuntime } from '../../runtime.js';
import type { CapabilityConfig, VarkConfig } from '../../types.js';
import {
  generatePolicyKeyPair,
  signPolicy,
  verifyPolicy,
} from '../../policy-signature.js';
import type { PolicySignature, VerifyResult } from '../../policy-signature.js';
import { diffPolicy } from '../../policy-diff.js';
import type { PolicyDiffEntry } from '../../policy-diff.js';
import pkg from 'picocolors';
const { green, red, yellow, dim } = pkg;
import { printBanner, printSummaryLine, progressBar } from '../ux.js';

export interface PolicyFile {
  // Policy configuration
  config?: VarkConfig;
  tools?: Array<{
    name: string;
    description: string;
    schema: Record<string, unknown>;
    capabilities?: CapabilityConfig;
    run: string; // Function body as string for testing
  }>;
  tests?: PolicyTest[];
}

export interface PolicyTest {
  name: string;
  tool: string;
  args: unknown;
  identity?: string;
  shouldAllow: boolean;
  expectedBlockedBy?: string;
  expectedReasonContains?: string;
}

export interface PolicyTestResult {
  name: string;
  passed: boolean;
  actual: {
    success: boolean;
    blockedBy?: string;
    error?: string;
  };
  expected: {
    shouldAllow: boolean;
    expectedBlockedBy?: string;
  };
  error?: string;
}

export async function runPolicyTest(
  policyPath: string,
  opts: {
    quiet?: boolean;
    /** Pin signature verification to this public key PEM. */
    keyPath?: string;
    /** Fail unless the policy carries a valid signature bundle. */
    requireSignature?: boolean;
    /** Skip automatic verification of an existing `<policy>.sig`. */
    skipSignature?: boolean;
  } = {},
): Promise<{ passed: number; failed: number; results: PolicyTestResult[] }> {
  const resolvedPath = resolve(policyPath);

  // Signature verification runs BEFORE the policy is parsed or executed:
  // a bundle that exists but no longer matches the bytes is refused, so
  // drifted/tampered policies never reach the test harness.
  if (opts.skipSignature && opts.requireSignature) {
    throw new Error('--skip-signature and --require-signature cannot be combined');
  }
  if (!opts.skipSignature) {
    const sigPath = `${resolvedPath}.sig`;
    const signed = await fileExists(sigPath);
    if (signed) {
      const outcome = await verifyPolicyFile(resolvedPath, {
        keyPath: opts.keyPath,
        sigPath,
      });
      if (!outcome.ok) {
        throw new Error(
          `policy signature verification failed (${outcome.reason}): ${outcome.detail ?? ''}`.trim(),
        );
      }
    } else if (opts.requireSignature) {
      throw new Error(
        `policy is unsigned but --require-signature was set (expected ${sigPath})`,
      );
    }
  }

  const policy = await loadPolicy(resolvedPath);

  if (!policy.tests || policy.tests.length === 0) {
    // `quiet` keeps stdout pure NDJSON for --output-format streaming-json.
    if (!opts.quiet) console.log(`${yellow('⚠')} No tests found in policy file`);
    return { passed: 0, failed: 0, results: [] };
  }

  // Create runtime with policy config
  const runtime = new VarkRuntime(policy.config);

  // Register tools from policy
  if (policy.tools) {
    for (const toolDef of policy.tools) {
      runtime.tool({
        name: toolDef.name,
        description: toolDef.description,
        schema: toolDef.schema,
        capabilities: toolDef.capabilities,
        run: createTestRunFunction(toolDef.run),
      });
    }
  }

  // Run tests
  const results: PolicyTestResult[] = [];

  for (const test of policy.tests) {
    const result = await runSingleTest(runtime, test);
    results.push(result);
  }

  const passed = results.filter((r) => r.passed).length;
  const failed = results.filter((r) => !r.passed).length;

  return { passed, failed, results };
}

export async function loadPolicy(filePath: string): Promise<PolicyFile> {
  const content = await readFile(filePath, 'utf8');
  const ext = extname(filePath).toLowerCase();

  if (ext !== '.json') {
    throw new Error(`Unsupported file format: ${ext} (policy files must be JSON)`);
  }
  try {
    return JSON.parse(content) as PolicyFile;
  } catch (error) {
    throw new Error(
      `Failed to parse ${filePath}: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    );
  }
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

// ── signed policy bundles ─────────────────────────────────────────────────────

export interface PolicyVerifyOutcome {
  ok: boolean;
  reason?: VerifyResult['reason'];
  detail?: string;
  signature?: PolicySignature;
  /** Where the signature bundle was read from. */
  sigPath: string;
}

/**
 * Verify `<policy>.sig` (or `opts.sigPath`) against the policy's exact
 * bytes. A missing bundle yields `reason: 'unsigned'` — callers decide
 * whether unsigned is acceptable (`--require-signature` says no).
 */
export async function verifyPolicyFile(
  policyPath: string,
  opts: { keyPath?: string; sigPath?: string } = {},
): Promise<PolicyVerifyOutcome> {
  const resolvedPath = resolve(policyPath);
  const sigPath = opts.sigPath ? resolve(opts.sigPath) : `${resolvedPath}.sig`;

  let rawSignature: string;
  try {
    rawSignature = await readFile(sigPath, 'utf8');
  } catch {
    return {
      ok: false,
      reason: 'unsigned',
      detail: `no signature bundle at ${sigPath}`,
      sigPath,
    };
  }

  let signature: PolicySignature;
  try {
    signature = JSON.parse(rawSignature) as PolicySignature;
  } catch (error) {
    return {
      ok: false,
      reason: 'malformed',
      detail: `signature bundle is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
      sigPath,
    };
  }

  const content = await readFile(resolvedPath); // raw bytes — byte-exact drift check
  const pinnedKey = opts.keyPath
    ? await readFile(resolve(opts.keyPath), 'utf8')
    : undefined;
  const result = verifyPolicy(content, signature, pinnedKey ? { publicKeyPem: pinnedKey } : {});
  return {
    ok: result.ok,
    reason: result.reason,
    detail: result.detail,
    signature: result.signature ?? signature,
    sigPath,
  };
}

/** Sign a policy file's exact bytes; writes `<policy>.sig` (or `outPath`). */
export async function signPolicyFile(
  policyPath: string,
  opts: { keyPath: string; outPath?: string },
): Promise<{ sigPath: string; keyId: string; policyHash: string }> {
  const resolvedPath = resolve(policyPath);
  const content = await readFile(resolvedPath); // raw bytes — signed as-is
  const privateKeyPem = await readFile(resolve(opts.keyPath), 'utf8');
  const signature = signPolicy(content, privateKeyPem);
  const sigPath = opts.outPath ? resolve(opts.outPath) : `${resolvedPath}.sig`;
  await writeFile(sigPath, `${JSON.stringify(signature, null, 2)}\n`, 'utf8');
  return { sigPath, keyId: signature.keyId, policyHash: signature.policyHash };
}

/**
 * Generate an Ed25519 key pair as PEM files: `<out>.key.pem` (private,
 * mode 600) and `<out>.pub.pem` (public). Default prefix `vark-policy-key`.
 */
export async function generatePolicyKeyFiles(
  opts: { out?: string } = {},
): Promise<{ privateKeyPath: string; publicKeyPath: string }> {
  const prefix = resolve(opts.out ?? 'vark-policy-key');
  const { privateKey, publicKey } = generatePolicyKeyPair();
  const privateKeyPath = `${prefix}.key.pem`;
  const publicKeyPath = `${prefix}.pub.pem`;
  await writeFile(privateKeyPath, privateKey, { encoding: 'utf8', mode: 0o600 });
  await writeFile(publicKeyPath, publicKey, { encoding: 'utf8', mode: 0o644 });
  return { privateKeyPath, publicKeyPath };
}

/** Structural diff of two policy JSON files (drift detection). */
export async function diffPolicyFiles(
  aPath: string,
  bPath: string,
): Promise<{ entries: PolicyDiffEntry[]; a: string; b: string }> {
  const before = await loadPolicy(resolve(aPath));
  const after = await loadPolicy(resolve(bPath));
  return { entries: diffPolicy(before, after), a: aPath, b: bPath };
}

/**
 * Compile a tool's `run` string into a real function for policy tests.
 *
 * Test-harness only: the body runs with `args` as its sole in-scope
 * variable (e.g. `"return args;"` or `"return { echo: args };"`). This is
 * never used by the production pipeline — `vark policy test` executes the
 * body so assertions exercise the same gates a live call would hit.
 */
function createTestRunFunction(
  body: string,
): (
  args: unknown,
  context: {
    sandbox: {
      readFile: (path: string) => Promise<string>;
      fetch: (url: string, init?: RequestInit) => Promise<Response>;
    };
  },
) => Promise<unknown> {
  const fn = new Function('args', body) as (args: unknown) => unknown;
  return async (args: unknown) => fn(args);
}

async function runSingleTest(
  runtime: VarkRuntime,
  test: PolicyTest,
): Promise<PolicyTestResult> {
  try {
    const options = test.identity ? { sessionId: test.identity } : undefined;
    const result = await runtime.execute(test.tool, test.args, options);

    const passed = test.shouldAllow === result.success &&
      (!test.expectedBlockedBy || (result.blockedBy === test.expectedBlockedBy)) &&
      (!test.expectedReasonContains || (result.error?.includes(test.expectedReasonContains) ?? false));

    return {
      name: test.name,
      passed,
      actual: {
        success: result.success,
        blockedBy: result.blockedBy,
        error: result.error,
      },
      expected: {
        shouldAllow: test.shouldAllow,
        expectedBlockedBy: test.expectedBlockedBy,
      },
    };
  } catch (error) {
    return {
      name: test.name,
      passed: false,
      actual: {
        success: false,
        error: error instanceof Error ? error.message : String(error),
      },
      expected: {
        shouldAllow: test.shouldAllow,
        expectedBlockedBy: test.expectedBlockedBy,
      },
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

export function printTestResults(
  results: { passed: number; failed: number; results: PolicyTestResult[] },
  elapsedMs?: number,
): void {
  printBanner('policy test  ·  assertions against the guard pipeline');

  const total = results.passed + results.failed;
  for (const result of results.results) {
    if (result.passed) {
      console.log(`${green('✓')} ${result.name}  ${dim(progressBar(results.results.indexOf(result) + 1, Math.max(total, 1), 10))}`);
    } else {
      console.log(`${red('✗')} ${result.name}`);
      if (result.actual.success !== undefined) {
        console.log(`    expected: ${result.expected.shouldAllow ? green('ALLOW') : red('BLOCK')}`);
        console.log(`    actual:   ${result.actual.success ? green('ALLOW') : red('BLOCK')}`);
      }
      if (result.expected.expectedBlockedBy) {
        console.log(`    expected gate: ${result.expected.expectedBlockedBy}`);
      }
      if (result.actual.blockedBy) {
        console.log(`    actual gate:   ${yellow(result.actual.blockedBy)}`);
      }
      if (result.actual.error) {
        console.log(`    error: ${result.actual.error}`);
      }
      if (result.error) {
        console.log(`    test error: ${result.error}`);
      }
    }
  }

  printSummaryLine(
    [
      results.failed === 0
        ? green(`✔ ${results.passed}/${total} passed`)
        : `${green(`✔ ${results.passed} passed`)}  ${red(`✘ ${results.failed} failed`)}`,
      dim(progressBar(results.passed, Math.max(total, 1))),
    ],
    elapsedMs,
  );

  if (results.failed > 0) {
    process.exitCode = 1;
  }
}

// ── printers for sign / verify / keygen / diff ───────────────────────────────

export function printPolicySign(result: {
  sigPath: string;
  keyId: string;
  policyHash: string;
}): void {
  printBanner('policy sign  ·  Ed25519 detached signature');
  console.log(`  bundle: ${dim(result.sigPath)}`);
  console.log(`  keyId:  ${result.keyId}`);
  console.log(`  hash:   ${result.policyHash}`);
  printSummaryLine([
    green('✔ policy signed'),
    dim('verify with: vark policy verify <policy>'),
  ]);
}

export function printPolicyVerify(outcome: PolicyVerifyOutcome, elapsedMs?: number): void {
  printBanner('policy verify  ·  Ed25519 detached signature');
  if (outcome.ok) {
    console.log(`  bundle: ${dim(outcome.sigPath)}`);
    console.log(`  keyId:  ${dim(outcome.signature?.keyId ?? '-')}`);
    console.log(`  hash:   ${dim(outcome.signature?.policyHash ?? '-')}`);
    printSummaryLine(
      [green('✔ signature valid'), dim('policy bytes match the signed bundle')],
      elapsedMs,
    );
  } else {
    console.log(`  bundle: ${dim(outcome.sigPath)}`);
    console.log(`  ${red(`✘ ${outcome.reason ?? 'verification failed'}`)}: ${outcome.detail ?? ''}`);
    printSummaryLine([red(`✘ verification failed (${outcome.reason ?? 'unknown'})`)], elapsedMs);
    process.exitCode = 1;
  }
}

export function printPolicyKeygen(files: {
  privateKeyPath: string;
  publicKeyPath: string;
}): void {
  printBanner('policy keygen  ·  Ed25519');
  console.log(`  private: ${dim(files.privateKeyPath)}  ${dim('(keep secret — written mode 600)')}`);
  console.log(`  public:  ${dim(files.publicKeyPath)}`);
  printSummaryLine([
    green('✔ key pair generated'),
    dim('sign with: vark policy sign <policy> --key <private.pem>'),
  ]);
}

function formatDiffValue(value: unknown): string {
  const json = value === undefined ? 'undefined' : (JSON.stringify(value) ?? String(value));
  return json.length > 120 ? `${json.slice(0, 120)}…` : json;
}

export function printPolicyDiff(
  entries: PolicyDiffEntry[],
  aPath: string,
  bPath: string,
  elapsedMs?: number,
): void {
  printBanner(`policy diff  ·  ${aPath} → ${bPath}`);
  for (const entry of entries) {
    if (entry.kind === 'added') {
      console.log(`  ${green('+')} ${entry.path} = ${green(formatDiffValue(entry.after))}`);
    } else if (entry.kind === 'removed') {
      console.log(`  ${red('-')} ${entry.path} = ${red(formatDiffValue(entry.before))}`);
    } else {
      console.log(
        `  ${yellow('~')} ${entry.path}: ${dim(formatDiffValue(entry.before))} → ${yellow(formatDiffValue(entry.after))}`,
      );
    }
  }
  if (entries.length === 0) {
    printSummaryLine([green('✔ policies identical')], elapsedMs);
  } else {
    printSummaryLine(
      [yellow(`✘ ${entries.length} difference${entries.length === 1 ? '' : 's'}`), dim('drift detected (exit 1)')],
      elapsedMs,
    );
  }
}