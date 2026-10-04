/**
 * `vark policy test` command handler
 *
 * Execute unit test assertions against custom declarative policy files.
 */

import { readFile } from 'node:fs/promises';
import { extname, resolve } from 'node:path';
import { VarkRuntime } from '../../runtime.js';
import type { VarkConfig } from '../../types.js';
import pkg from 'picocolors';
const { green, red, yellow, dim } = pkg;
import { printBanner, printSummaryLine, progressBar } from '../ux.js';

export interface PolicyFile {
  // Policy configuration
  config?: VarkConfig;
  tools?: Array<{
    name: string;
    description: string;
    schema: Record<string, any>;
    capabilities?: Record<string, any>;
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
): Promise<{ passed: number; failed: number; results: PolicyTestResult[] }> {
  const resolvedPath = resolve(policyPath);
  const policy = await loadPolicy(resolvedPath);

  if (!policy.tests || policy.tests.length === 0) {
    console.log(`${yellow('⚠')} No tests found in policy file`);
    return { passed: 0, failed: 0, results: [] };
  }

  // Create runtime with policy config
  const runtime = new VarkRuntime(policy.config);

  // Register tools from policy
  if (policy.tools) {
    for (const toolDef of policy.tools) {
      // Create a mock run function from the string
      const runFn = createMockRunFunction(toolDef.run);
      runtime.tool({
        name: toolDef.name,
        description: toolDef.description,
        schema: toolDef.schema,
        capabilities: toolDef.capabilities,
        run: runFn,
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

async function loadPolicy(filePath: string): Promise<PolicyFile> {
  const content = await readFile(filePath, 'utf8');
  const ext = extname(filePath).toLowerCase();

  try {
    if (ext === '.json') {
      return JSON.parse(content) as PolicyFile;
    } else if (ext === '.yaml' || ext === '.yml') {
      return parseYaml(content) as PolicyFile;
    } else {
      throw new Error(`Unsupported file format: ${ext}`);
    }
  } catch (error) {
    throw new Error(`Failed to parse ${filePath}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

// Simple YAML parser - in production use js-yaml
function parseYaml(content: string): unknown {
  try {
    return JSON.parse(content);
  } catch {
    throw new Error('YAML parsing not fully implemented. Please use JSON format or install js-yaml.');
  }
}

function createMockRunFunction(_body: string): (args: unknown, context: { sandbox: { readFile: (path: string) => Promise<string>; fetch: (url: string, init?: RequestInit) => Promise<Response> } }) => Promise<unknown> {
  // Create a mock run function from the string body
  // In production, this would be more sophisticated
  return async (args: unknown, _context: { sandbox: { readFile: (path: string) => Promise<string>; fetch: (url: string, init?: RequestInit) => Promise<Response> } }) => {
    // For testing, we'll just return the args or a mock response
    // The actual implementation would evaluate the function body
    return { args, mock: true };
  };
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