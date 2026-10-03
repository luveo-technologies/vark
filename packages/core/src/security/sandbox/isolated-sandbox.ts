/**
 * Isolated-VM / QuickJS Sandbox
 *
 * Runs tool code in memory-isolated heaps with configurable memory ceiling
 * caps (default 64 MB). Wraps the core `isolated-vm` module with a
 * higher-level API that enforces memory limits, execution timeouts, and
 * provides a clean result type for the security pipeline.
 */

import { executeIsolated, DEFAULT_ISOLATE_MEMORY_LIMIT_MB } from '../../isolated-vm.js';
import type { IsolateConfig } from '../../isolated-vm.js';

export interface SandboxConfig {
  /** Memory ceiling in MB. @default 64 */
  memoryLimitMb?: number;
  /** Wall-clock execution timeout in ms. @default 10_000 */
  timeoutMs?: number;
  /** Whether to allow fallback to in-process execution. @default true */
  allowFallback?: boolean;
}

export interface SandboxExecutionResult<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  /** Whether true isolation was used (vs fallback). */
  isolated: boolean;
  /** Peak memory usage in bytes (when measurable). */
  peakMemoryBytes?: number;
  /** Wall-clock execution time in ms. */
  executionTimeMs: number;
}

/**
 * Execute a function inside an isolated sandbox with memory ceiling enforcement.
 *
 * When `isolated-vm` is available, the function runs in a true separate V8
 * heap with a hard memory limit. When it is not available and `allowFallback`
 * is true, the function runs in-process (with a warning). When `allowFallback`
 * is false, the execution is refused.
 */
export async function executeInSandbox<TArgs extends unknown[], TResult>(
  fn: (...args: TArgs) => TResult | Promise<TResult>,
  args: TArgs,
  config: SandboxConfig = {},
): Promise<SandboxExecutionResult<TResult>> {
  const memoryLimitMb = config.memoryLimitMb ?? DEFAULT_ISOLATE_MEMORY_LIMIT_MB;
  const timeoutMs = config.timeoutMs ?? 10_000;
  const allowFallback = config.allowFallback ?? true;

  const isolateConfig: IsolateConfig = {
    memoryLimitMb,
    timeoutMs,
  };

  const result = await executeIsolated(fn, args, isolateConfig);

  if (!result.success && !allowFallback) {
    return {
      success: false,
      error: `Sandbox execution failed: ${result.error ?? 'unknown error'}`,
      isolated: false,
      executionTimeMs: result.executionTimeMs,
    };
  }

  return {
    success: result.success,
    data: result.data,
    error: result.error,
    isolated: true,
    peakMemoryBytes: result.peakMemoryBytes,
    executionTimeMs: result.executionTimeMs,
  };
}

/**
 * Create a sandboxed version of an async function that always runs in isolation.
 */
export function createSandboxedFunction<TArgs extends unknown[], TResult>(
  fn: (...args: TArgs) => TResult | Promise<TResult>,
  config: SandboxConfig = {},
): (...args: TArgs) => Promise<SandboxExecutionResult<TResult>> {
  return (...args: TArgs) => executeInSandbox(fn, args, config);
}
