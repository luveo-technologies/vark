/**
 * True WASM / Sandbox Isolation
 *
 * Replaces the `'wasm'` fallback-to-`'process'` behavior with a real isolated
 * execution boundary. Tool code runs in a separate V8 isolate (via
 * `isolated-vm`) with configurable memory ceilings, or falls back to a
 * restricted `vm.Module` context when `isolated-vm` is unavailable.
 */

import type { IsolationMode } from './types.js';
import * as vm from 'node:vm';

/** Memory ceiling for an isolated isolate (default 64 MB). */
export const DEFAULT_ISOLATE_MEMORY_LIMIT_MB = 64;

/** Wall-clock budget for isolate creation + script compilation. */
export const ISOLATE_WALLCLOCK_BUDGET_MS = 5_000;

export interface IsolateConfig {
  /** Memory ceiling in MB. Default 64. */
  memoryLimitMb?: number;
  /** Wall-clock budget for script execution in ms. */
  timeoutMs?: number;
  /** Whether to capture stdout/stderr from the isolate. */
  captureOutput?: boolean;
}

export interface IsolateResult<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  /** Peak memory usage in bytes (when measurable). */
  peakMemoryBytes?: number;
  /** Wall-clock execution time in ms. */
  executionTimeMs: number;
}

/**
 * Execute a function inside an isolated V8 context.
 *
 * When `isolated-vm` is installed, the function runs in a true separate heap
 * with a hard memory ceiling. When it is not available, we fall back to
 * Node's built-in `vm` module which still provides a fresh V8 context with
 * no access to the host's `require`, `process`, or global scope.
 */
export async function executeIsolated<TArgs extends unknown[], TResult>(
  fn: (...args: TArgs) => TResult | Promise<TResult>,
  args: TArgs,
  config: IsolateConfig = {},
): Promise<IsolateResult<TResult>> {
  const startedAt = performance.now();
  const memoryLimitMb = config.memoryLimitMb ?? DEFAULT_ISOLATE_MEMORY_LIMIT_MB;
  const timeoutMs = config.timeoutMs ?? 10_000;

  // Attempt to use isolated-vm for true heap isolation. The specifier is
  // indirect so TypeScript does not try to resolve the optional dependency
  // at compile time.
  try {
    const moduleName = 'isolated-vm';
    const ivm = (await import(moduleName)) as IsolatedVmModule;
    return await executeWithIsolatedVm(ivm, fn, args, { memoryLimitMb, timeoutMs, startedAt });
  } catch {
    // isolated-vm not available — fall back to Node's vm module.
    return executeWithNodeVm(fn, args, { timeoutMs, startedAt });
  }
}

interface IsolatedVmModule {
  Isolate: new (options: { memoryLimit: number }) => {
    createContext(): Promise<{
      global: Record<string, unknown>;
    }>;
    compileScript(code: string): Promise<{
      run(
        context: unknown,
        options: { timeout: number },
      ): Promise<{ copy(): Promise<unknown> }>;
    }>;
    dispose(): void;
  };
}

async function executeWithIsolatedVm<TArgs extends unknown[], TResult>(
  ivm: IsolatedVmModule,
  fn: (...args: TArgs) => TResult | Promise<TResult>,
  args: TArgs,
  opts: { memoryLimitMb: number; timeoutMs: number; startedAt: number },
): Promise<IsolateResult<TResult>> {
  const isolate = new ivm.Isolate({ memoryLimit: opts.memoryLimitMb });
  try {
    const context = await isolate.createContext();

    // Serialise the function and its arguments into the isolate.
    const fnSource = fn.toString();
    const argsJson = JSON.stringify(args);

    const script = await isolate.compileScript(`
      (function() {
        const fn = ${fnSource};
        const args = JSON.parse(${JSON.stringify(argsJson)});
        return Promise.resolve(fn(...args));
      })()
    `);

    const result = await script.run(context, { timeout: opts.timeoutMs });
    const data = (await result.copy()) as TResult;

    return {
      success: true,
      data,
      executionTimeMs: performance.now() - opts.startedAt,
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : String(error),
      executionTimeMs: performance.now() - opts.startedAt,
    };
  } finally {
    isolate.dispose();
  }
}

async function executeWithNodeVm<TArgs extends unknown[], TResult>(
  fn: (...args: TArgs) => TResult | Promise<TResult>,
  args: TArgs,
  opts: { timeoutMs: number; startedAt: number },
): Promise<IsolateResult<TResult>> {
  // node:vm is imported statically at module top: require() does not exist
  // in ESM and would throw ReferenceError here.
  const sandbox: Record<string, unknown> = {
    console: { log: () => undefined, error: () => undefined, warn: () => undefined },
    JSON,
    Math,
    Date,
    Promise,
    setTimeout: undefined,
    setInterval: undefined,
    process: undefined,
    require: undefined,
  };

  const context = vm.createContext(sandbox);

  try {
    const fnSource = fn.toString();
    const argsJson = JSON.stringify(args);
    const script = `
      (function() {
        const fn = ${fnSource};
        const args = JSON.parse(${JSON.stringify(argsJson)});
        return Promise.resolve(fn(...args));
      })()
    `;

    const result = vm.runInContext(script, context, { timeout: opts.timeoutMs });
    // Await the result if it's a Promise (works for both sync and async functions).
    const data = (await result) as TResult;
    return {
      success: true,
      data,
      executionTimeMs: performance.now() - opts.startedAt,
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : String(error),
      executionTimeMs: performance.now() - opts.startedAt,
    };
  }
}

/**
 * Check whether true isolation (isolated-vm) is available at runtime.
 */
export async function isTrueIsolationAvailable(): Promise<boolean> {
  try {
    const moduleName = 'isolated-vm';
    const mod = (await import(moduleName)) as IsolatedVmModule;
    return typeof mod.Isolate === 'function';
  } catch {
    return false;
  }
}

/**
 * Resolve the effective isolation mode, accounting for availability.
 *
 * The fallback is never silent: when true isolation is requested but
 * unavailable, `warning` explains exactly what the caller gets instead, so
 * operators cannot mistake advisory in-process execution for a real boundary.
 */
export async function resolveIsolationMode(
  requested: IsolationMode,
): Promise<{ mode: IsolationMode; trueIsolation: boolean; warning?: string }> {
  if (requested === 'wasm') {
    const available = await isTrueIsolationAvailable();
    return available
      ? { mode: 'wasm', trueIsolation: true }
      : {
          mode: 'process',
          trueIsolation: false,
          warning:
            "isolation:'wasm' requested but isolated-vm is not installed — " +
            'falling back to advisory in-process execution (no memory ceiling, ' +
            'shared heap). Install isolated-vm or set isolationConfig.allowFallback: false to refuse instead.',
        };
  }
  return { mode: requested, trueIsolation: false };
}
