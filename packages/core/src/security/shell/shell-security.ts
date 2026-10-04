/**
 * Shell Execution Security
 *
 * Eliminates string-based character blocklists in favor of explicit argv
 * arrays. Strictly disables `shell: true`. Implements strict binary allowlists
 * and argument validation.
 */

import { execFile, type ChildProcess } from 'node:child_process';
import { resolve as resolvePath } from 'node:path';

export interface ShellExecConfig {
  /** Allowed binary paths (absolute). */
  allowedBinaries: string[];
  /** Maximum argument count. @default 32 */
  maxArgs?: number;
  /** Maximum argument length. @default 4096 */
  maxArgLength?: number;
  /** Timeout in ms. @default 10_000 */
  timeoutMs?: number;
  /** Working directory. */
  cwd?: string;
  /** Environment variables. */
  env?: Record<string, string>;
}

export interface ShellExecResult {
  success: boolean;
  stdout: string;
  stderr: string;
  exitCode: number;
  error?: string;
}

/**
 * Validate that a binary path is in the allowlist.
 */
export function validateBinary(binary: string, allowedBinaries: string[]): boolean {
  const resolved = resolvePath(binary);
  return allowedBinaries.some((allowed) => resolvePath(allowed) === resolved);
}

/**
 * Validate argument count and length.
 */
export function validateArgs(
  args: string[],
  config: Pick<ShellExecConfig, 'maxArgs' | 'maxArgLength'> = {},
): { valid: boolean; reason?: string } {
  const maxArgs = config.maxArgs ?? 32;
  const maxArgLength = config.maxArgLength ?? 4096;

  if (args.length > maxArgs) {
    return { valid: false, reason: `Too many arguments: ${args.length} > ${maxArgs}` };
  }

  for (const arg of args) {
    if (arg.length > maxArgLength) {
      return { valid: false, reason: `Argument too long: ${arg.length} > ${maxArgLength}` };
    }
  }

  return { valid: true };
}

// Callback type for execFile that avoids TypeScript return type inference issues
type ExecFileCallback = (error: Error | null, stdout: string, stderr: string) => void;

function makeExecFileCallback(
  resolve: (result: ShellExecResult) => void,
): ExecFileCallback {
  return (error: Error | null, stdout: string, stderr: string): void => {
    if (error) {
      resolve({
        success: false,
        stdout,
        stderr,
        exitCode: (error as { code?: number }).code ?? -1,
        error: error.message,
      });
      return;
    }
    resolve({
      success: true,
      stdout,
      stderr,
      exitCode: 0,
    });
  };
}

/**
 * Execute a binary with explicit argv array. Never uses `shell: true`.
 * This is the safe alternative to `exec()` with string concatenation.
 */
export function execFileSafe(
  binary: string,
  args: string[],
  config: ShellExecConfig,
): Promise<ShellExecResult> {
  return new Promise((resolve) => {
    // Validate binary allowlist
    if (!validateBinary(binary, config.allowedBinaries)) {
      resolve({
        success: false,
        stdout: '',
        stderr: '',
        exitCode: -1,
        error: `Binary "${binary}" is not in the allowlist`,
      });
      return;
    }

    // Validate arguments
    const argCheck = validateArgs(args, config);
    if (!argCheck.valid) {
      resolve({
        success: false,
        stdout: '',
        stderr: '',
        exitCode: -1,
        error: argCheck.reason,
      });
      return;
    }

    const timeoutMs = config.timeoutMs ?? 10_000;
    const child: ChildProcess = execFile(
      resolvePath(binary),
      args,
      {
        cwd: config.cwd ?? process.cwd(),
        env: { ...process.env, ...(config.env ?? {}) },
        timeout: timeoutMs,
        maxBuffer: 1_048_576,
      },
      makeExecFileCallback(resolve),
    );
    // Suppress unused variable warning — child is used for cleanup
    void child;
  });
}

/**
 * Check if an argument contains shell metacharacters.
 * This is informational only — the safe approach is to use argv arrays.
 */
export function containsShellMetacharacters(arg: string): boolean {
  return /[;&|`$(){}[\]<>!#*?~]/.test(arg);
}

/**
 * Sanitize an argument for safe display in error messages.
 */
export function sanitizeArgForDisplay(arg: string, maxLength: number = 100): string {
  if (arg.length <= maxLength) return arg;
  return `${arg.slice(0, maxLength)}... (${arg.length} chars total)`;
}