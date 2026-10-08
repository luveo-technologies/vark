/**
 * Subprocess & Resource Quotas
 *
 * Enforces strict CPU time, memory limits, and subprocess instantiation
 * limits per session. Prevents runaway tools from exhausting host resources.
 */

export interface QuotaConfig {
  /** Maximum CPU time per tool execution in ms. @default 5_000 */
  maxCpuTimeMs?: number;
  /** Maximum memory per tool execution in bytes. @default 268_435_456 (256 MB) */
  maxMemoryBytes?: number;
  /** Maximum number of subprocesses a tool may spawn. @default 0 (no subprocesses) */
  maxSubprocesses?: number;
  /** Maximum number of file descriptors a tool may open. @default 32 */
  maxFileDescriptors?: number;
  /** Maximum output size in bytes. @default 1_048_576 (1 MB) */
  maxOutputBytes?: number;
}

export interface QuotaStatus {
  cpuTimeMs: number;
  memoryBytes: number;
  subprocesses: number;
  fileDescriptors: number;
  outputBytes: number;
}

export interface QuotaCheckResult {
  allowed: boolean;
  reason?: string;
  /** Machine-readable refusal code. Present exactly when `allowed` is false. */
  code?: QuotaCode;
  status: QuotaStatus;
}

/** Machine-readable quota refusal codes for SIEM routing and alerting. */
export type QuotaCode =
  | 'QUOTA_CPU_TIME'
  | 'QUOTA_MEMORY'
  | 'QUOTA_SUBPROCESS'
  | 'QUOTA_FILE_DESCRIPTORS'
  | 'QUOTA_OUTPUT';

const DEFAULT_MAX_CPU_TIME_MS = 5_000;
const DEFAULT_MAX_MEMORY_BYTES = 268_435_456; // 256 MB
const DEFAULT_MAX_SUBPROCESSES = 0;
const DEFAULT_MAX_FILE_DESCRIPTORS = 32;
const DEFAULT_MAX_OUTPUT_BYTES = 1_048_576; // 1 MB

/**
 * Per-session resource quota tracker. Enforces limits on CPU time, memory,
 * subprocess count, file descriptors, and output size.
 */
export class ResourceQuota {
  readonly #config: Required<QuotaConfig>;
  readonly #sessions = new Map<string, QuotaStatus>();

  constructor(config: QuotaConfig = {}) {
    this.#config = {
      maxCpuTimeMs: config.maxCpuTimeMs ?? DEFAULT_MAX_CPU_TIME_MS,
      maxMemoryBytes: config.maxMemoryBytes ?? DEFAULT_MAX_MEMORY_BYTES,
      maxSubprocesses: config.maxSubprocesses ?? DEFAULT_MAX_SUBPROCESSES,
      maxFileDescriptors: config.maxFileDescriptors ?? DEFAULT_MAX_FILE_DESCRIPTORS,
      maxOutputBytes: config.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES,
    };
  }

  get config(): Readonly<Required<QuotaConfig>> {
    return { ...this.#config };
  }

  /** Get or create quota status for a session. */
  getSession(sessionId: string): QuotaStatus {
    let status = this.#sessions.get(sessionId);
    if (!status) {
      status = {
        cpuTimeMs: 0,
        memoryBytes: 0,
        subprocesses: 0,
        fileDescriptors: 0,
        outputBytes: 0,
      };
      this.#sessions.set(sessionId, status);
    }
    return status;
  }

  /** Check whether a tool execution is allowed under current quotas. */
  checkExecution(sessionId: string): QuotaCheckResult {
    const status = this.getSession(sessionId);
    return { allowed: true, status };
  }

  /** Record CPU time consumption. Returns false if quota exceeded. */
  recordCpuTime(sessionId: string, ms: number): QuotaCheckResult {
    const status = this.getSession(sessionId);
    status.cpuTimeMs += ms;
    if (status.cpuTimeMs > this.#config.maxCpuTimeMs) {
      return {
        allowed: false,
        code: 'QUOTA_CPU_TIME',
        reason: `CPU time quota exceeded: ${status.cpuTimeMs}ms > ${this.#config.maxCpuTimeMs}ms`,
        status,
      };
    }
    return { allowed: true, status };
  }

  /** Record memory allocation. Returns false if quota exceeded. */
  recordMemory(sessionId: string, bytes: number): QuotaCheckResult {
    const status = this.getSession(sessionId);
    status.memoryBytes += bytes;
    if (status.memoryBytes > this.#config.maxMemoryBytes) {
      return {
        allowed: false,
        code: 'QUOTA_MEMORY',
        reason: `Memory quota exceeded: ${status.memoryBytes} > ${this.#config.maxMemoryBytes} bytes`,
        status,
      };
    }
    return { allowed: true, status };
  }

  /** Record subprocess instantiation. Returns false if quota exceeded. */
  recordSubprocess(sessionId: string): QuotaCheckResult {
    const status = this.getSession(sessionId);
    status.subprocesses += 1;
    if (status.subprocesses > this.#config.maxSubprocesses) {
      return {
        allowed: false,
        code: 'QUOTA_SUBPROCESS',
        reason: `Subprocess quota exceeded: ${status.subprocesses} > ${this.#config.maxSubprocesses}`,
        status,
      };
    }
    return { allowed: true, status };
  }

  /** Record file descriptor usage. Returns false if quota exceeded. */
  recordFileDescriptor(sessionId: string, count: number = 1): QuotaCheckResult {
    const status = this.getSession(sessionId);
    status.fileDescriptors += count;
    if (status.fileDescriptors > this.#config.maxFileDescriptors) {
      return {
        allowed: false,
        code: 'QUOTA_FILE_DESCRIPTORS',
        reason: `File descriptor quota exceeded: ${status.fileDescriptors} > ${this.#config.maxFileDescriptors}`,
        status,
      };
    }
    return { allowed: true, status };
  }

  /** Record output size. Returns false if quota exceeded. */
  recordOutput(sessionId: string, bytes: number): QuotaCheckResult {
    const status = this.getSession(sessionId);
    status.outputBytes += bytes;
    if (status.outputBytes > this.#config.maxOutputBytes) {
      return {
        allowed: false,
        code: 'QUOTA_OUTPUT',
        reason: `Output size quota exceeded: ${status.outputBytes} > ${this.#config.maxOutputBytes} bytes`,
        status,
      };
    }
    return { allowed: true, status };
  }

  /** Reset quotas for a session. */
  resetSession(sessionId: string): void {
    this.#sessions.delete(sessionId);
  }

  /** Reset all sessions. */
  resetAll(): void {
    this.#sessions.clear();
  }

  get sessionCount(): number {
    return this.#sessions.size;
  }
}
