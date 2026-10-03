/**
 * Core interfaces & type definitions for `@saturn/vark`.
 *
 * Everything an integrator needs to describe a tool, its privileges, and the
 * result of a guarded execution.
 */

/** Isolation backend used to run tool bodies. */
export type IsolationMode = 'process' | 'wasm' | 'mock';

/** Capability (privilege) grants for a single tool. */
export interface CapabilityConfig {
  /** Filesystem read/write grants. Omitted = unrestricted. */
  filesystem?: {
    /** Glob or prefix grants, e.g. `['./workspace/*']`. Resolved against `process.cwd()`. */
    allow?: string[];
  };
  /**
   * Outbound network grants.
   * - `undefined` | `true`  → unrestricted
   * - `false`               → deny every outbound request
   * - `{ allowedHosts }`    → deny anything outside the host list (`*.example.com` wildcards OK)
   */
  network?: boolean | {
    allowedHosts?: string[];
  };
  /** Hard wall-clock budget for `run()`. Defaults to 10 000 ms. */
  maxExecutionMs?: number;
}

/** Pre-execution payload firewall rules. */
export interface CircuitBreakerConfig {
  /** Block `;`, `&&`, `|`, `$()`, backticks, `eval(`, `rm -rf`, `curl|sh`, … @default true */
  blockShellInjection?: boolean;
  /** Block `../`, `..\`, `/etc/passwd`, `/root`, `.env`, … @default true */
  blockPathTraversal?: boolean;
  /**
   * Extra rules evaluated for every argument value.
   *
   * Return `false` / `undefined` → value passes.
   * Return `true`                → value is blocked (generic reason).
   * Return a `string`            → value is blocked, string becomes the reason.
   */
  customRules?: Array<(argName: string, value: unknown) => boolean | string>;
}

/** Output/input Data-Leak-Prevention (secret redaction) policy. */
export interface DlpConfig {
  /**
   * - `'redact'` → replace secrets with `[REDACTED_SECRET: <TYPE>]` and continue (default)
   * - `'block'`  → refuse the call with `blockedBy: 'DLP_REDACTED'`
   * @default 'redact'
   */
  mode?: 'redact' | 'block';
  /** @default true */
  enabled?: boolean;
  /** Additional scanners, processed after the built-in ones. */
  patterns?: ReadonlyArray<{ type: string; pattern: RegExp }>;
}

/** Indirect prompt-injection defence for untrusted text entering the LLM. */
export interface IndirectInjectionConfig {
  /**
   * - `'sanitize'` → strip the malicious spans and return cleaned text (default)
   * - `'block'`    → refuse the call with `blockedBy: 'INDIRECT_INJECTION'`
   * - `'flag'`     → return the text untouched, but audit it as `INDIRECT_INJECTION`
   * @default 'sanitize'
   */
  mode?: 'sanitize' | 'block' | 'flag';
  /** @default true */
  enabled?: boolean;
  /** Extra detectors: return `true`/a reason to flag the text. */
  customRules?: ReadonlyArray<(text: string) => boolean | string>;
}

/** Stateful agent-loop / velocity limits, tracked per session. */
export interface AnomalyGuardConfig {
  /** Identical `tool + args` calls allowed before the next one is blocked. @default 3 */
  maxIdenticalCalls?: number;
  /** Calls allowed in `windowMs` before the session is halted. @default 30 */
  maxCallsPerMinute?: number;
  /** Sliding window size in ms. @default 60_000 */
  windowMs?: number;
  /** Lifetime call budget for a session. @default 1_000 */
  maxTotalCalls?: number;
  /** Lifetime token budget for a session (estimated tokens). @default 250_000 */
  maxSessionTokens?: number;
  /** Sessions kept in memory (least-recently-used evicted). @default 1_000 */
  maxSessions?: number;
  /** @default true */
  enabled?: boolean;
}

/** Append-only, hash-chained audit telemetry. */
export interface AuditLoggerConfig {
  /** Optional HMAC-SHA256 key — makes entries tamper-evident, not just tamper-detecting. */
  hmacKey?: string | Uint8Array;
  /** Ring-buffer cap; oldest entries are dropped first. @default 10_000 */
  maxEntries?: number;
  /** Called with every appended entry (persist / ship to a SIEM). */
  sink?: (entry: AuditEntry) => void;
  /** @default true */
  enabled?: boolean;
}

/** One immutable record in the audit trail. */
export interface AuditEntry {
  readonly seq: number;
  readonly timestamp: string;
  readonly sessionId: string;
  readonly tool: string;
  readonly decision: GateDecision;
  readonly blockedBy?: BlockedBy;
  readonly reason?: string;
  /** Arguments after input DLP — never the raw secrets. */
  readonly sanitizedInputs: unknown;
  readonly inputRedactions: number;
  readonly outputRedactions: number;
  readonly injectionSanitized: number;
  readonly executionTimeMs: number;
  /** Time spent inside the circuit breaker (sub-ms budget). */
  readonly inspectionMs: number;
  /** CTP tokens saved for this tool on this call. */
  readonly tokensSaved: number;
  readonly findings: string[];
  readonly prevHash: string;
  readonly hash: string;
}

/** Schema validation policy for the runtime schema gate. */
export interface SchemaValidationConfig {
  /** @default true */
  enabled?: boolean;
  /** Reject instead of coerce type mismatches ("42" → 42). @default false */
  strict?: boolean;
  /** Validate arguments against the tool's declared JSON Schema. @default true */
  validateArgs?: boolean;
}

/** Isolation policy for the execution gate. */
export interface IsolationConfig {
  /** Requested isolation backend. @default 'process' */
  mode?: IsolationMode;
  /** Memory ceiling per isolated execution, in MB. @default 64 */
  memoryLimitMb?: number;
  /** Fall back to in-process execution when true isolation is unavailable. @default true */
  allowFallback?: boolean;
}

/** Top-level runtime configuration. */
export interface VarkConfig {
  /**
   * Isolation backend. `'wasm'` now runs tool code in a true isolated V8
   * context (via `isolated-vm`) with a memory ceiling; it falls back to
   * `'process'` only when `isolation.allowFallback` is set and the native
   * module is unavailable.
   * @default 'process'
   */
  isolation?: IsolationMode;
  /** Fine-grained isolation policy. */
  isolationConfig?: IsolationConfig;
  circuitBreaker?: CircuitBreakerConfig;
  defaultCapabilities?: CapabilityConfig;
  /** Secret redaction on the way in and out. */
  dlp?: DlpConfig;
  /** Indirect prompt-injection filter for returned text. */
  indirectInjection?: IndirectInjectionConfig;
  /** Per-session loop / velocity limits. */
  anomaly?: AnomalyGuardConfig;
  /** Hash-chained audit telemetry. */
  audit?: AuditLoggerConfig;
  /** Runtime schema validation gate. */
  schema?: SchemaValidationConfig;
  /** Initial agent session id. @default 'default' */
  sessionId?: string;
}

/** A tool exposed to the agent, guarded by vark. */
export interface ToolDefinition<TArgs = any, TResult = any> {
  name: string;
  description: string;
  /** Standard JSON Schema (or plain object schema) describing `TArgs`. */
  schema: Record<string, any>;
  /** Privilege grants. Merged over `VarkConfig.defaultCapabilities`. */
  capabilities?: CapabilityConfig;
  run: (args: TArgs, context: ExecutionContext) => Promise<TResult>;
}

/** Privileged host services handed to `run()`. Every method enforces capabilities. */
export interface ExecutionContext {
  sandbox: {
    readFile: (path: string) => Promise<string>;
    fetch: (url: string, init?: RequestInit) => Promise<Response>;
  };
}

/** Why a call was refused. */
export type BlockedBy =
  | 'CIRCUIT_BREAKER'
  | 'CAPABILITY_VIOLATION'
  | 'TIMEOUT'
  | 'EXECUTION_ERROR'
  | 'DLP_REDACTED'
  | 'INDIRECT_INJECTION'
  | 'LOOP_BLOCKED';

/** Terminal gate decision recorded in the audit trail. */
export type GateDecision =
  | 'ALLOWED'
  | 'CIRCUIT_BREAKER'
  | 'CAPABILITY_VIOLATION'
  | 'DLP_REDACTED'
  | 'INDIRECT_INJECTION'
  | 'LOOP_BLOCKED'
  | 'TIMEOUT'
  | 'EXECUTION_ERROR';

/** Per-call options (which agent session the call belongs to). */
export interface ExecutionOptions {
  /** Defaults to the runtime's current session (`'default'`). */
  sessionId?: string;
}

/** Outcome of a guarded tool execution. Always returned, never thrown. */
export interface ToolExecutionResult<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  blockedBy?: BlockedBy;
  executionTimeMs: number;
  /** Secrets stripped from the arguments before `run()` saw them. */
  inputRedactions?: number;
  /** Secrets stripped from the return value before it reached the LLM. */
  outputRedactions?: number;
  /** Indirect prompt-injection spans removed from the return value. */
  injectionSanitized?: number;
  /** Agent session that produced this call. */
  sessionId?: string;
}

/** Result of a non-throwing check (payload inspection, capability audit, dry run). */
export interface InspectionResult {
  safe: boolean;
  reason?: string;
}

/** Result of a dry run: guards only, no execution. */
export interface GuardResult extends InspectionResult {
  blockedBy?: BlockedBy;
}

/** Base class for every refusal raised inside vark. */
export class VarkError extends Error {
  readonly blockedBy: BlockedBy;

  constructor(blockedBy: BlockedBy, message: string) {
    super(message);
    this.name = 'VarkError';
    this.blockedBy = blockedBy;
  }
}

/** Payload tripped the circuit breaker. */
export class CircuitBreakerError extends VarkError {
  constructor(message: string) {
    super('CIRCUIT_BREAKER', message);
    this.name = 'CircuitBreakerError';
  }
}

/** Argument or sandbox call exceeded the granted capabilities. */
export class CapabilityViolationError extends VarkError {
  constructor(message: string) {
    super('CAPABILITY_VIOLATION', message);
    this.name = 'CapabilityViolationError';
  }
}

/** `run()` exceeded `maxExecutionMs`. */
export class VarkTimeoutError extends VarkError {
  constructor(message: string) {
    super('TIMEOUT', message);
    this.name = 'VarkTimeoutError';
  }
}
