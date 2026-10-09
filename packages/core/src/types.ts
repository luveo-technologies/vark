/**
 * Core interfaces & type definitions for `@luveo-tech/vark`.
 *
 * Everything an integrator needs to describe a tool, its privileges, and the
 * result of a guarded execution.
 */

import type { AdaptiveRiskConfig } from './adaptive-risk.js';
import type { BreakGlassConfig } from './break-glass.js';
import type { HitlGate } from './gates/hitl-gate.js';
import type { StateStore } from './state-store.js';

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
   * - `undefined` | `true`  → unrestricted (baseline SSRF guard still applies)
   * - `false`               → deny every outbound request
   * - `{ allowedHosts }`    → deny anything outside the host list (`*.example.com` wildcards OK)
   *
   * `ctx.sandbox.fetch` always refuses cloud-metadata endpoints, embedded
   * credentials, and non-http(s) schemes; loopback/RFC1918/link-local
   * targets are refused too unless `allowPrivate` is set (local-dev APIs).
   * Transport-level `VarkConfig.proxy` (corporate forward proxy) is
   * orthogonal: it changes *how* a permitted request travels, never
   * *whether* it is allowed.
   */
  network?: boolean | {
    allowedHosts?: string[];
    /** Permit loopback / private-range egress (dev APIs). @default false */
    allowPrivate?: boolean;
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
  /**
   * Maximum recursive decode depth used when detecting encoded payloads
   * (percent, HTML entities, hex, base64 — nested). Raise it to catch
   * deeper nesting; lower it to bound decode work. @default 5
   */
  maxDecodeDepth?: number;
  /**
   * Refuse any argument string that decodes from an explicit encoding
   * instead of scanning the decoded forms — for deployments that must never
   * accept encoded input at all. Off by default (the strict decoder's
   * marker + printability admission already keeps opaque tokens safe).
   * @default false
   */
  strictDecode?: boolean;
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
  /**
   * Where per-session state lives. Defaults to in-process memory; plug a
   * shared store (e.g. `RedisStateStore`) so loop/velocity/budget limits
   * hold across N replicas of the same deployment.
   */
  store?: StateStore;
  /**
   * Idle-session TTL in ms. Sessions idle longer than this are dropped by
   * `sweepExpired()` (halted/frozen sessions are retained). @default 0 (off)
   */
  sessionTTLMs?: number;
  /**
   * Freeze the session when gate 7 blocks a call (`mode: 'block'`).
   * Frozen sessions refuse everything until `resetSession()`.
   * @default false
   */
  freezeOnInjectionBlock?: boolean;
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
  /**
   * Fail closed when the trail cannot be persisted: a sink that throws marks
   * the logger `degraded`, and while degraded the runtime refuses new calls
   * with `AUDIT_UNAVAILABLE` before gate 1 — no execution without a durable
   * record. The refusal record itself probes the sink, so one successful
   * write restores service automatically. Default false (best-effort).
   */
  failClosed?: boolean;
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

/** Human-in-the-loop approval policy for high-risk tools. */
export interface HitlRuntimeConfig {
  /** Gate instance holding capabilities and pending approvals. */
  gate: HitlGate;
  /**
   * Tool name → capability id. Only mapped tools pause for approval;
   * everything else executes normally.
   */
  tools: Record<string, string>;
  /**
   * Per-approval wait budget. Undecided requests expire into denials
   * (fail-closed). @default 60_000
   */
  timeoutMs?: number;
}

/**
 * Corporate forward-proxy transport for `ctx.sandbox.fetch`.
 * All fields optional — unset means "honour the standard
 * `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` environment variables".
 */
export interface ProxyConfig {
  /**
   * Explicit forward proxy, e.g. `http://user:pass@proxy.corp:3128`.
   * Scheme-less values default to `http://`. Wins over proxy env vars.
   * Credentials travel as `Proxy-Authorization` (Basic), never in the URL.
   */
  url?: string;
  /**
   * Hosts that bypass the proxy: comma-separated string or array.
   * Entries match an exact host or any subdomain, support `:port`,
   * `*.` / `.` prefixes, and `*` (bypass everything). Replaces
   * `NO_PROXY` when set.
   */
  noProxy?: string | string[];
  /** Read proxy settings from the environment. @default true */
  useEnv?: boolean;
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
  /**
   * Human-in-the-loop approvals. When set, tools mapped in
   * `hitl.tools` pause in gate 5 until approved; denials and timeouts
   * refuse with `blockedBy: 'HITL_DENIED'`.
   */
  hitl?: HitlRuntimeConfig;
  /**
   * Adaptive per-tool risk scoring: refusals raise a tool's score, clean
   * runs relax it, and (with `risk.escalateTier` + a `hitl` gate) an
   * elevated tool pauses for approval even when unmapped.
   */
  risk?: AdaptiveRiskConfig;
  /**
   * Break-glass limits (time-boxed operator override for the HITL and
   * anomaly gates; detection gates are never bypassed). Every transition
   * is appended to the audit trail.
   */
  breakGlass?: BreakGlassRuntimeConfig;
  /**
   * Corporate forward proxy for `ctx.sandbox.fetch`. Unset honours the
   * standard `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` environment variables
   * (curl-compatible); set an object for explicit control; `false` forces
   * direct egress and ignores proxy environment variables entirely.
   */
  proxy?: ProxyConfig | false;
  /** Initial agent session id. @default 'default' */
  sessionId?: string;
}

/**
 * Break-glass settings visible in `VarkConfig` — the runtime owns the
 * `onEvent` audit wiring, so users configure durations only.
 */
export type BreakGlassRuntimeConfig = Omit<BreakGlassConfig, 'onEvent'>;

/** A tool exposed to the agent, guarded by vark. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- `any` defaults are deliberate: `unknown` would break contextual inference for consumers writing `run: (args) => args.path`. Explicit type arguments still narrow.
export interface ToolDefinition<TArgs = any, TResult = any> {
  name: string;
  description: string;
  /** Standard JSON Schema (or plain object schema) describing `TArgs`. */
  schema: Record<string, unknown>;
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
  | 'LOOP_BLOCKED'
  | 'VELOCITY_EXCEEDED'
  | 'BUDGET_EXCEEDED'
  | 'DESCRIPTOR_PIN_VIOLATION'
  | 'SESSION_FROZEN'
  | 'HITL_DENIED'
  | 'ISOLATION_UNAVAILABLE'
  | 'AUDIT_UNAVAILABLE';

/** Terminal gate decision recorded in the audit trail. */
export type GateDecision =
  | 'ALLOWED'
  | 'CIRCUIT_BREAKER'
  | 'CAPABILITY_VIOLATION'
  | 'DLP_REDACTED'
  | 'INDIRECT_INJECTION'
  | 'LOOP_BLOCKED'
  | 'VELOCITY_EXCEEDED'
  | 'BUDGET_EXCEEDED'
  | 'DESCRIPTOR_PIN_VIOLATION'
  | 'SESSION_FROZEN'
  | 'HITL_DENIED'
  | 'ISOLATION_UNAVAILABLE'
  | 'AUDIT_UNAVAILABLE'
  | 'TIMEOUT'
  | 'EXECUTION_ERROR';

/** Per-call options (which agent session the call belongs to). */
export interface ExecutionOptions {
  /** Defaults to the runtime's current session (`'default'`). */
  sessionId?: string;
}

/** Outcome of a guarded tool execution. Always returned, never thrown. */
export interface ToolExecutionResult<T = unknown> {
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
