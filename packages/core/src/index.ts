/**
 * `@saturn/vark` — zero-trust security runtime for AI agent tool calls.
 *
 * @example
 * ```ts
 * import { VarkRuntime } from '@saturn/vark';
 *
 * const runtime = new VarkRuntime({
 *   defaultCapabilities: { filesystem: { allow: ['./workspace/*'] } },
 * });
 *
 * const read = runtime.tool({
 *   name: 'read_file',
 *   description: 'Read a UTF-8 text file.',
 *   schema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] },
 *   run: (_args, ctx) => ctx.sandbox.readFile(_args.path),
 * });
 *
 * await read.execute({ path: '../../etc/passwd' }); // → CAPABILITY_VIOLATION
 * ```
 */

export { VarkRuntime, DEFAULT_SESSION } from './runtime.js';
export type { ResolvedVarkConfig, WrappedTool } from './runtime.js';

export { benchmarkInspection, inspect, inspectPayload } from './circuit-breaker.js';
export type { InspectionBenchmark } from './circuit-breaker.js';

export { analyzeCompression, compressSchema, estimateTokens } from './compressor.js';
export type { CompressionReport } from './compressor.js';

export { redactText, redactValue, scanSecrets } from './dlp.js';
export type { DlpMatch, DlpScanResult, DlpValueResult } from './dlp.js';

export {
  scanValueSync,
  scanValueAsync,
  redactBuffer,
  extractTextSurfaces,
} from './dlp-extended.js';
export type { ExtendedDlpResult } from './dlp-extended.js';

export {
  FileAuditSink,
  StreamAuditSink,
  MultiAuditSink,
  createDefaultAuditSink,
} from './audit-sink.js';
export type { AuditSink, AuditSinkOptions } from './audit-sink.js';

export {
  executeIsolated,
  isTrueIsolationAvailable,
  resolveIsolationMode,
  DEFAULT_ISOLATE_MEMORY_LIMIT_MB,
} from './isolated-vm.js';
export type { IsolateConfig, IsolateResult } from './isolated-vm.js';

export { validateSchema, coerceValue } from './schema-validator.js';
export type { SchemaValidationResult } from './schema-validator.js';

// ── Enterprise security modules ─────────────────────────────────────────────
export * from './security/sandbox/index.js';
export * from './security/vfs/index.js';
export * from './security/quotas/index.js';
export * from './security/injection/index.js';
export * from './security/canary/index.js';
export * from './security/reflection/index.js';
export * from './security/pii/index.js';
export * from './security/flow/index.js';
export * from './security/credentials/index.js';
export * from './security/egress/index.js';
export * from './security/audit/index.js';
export * from './security/replay/index.js';
export * from './security/telemetry/index.js';

export { INJECTION_MARKER, sanitizeIndirectInjection, scanIndirectInjection } from './indirect-injection.js';
export type {
  InjectionFinding,
  InjectionScanResult,
  InjectionValueResult,
} from './indirect-injection.js';

export { AnomalyGuard, callFingerprint } from './anomaly-guard.js';
export type { AnomalySessionStats, AnomalyVerdict } from './anomaly-guard.js';

export { AuditLogger, GENESIS_HASH, stableStringify } from './audit-logger.js';
export type { AuditAppendInput, AuditVerifyResult } from './audit-logger.js';

export {
  DEFAULT_MAX_EXECUTION_MS,
  assertNetworkAllowed,
  assertPathAllowed,
  checkHostAllowed,
  checkPathAllowed,
  createSandbox,
  inspectArguments,
  normalizePath,
  withTimeout,
} from './sandbox.js';

export {
  CapabilityViolationError,
  CircuitBreakerError,
  VarkError,
  VarkTimeoutError,
} from './types.js';

export type {
  AnomalyGuardConfig,
  AuditEntry,
  AuditLoggerConfig,
  BlockedBy,
  CapabilityConfig,
  CircuitBreakerConfig,
  DlpConfig,
  ExecutionOptions,
  ExecutionContext,
  GateDecision,
  GuardResult,
  IndirectInjectionConfig,
  InspectionResult,
  IsolationMode,
  ToolDefinition,
  ToolExecutionResult,
  VarkConfig,
} from './types.js';
