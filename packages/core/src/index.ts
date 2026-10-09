/**
 * `@luveo-tech/vark` — zero-trust security runtime for AI agent tool calls.
 *
 * @example
 * ```ts
 * import { VarkRuntime } from '@luveo-tech/vark';
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

export {
  redactText,
  redactValue,
  scanSecrets,
  luhnCheck,
  shannonEntropy,
  HIGH_ENTROPY_THRESHOLD,
  HIGH_ENTROPY_MIN_LENGTH,
} from './dlp.js';
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
export { OtlpAuditExporter, toOtlpLogRecord, DEFAULT_OTLP_LOGS_ENDPOINT } from './otlp-exporter.js';
export type { OtlpExporterOptions, OtlpLogRecord, OtlpAttribute } from './otlp-exporter.js';
export { MemoryStateStore } from './state-store.js';
export type { StateStore, SessionRecord, LoadedSession } from './state-store.js';
export { RedisStateStore } from './redis-state-store.js';
export type { RedisStateStoreOptions, RedisEvalClient } from './redis-state-store.js';
export {
  signPolicy,
  verifyPolicy,
  generatePolicyKeyPair,
  hashPolicy,
  policyKeyId,
  POLICY_SIGNATURE_ALG,
} from './policy-signature.js';
export type { PolicySignature, VerifyResult } from './policy-signature.js';
export { diffPolicy } from './policy-diff.js';
export type { PolicyDiffEntry } from './policy-diff.js';
export { AdaptiveRiskAssessor, tierForScore, tierAtLeast } from './adaptive-risk.js';
export type { AdaptiveRiskConfig, RiskTier, RiskSignal, RiskAssessment } from './adaptive-risk.js';
export { BreakGlassManager } from './break-glass.js';
export type {
  BreakGlassConfig,
  BreakGlassScope,
  BreakGlassEventType,
  BreakGlassEvent,
  BreakGlassEnableOptions,
  BreakGlassSession,
  BreakGlassStatus,
} from './break-glass.js';

export {
  executeIsolated,
  isTrueIsolationAvailable,
  resolveIsolationMode,
  DEFAULT_ISOLATE_MEMORY_LIMIT_MB,
} from './isolated-vm.js';
export type { IsolateConfig, IsolateResult } from './isolated-vm.js';

export { validateSchema, coerceValue, coerceValueDeep } from './schema-validator.js';
export { applyEnvOverrides } from './env-config.js';
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
export * from './security/sanitization/index.js';
export * from './security/network/index.js';
export * from './security/paths/index.js';
export * from './security/shell/index.js';
export * from './gates/index.js';

export { INJECTION_MARKER, sanitizeIndirectInjection, scanIndirectInjection } from './indirect-injection.js';
export type {
  InjectionFinding,
  InjectionScanResult,
  InjectionValueResult,
} from './indirect-injection.js';

export { AnomalyGuard, callFingerprint } from './anomaly-guard.js';
export type { AnomalySessionStats, AnomalyVerdict, AnomalyCause } from './anomaly-guard.js';

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
  BreakGlassRuntimeConfig,
  CapabilityConfig,
  CircuitBreakerConfig,
  DlpConfig,
  ExecutionOptions,
  ExecutionContext,
  GateDecision,
  GuardResult,
  HitlRuntimeConfig,
  IndirectInjectionConfig,
  InspectionResult,
  IsolationMode,
  SchemaValidationConfig,
  ToolDefinition,
  ToolExecutionResult,
  VarkConfig,
} from './types.js';
