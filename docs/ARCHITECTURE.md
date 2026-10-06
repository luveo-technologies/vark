# Architecture

## High-Level Overview

`@luveo-tech/vark` is a zero-trust security runtime and firewall for AI agent tool calls. It sits between the LLM/agent loop and your tools, enforcing an 8-gate security pipeline on every tool invocation.

```
   LLM / agent loop
        │  tool call (name + args)
        ▼
   ┌────────────────────────── @luveo-tech/vark ───────────────────────────┐
   │  1 anomaly → 2 sandbox → 3 breaker → 4 in-DLP → 5 exec           │
   │  → 6 out-DLP → 7 injection filter → 8 audit                       │
   └────────────────────────────────────────────────────────────────────┘
        │  ToolExecutionResult  (always — never a throw)
        ▼
   your tool body → sanitised result → back to the model
```

## The 8-Gate Lifecycle

Every tool call flows through these gates in exact order:

| Gate | Name | Purpose | Refusal |
|------|------|---------|---------|
| 1 | Anomaly Guard | Session velocity, loop detection, budgets | `LOOP_BLOCKED` |
| 2 | Capability Sandbox | Path & host authorisation | `CAPABILITY_VIOLATION` |
| 3 | Circuit Breaker | Shell injection, path traversal | `CIRCUIT_BREAKER` |
| 3b | Schema Validation | JSON Schema enforcement | `EXECUTION_ERROR` |
| 4 | Input DLP | Secret redaction from arguments | `DLP_REDACTED` |
| 5 | Isolated Execution | `run()` with timeout + sandbox | `TIMEOUT` / `EXECUTION_ERROR` |
| 6 | Output DLP | Secret redaction from return value | `DLP_REDACTED` |
| 7 | Injection Filter | Indirect prompt injection defense | `INDIRECT_INJECTION` |
| 8 | Audit Logger | Hash-chained telemetry | — |

### Why This Order

1. **Anomaly guard first** — cheapest gate, stops runaway agents before any downstream budget is spent.
2. **Authorisation before detection** — `CAPABILITY_VIOLATION` is a precise policy answer; `CIRCUIT_BREAKER` is a signature answer.
3. **Detection before redaction** — the breaker inspects the raw payload; redaction could mask injection syntax.
4. **Redaction before execution** — `run()` must never receive credentials.
5. **Redaction before re-entry** — secrets must not leak through injection findings.
6. **Audit last** — records the terminal decision for every path.

## Thread Isolation Model

Vark is designed for single-threaded Node.js event loop execution. Each `VarkRuntime` instance maintains its own:

- **Tool registry** — `Map<string, WrappedTool>` with merged capabilities
- **Audit trail** — hash-chained, append-only, in-memory with optional persistent sink
- **Anomaly state** — per-session loop/velocity counters with LRU eviction
- **Schema cache** — compiled JSON Schema validators per tool

For multi-threaded deployments, run one `VarkRuntime` per worker thread. The runtime is not designed to be shared across threads.

## Module Structure

```
packages/core/src/
├── runtime.ts               # 8-gate pipeline (VarkRuntime)
├── circuit-breaker.ts       # Sub-ms payload firewall + benchmark
├── sandbox.ts               # Capability grants, glob/allowlist, timeout
├── dlp.ts                   # Secret scanners + redaction
├── dlp-extended.ts          # Non-plain object DLP (Buffer, streams, classes)
├── indirect-injection.ts    # Prompt injection detectors
├── anomaly-guard.ts         # Session loops / velocity / budgets
├── audit-logger.ts          # Hash-chained append-only telemetry
├── audit-sink.ts            # Pluggable persistent audit sinks
├── compressor.ts            # Compact Tool Protocol (CTP)
├── isolated-vm.ts           # True WASM/sandbox isolation
├── schema-validator.ts      # JSON Schema validation gate
├── types.ts                 # All public interfaces + errors
├── index.ts                 # Public export surface
├── gates/
│   └── hitl-gate.ts         # Human-in-the-loop approval gate
└── security/
    ├── sandbox/             # Isolated-VM / QuickJS sandbox
    ├── vfs/                 # Ephemeral virtual filesystem
    ├── quotas/              # Subprocess & resource quotas
    ├── injection/           # Semantic & embedding injection detector
    ├── canary/              # Honeytoken trap
    ├── reflection/          # Entropy & reflection scanner
    ├── pii/                 # Reversible PII anonymization
    ├── flow/                # Stateful DAG flow enforcement
    ├── credentials/         # Zero-trust ephemeral credential injection
    ├── egress/              # Outbound egress proxy & domain pinning
    ├── audit/               # Asymmetric KMS audit signing
    ├── replay/              # Deterministic replay engine
    └── telemetry/           # SIEM telemetry broadcaster
```

## Data Flow

```
Tool Call
    │
    ▼
┌─────────────────┐
│  Anomaly Guard  │──session state──▶ AnomalyGuard
└────────┬────────┘
         │ safe
         ▼
┌─────────────────┐
│ Capability      │──grants──▶ CapabilityConfig
│ Sandbox         │
└────────┬────────┘
         │ allowed
         ▼
┌─────────────────┐
│ Circuit Breaker │──patterns──▶ SHELL_PATTERNS, PATH_PATTERNS
└────────┬────────┘
         │ safe
         ▼
┌─────────────────┐
│ Schema Gate     │──schema──▶ ToolDefinition.schema
└────────┬────────┘
         │ valid
         ▼
┌─────────────────┐
│ Input DLP       │──scanners──▶ BUILT_IN_PATTERNS
└────────┬────────┘
         │ redacted
         ▼
┌─────────────────┐
│ Execution       │──sandbox──▶ ExecutionContext
│ (isolated)      │
└────────┬────────┘
         │ result
         ▼
┌─────────────────┐
│ Output DLP      │──scanners──▶ BUILT_IN_PATTERNS
└────────┬────────┘
         │ redacted
         ▼
┌─────────────────┐
│ Injection       │──detectors──▶ PATTERNS
│ Filter          │
└────────┬────────┘
         │ sanitised
         ▼
┌─────────────────┐
│ Audit Logger    │──hash chain──▶ AuditEntry[]
└────────┬────────┘
         │
         ▼
ToolExecutionResult
```

## Isolation Modes

| Mode | Behavior | Memory Ceiling |
|------|----------|----------------|
| `'process'` | In-process execution (default) | None |
| `'wasm'` | True isolated V8 context via `isolated-vm` | 64 MB (configurable) |
| `'mock'` | Mock execution for testing | None |

When `isolated-vm` is not installed, `'wasm'` falls back to `'process'` with a warning. Set `isolation.allowFallback: false` to refuse execution instead.

## Performance Characteristics

| Metric | Value |
|--------|-------|
| Circuit breaker p50 | 0.0016 ms |
| Circuit breaker p99 | 0.0079 ms |
| DLP scan (350 B) | 0.015 ms |
| Injection scan (350 B) | 0.038 ms |
| Audit append | ~0.01 ms |
| Memory per session | ~2 KB |
| Memory per audit entry | ~500 B |
