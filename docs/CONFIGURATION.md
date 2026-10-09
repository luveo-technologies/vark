# Configuration Reference

## Environment Variables

Environment variables fill in only what the programmatic `VarkConfig`
leaves unset — **explicit config wins over the environment**, and values
that fail to parse are ignored rather than throwing
(`applyEnvOverrides()`).

| Variable | Maps to | Description | Default |
|----------|---------|-------------|---------|
| `VARK_ISOLATION` | `isolation` | Requested isolation backend (`process`, `wasm`, `mock`). `wasm` warns once at first execute when true isolation can't engage. | `process` |
| `VARK_AUDIT_PATH` | CLI | Default log path for `vark audit verify\|tail\|export` when `[log]` is omitted | — |
| `VARK_AUDIT_HMAC_KEY` | `audit.hmacKey` | HMAC-SHA256 key for tamper-evident audit entries | — |
| `VARK_DLP_MODE` | `dlp.mode` | DLP mode (`redact`, `block`) | `redact` |
| `VARK_INJECTION_MODE` | `indirectInjection.mode` | Injection filter mode (`sanitize`, `block`, `flag`) | `sanitize` |
| `VARK_ANOMALY_MAX_CALLS_PER_MIN` | `anomaly.maxCallsPerMinute` | Max calls per minute per session | `30` |
| `VARK_ANOMALY_MAX_IDENTICAL_CALLS` | `anomaly.maxIdenticalCalls` | Max identical calls per session | `3` |
| `VARK_SESSION_TTL_MS` | `anomaly.sessionTTLMs` | Idle-session TTL before `sweepExpired()` evicts it | `0` (off) |
| `VARK_FREEZE_ON_INJECTION_BLOCK` | `anomaly.freezeOnInjectionBlock` | Freeze the session when gate 7 blocks (`true`/`1`/`false`/`0`) | `false` |
| `VARK_SCHEMA_STRICT` | `schema.strict` | Strict schema validation (reject instead of coerce) | `false` |
| `VARK_MAX_DECODE_DEPTH` | `circuitBreaker.maxDecodeDepth` | Recursive decode depth for encoded-payload detection | `5` |
| `VARK_STRICT_DECODE` | `circuitBreaker.strictDecode` | Refuse any argument that decodes from an explicit encoding | `false` |
| `VARK_SIEM_WEBHOOK_URL` | `vark audit tail --alert` | Webhook that alert entries are POSTed to | — |

HITL approvals, adaptive risk and canary seeding are programmatic APIs
(`VarkConfig.hitl`, `VarkConfig.risk`, the canary module) — there is no
environment toggle for them, and none exists for break-glass either: it must
be an explicit, audited `runtime.breakGlass.enable(...)` call.

## VarkConfig

```ts
interface VarkConfig {
  // Isolation
  isolation?: 'process' | 'wasm' | 'mock';
  isolationConfig?: {
    mode?: 'process' | 'wasm' | 'mock';
    memoryLimitMb?: number;       // default: 64
    allowFallback?: boolean;      // default: true
  };

  // Circuit Breaker
  circuitBreaker?: {
    blockShellInjection?: boolean;  // default: true
    blockPathTraversal?: boolean;   // default: true
    customRules?: Array<(argName: string, value: unknown) => boolean | string>;
  };

  // Capabilities
  defaultCapabilities?: {
    filesystem?: { allow?: string[] };
    network?: boolean | { allowedHosts?: string[] };
    maxExecutionMs?: number;      // default: 10_000
  };

  // DLP
  dlp?: {
    mode?: 'redact' | 'block';    // default: 'redact'
    enabled?: boolean;             // default: true
    patterns?: Array<{ type: string; pattern: RegExp }>;
  };

  // Indirect Injection
  indirectInjection?: {
    mode?: 'sanitize' | 'block' | 'flag';  // default: 'sanitize'
    enabled?: boolean;                      // default: true
    customRules?: Array<(text: string) => boolean | string>;
  };

  // Anomaly Guard
  anomaly?: {
    maxIdenticalCalls?: number;     // default: 3
    maxCallsPerMinute?: number;     // default: 30
    windowMs?: number;              // default: 60_000
    maxTotalCalls?: number;         // default: 1_000
    maxSessionTokens?: number;      // default: 250_000
    maxSessions?: number;           // default: 1_000
    sessionTTLMs?: number;          // idle-session TTL, default: 0 (off)
    freezeOnInjectionBlock?: boolean; // freeze session on gate-7 block, default: false
    enabled?: boolean;              // default: true
  };

  // Human-in-the-loop (opt-in)
  hitl?: {
    gate: HitlGate;                 // holds capabilities + pending approvals
    tools: Record<string, string>;  // tool name → capability id
    timeoutMs?: number;             // default: 60_000 (fail-closed)
  };

  // Adaptive per-tool risk (see AdaptiveRiskConfig)
  risk?: {
    tools?: Record<string, number>; // per-tool base scores, 0–100
    defaultScore?: number;          // default: 0
    blockPenalty?: number;          // per gate refusal, default: 25
    recoveryPerCleanRun?: number;   // per clean run, default: 5
    signalTtlMs?: number;           // default: 300_000
    tierThresholds?: { medium: number; high: number; critical: number };
    escalateTier?: 'low' | 'medium' | 'high' | 'critical'; // requires hitl
  };

  // Break-glass limits (audited operator override — see Break-glass)
  breakGlass?: {
    maxDurationMs?: number;         // default: 900_000 (15 min)
    defaultDurationMs?: number;     // default: 300_000 (5 min)
  };

  // Audit
  audit?: {
    hmacKey?: string | Uint8Array;
    maxEntries?: number;            // default: 10_000
    sink?: (entry: AuditEntry) => void;
    failClosed?: boolean;           // refuse calls while the sink is failing
    enabled?: boolean;              // default: true
  };

  // Schema Validation
  schema?: {
    enabled?: boolean;              // default: true
    strict?: boolean;               // default: false
    validateArgs?: boolean;         // default: true
  };

  // Session
  sessionId?: string;              // default: 'default'
}
```

## CapabilityConfig

```ts
interface CapabilityConfig {
  filesystem?: {
    allow?: string[];  // Glob or prefix grants, e.g. ['./workspace/*']
  };
  network?: boolean | {
    allowedHosts?: string[];  // Supports wildcards: '*.example.com'
  };
  maxExecutionMs?: number;  // Wall-clock budget, default: 10_000
}
```

## AuditLoggerConfig

```ts
interface AuditLoggerConfig {
  hmacKey?: string | Uint8Array;  // HMAC-SHA256 key for tamper resistance
  maxEntries?: number;            // Ring-buffer cap, default: 10_000
  sink?: (entry: AuditEntry) => void;  // Called on every append
  failClosed?: boolean;           // default: false — refuse calls while the
                                  // sink is failing (AUDIT_UNAVAILABLE)
  enabled?: boolean;              // default: true
}
```

With `failClosed: true`, a sink that throws marks the trail `degraded` and
every subsequent call is refused **before gate 1** — no execution without a
durable record. The refusal record's own append probes the sink, so the next
call proceeds automatically once a write succeeds again.

## OpenTelemetry (OTLP)

`OtlpAuditExporter` implements `AuditSink` and batches audit records to an
OTLP/HTTP collector as log records — `endpoint` (default
`http://localhost:4318/v1/logs`), `serviceName`, `headers` (collector auth),
`maxBatchSize` (default 64), `flushIntervalMs` (default 5_000; `0` = manual
`flush()` only), `includeSanitizedInputs`, `onError`, `failClosed`.

```ts
const otlp = new OtlpAuditExporter({ endpoint: 'https://otel.example.com/v1/logs' });
const runtime = new VarkRuntime({ audit: { sink: (entry) => otlp.write(entry) } });
```

## AnomalyGuardConfig

```ts
interface AnomalyGuardConfig {
  maxIdenticalCalls?: number;     // default: 3
  maxCallsPerMinute?: number;     // default: 30
  windowMs?: number;              // default: 60_000
  maxTotalCalls?: number;         // default: 1_000
  maxSessionTokens?: number;      // default: 250_000
  maxSessions?: number;           // default: 1_000
  sessionTTLMs?: number;          // idle TTL for sweepExpired(), default: 0 (off)
  freezeOnInjectionBlock?: boolean; // freeze session when gate 7 blocks, default: false
  enabled?: boolean;              // default: true
  store?: StateStore;             // default: MemoryStateStore (in-process)
}
```

## Session state store

Per-session guard state (loop counters, velocity window, budgets, freeze
flags) persists behind the `StateStore` interface using optimistic
compare-and-swap: writes carry the version they read, a conflict reloads and
re-evaluates so every call commits exactly once, and exhausted retries throw
(the runtime refuses the call with `EXECUTION_ERROR` — a broken store fails
closed).

- **`MemoryStateStore`** (default) — single-process behaviour with LRU
  eviction up to `maxSessions`.
- **`RedisStateStore`** — shared state so N replicas enforce **one**
  window instead of N copies of it. The client is injected: vark opens no
  connections, so TLS, clusters and pooling stay your client's job.

```ts
import { RedisStateStore, VarkRuntime } from '@luveo-tech/vark';
import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL!);

const runtime = new VarkRuntime({
  anomaly: {
    store: new RedisStateStore({
      client: redis,               // ioredis exposes eval() natively
      scan: (c, m, n) => redis.scan(c, 'MATCH', m, 'COUNT', n), // for sessions()/sweepExpired()
      prefix: 'vark:session',      // key namespace (default)
      ttlMs: 86_400_000,           // optional key TTL, refreshed per write
    }),
  },
});
```

node-redis users wrap `eval` once (different argument shape):

```ts
client: { eval: (script, n, ...a) => redis.eval(script, { keys: a.slice(0, n), arguments: a.slice(n) }) },
```

## HitlGate

`HitlGate` is constructed as a runtime *value* and handed to
`VarkConfig.hitl`, so quorum/webhook options belong to its constructor:

```ts
const gate = new HitlGate({
  requiredCapabilities: DEFAULT_HITL_CAPABILITIES,
  defaultTtlMs: 300_000,               // request lifetime
  autoApprove: (req) => req.capability.risk === 'low',
  quorum: {                            // approval quorum (optional)
    required: 2,                       // distinct approvers
    approvers: ['alice', 'bob'],       // whitelist; omit to allow anyone
  },
  webhook: {                           // outbound fan-out (optional)
    url: 'https://approvals.example/hitl',
    secret: process.env.HITL_WEBHOOK_SECRET, // HMAC-SHA256 → x-vark-signature: sha256=<hex>
    headers: { authorization: `Bearer ${token}` },
    timeoutMs: 5_000,
    required: false,                   // true: a delivery failure denies the request
  },
  onWebhookError: (err, request) => metrics.count('hitl_webhook_failed'),
});
```

Decision rules — every one of them fail-closed:

| Rule | Behaviour |
| --- | --- |
| Quorum | `quorum.required` **distinct** approvers must approve; one approver, one vote (a repeat vote returns `false` and is not counted) |
| Denial | A single `gate.deny(...)` vetoes regardless of quorum — approval needs consensus, refusal needs one voice |
| Timeout | Undecided requests expire into denials (`hitl.timeoutMs`, default 60 s); timers are always cleared on settle |
| Whitelist | With `quorum.approvers` configured, only listed ids may approve **or** deny |
| Webhook | A delivery failure denies only when `webhook.required: true`; otherwise the request stays pending for in-band approvers |
| Ledger | `gate.getDecisions(requestId)` returns `{ by, approved, at, reason }[]`; when quorum settles approval, `request.decidedBy` reads `alice+bob` |

Webhooks are **outbound notifications** — responders call back through your
control plane (`gate.approve(requestId, approverId)` /
`gate.deny(requestId, approverId)`; there is no built-in HTTP server).
Receivers verify the body with `verifyWebhookSignature(secret, body, header)`,
or re-derive the HMAC via `signWebhookBody(secret, body)`.

## AdaptiveRiskConfig

```ts
interface AdaptiveRiskConfig {
  tools?: Record<string, number>;   // per-tool base scores, 0–100
  defaultScore?: number;            // base for unlisted tools, default: 0
  blockPenalty?: number;            // added per gate refusal, default: 25
  recoveryPerCleanRun?: number;     // given back per clean run, default: 5
  signalTtlMs?: number;             // signal lifetime, default: 300_000
  tierThresholds?: {                // inclusive score → tier cut points
    medium: number; high: number; critical: number; // default: 25 / 50 / 75
  };
  escalateTier?: 'low' | 'medium' | 'high' | 'critical';
}
```

Score = base + live signals, **floored at the base** and capped at 100 —
history can only escalate a tool above its configured inherent risk; clean
runs walk it back down to (never below) the base, and signals expire after
`signalTtlMs`. Read it with `runtime.risk.assess(tool)` →
`{ score, tier, base, penalty, reasons }`.

`escalateTier` (requires `VarkConfig.hitl`; the runtime warns once at
construction otherwise) makes gate 4b pause any **unmapped** tool whose tier
reaches the threshold, via synthetic capability `risk:<tool>` — tools mapped
in `hitl.tools` behave exactly as before. The runtime feeds the assessor
automatically (refusals from any gate raise the score, completed calls
relax it); integrators can also call `runtime.risk.recordBlock(tool, reason)`,
`recordCleanRun(tool)` or `reset(tool?)` directly.

## Break-glass

A deliberate, time-boxed operator override for when Vark's *operational*
gates are what's taking production down (approver rota offline, a session
frozen by a bad config, an incident where a human has decided the agent must
proceed). Activation is programmatic, per-runtime and fully audited — by
design there is no environment variable or config flag that silently
enables it.

```ts
runtime.breakGlass.enable({
  reason: 'incident-42: approver rota offline', // required, audited verbatim
  by: 'oncall-1',                                // required, audited
  scopes: ['anomaly', 'hitl'],                   // default: both
  durationMs: 600_000,                           // default 300_000, clamped to maxDurationMs
});
```

| Scope | What it bypasses |
| --- | --- |
| `'anomaly'` | Gate 1: frozen/halted sessions and loop/velocity/budget refusals resume executing — counters keep recording, so the trail still shows what the session did |
| `'hitl'` | Gate 5: approval waits for mapped **and** risk-escalated tools |

Contract:

- `VarkConfig.breakGlass` tunes `defaultDurationMs` (default 5 min) and
  `maxDurationMs` (default 15 min); longer requests are clamped, not rejected.
- Enabling while one is active, missing `reason`/`by`, unknown scopes and
  non-positive durations **throw**. `disable()` ends it early (returns the
  session), expiry runs on an `unref`'d timer, and `status()` reports
  `remainingMs`.
- Detection gates are **never** bypassed: capability sandbox, circuit
  breaker, schema validation, DLP, injection filter, execution timeout and
  audit durability stay armed.
- Audit: every transition is appended as its own entry
  (`sessionId: 'break-glass'`, findings `BREAK_GLASS_ENABLED` /
  `BREAK_GLASS_DISABLED` / `BREAK_GLASS_EXPIRED`), and each call executed
  under the override carries a `BREAK_GLASS` finding in its own record.

## DlpConfig

```ts
interface DlpConfig {
  mode?: 'redact' | 'block';    // default: 'redact'
  enabled?: boolean;             // default: true
  patterns?: ReadonlyArray<{ type: string; pattern: RegExp }>;
}
```

## IndirectInjectionConfig

```ts
interface IndirectInjectionConfig {
  mode?: 'sanitize' | 'block' | 'flag';  // default: 'sanitize'
  enabled?: boolean;                      // default: true
  customRules?: ReadonlyArray<(text: string) => boolean | string>;
}
```

## SchemaValidationConfig

```ts
interface SchemaValidationConfig {
  enabled?: boolean;              // default: true
  strict?: boolean;               // default: false (coerce types)
  validateArgs?: boolean;         // default: true
}
```

## IsolationConfig

```ts
interface IsolationConfig {
  mode?: 'process' | 'wasm' | 'mock';  // default: 'process'
  memoryLimitMb?: number;             // default: 64
  allowFallback?: boolean;             // default: true
}
```

> **Honesty note.** The guard pipeline (gate 5) always executes `run()`
> in-process — with the capability sandbox and a wall-clock timeout —
> because tool closures need module scope and `ctx.sandbox` carries live
> functions that cannot cross an isolate boundary. `isolation: 'wasm'`
> controls the *standalone* isolate APIs (`executeInSandbox()`,
> `executeIsolated()`, `resolveIsolationMode()`); when the runtime is
> configured with `'wasm'` it warns **once** at the first `execute()`
> stating exactly this, and `resolveIsolationMode()` reports any fallback
> from true isolation. Nothing degrades silently.
>
> With `allowFallback: false` the fallback becomes a **refusal**: while
> `isolated-vm` is unavailable, every `execute()` returns
> `blockedBy: 'ISOLATION_UNAVAILABLE'` (fail-closed on dependency loss), and
> `executeInSandbox(..., { allowFallback: false })` refuses any run that did
> not get the true isolate boundary — even a fallback run that would
> otherwise have succeeded.

## QuotaConfig

```ts
interface QuotaConfig {
  maxCpuTimeMs?: number;          // default: 5_000
  maxMemoryBytes?: number;        // default: 268_435_456 (256 MB)
  maxSubprocesses?: number;       // default: 0
  maxFileDescriptors?: number;    // default: 32
  maxOutputBytes?: number;        // default: 1_048_576 (1 MB)
}
```

## EgressConfig

```ts
interface EgressConfig {
  rules: EgressRule[];
  defaultPolicy?: 'allow' | 'deny';  // default: 'deny'
  enforceMtls?: boolean;              // default: false
  pinDns?: boolean;                   // default: false
  dnsResolver?: (hostname: string) => Promise<string>;
}
```

## SiemConfig

```ts
interface SiemConfig {
  webhookUrl?: string;
  grpcEndpoint?: string;
  authToken?: string;
  maxEventsPerSecond?: number;   // default: 100
  maxQueueSize?: number;         // default: 10_000
  batchSize?: number;            // default: 50
  flushIntervalMs?: number;      // default: 1_000
  customSender?: (events: SiemEvent[]) => Promise<void>;
}
```

## Complete Example

```ts
import { VarkRuntime } from '@luveo-tech/vark';

const runtime = new VarkRuntime({
  isolation: 'wasm',
  isolationConfig: {
    memoryLimitMb: 64,
    allowFallback: true,
  },
  circuitBreaker: {
    blockShellInjection: true,
    blockPathTraversal: true,
    customRules: [
      (argName, value) =>
        argName === 'method' && value === 'DELETE'
          ? 'DELETE method is not permitted'
          : false,
    ],
  },
  defaultCapabilities: {
    filesystem: { allow: ['./workspace/*'] },
    network: { allowedHosts: ['api.example.com', '*.example.com'] },
    maxExecutionMs: 5_000,
  },
  dlp: {
    mode: 'redact',
    patterns: [{ type: 'INTERNAL_ID', pattern: /\bACME-\d{6}\b/g }],
  },
  indirectInjection: {
    mode: 'sanitize',
  },
  anomaly: {
    maxIdenticalCalls: 3,
    maxCallsPerMinute: 30,
    windowMs: 60_000,
    maxTotalCalls: 1_000,
    maxSessionTokens: 250_000,
  },
  audit: {
    hmacKey: process.env.VARK_AUDIT_HMAC_KEY,
    maxEntries: 10_000,
    sink: (entry) => appendFileSync('audit.jsonl', JSON.stringify(entry) + '\n'),
  },
  schema: {
    enabled: true,
    strict: false,
    validateArgs: true,
  },
  sessionId: 'agent-1',
});
```
