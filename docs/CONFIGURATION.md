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

HITL approvals and canary seeding are programmatic APIs (`VarkConfig.hitl`,
the canary module) — there is no environment toggle for them.

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
}
```

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
