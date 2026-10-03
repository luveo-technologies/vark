# Configuration Reference

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VARK_ISOLATION` | Isolation mode (`process`, `wasm`, `mock`) | `process` |
| `VARK_ISOLATION_MEMORY_MB` | Memory ceiling for isolated execution | `64` |
| `VARK_AUDIT_PATH` | Path for persistent audit log | — |
| `VARK_AUDIT_HMAC_KEY` | HMAC key for audit signing | — |
| `VARK_DLP_MODE` | DLP mode (`redact`, `block`) | `redact` |
| `VARK_INJECTION_MODE` | Injection filter mode (`sanitize`, `block`, `flag`) | `sanitize` |
| `VARK_ANOMALY_MAX_CALLS_PER_MIN` | Max calls per minute per session | `30` |
| `VARK_ANOMALY_MAX_IDENTICAL_CALLS` | Max identical calls per session | `3` |
| `VARK_SCHEMA_STRICT` | Strict schema validation (no coercion) | `false` |
| `VARK_HITL_ENABLED` | Enable HITL gate | `false` |
| `VARK_CANARY_ENABLED` | Enable honeytoken seeding | `false` |
| `VARK_SIEM_WEBHOOK_URL` | SIEM webhook URL | — |
| `VARK_SIEM_AUTH_TOKEN` | SIEM authentication token | — |

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
    enabled?: boolean;              // default: true
  };

  // Audit
  audit?: {
    hmacKey?: string | Uint8Array;
    maxEntries?: number;            // default: 10_000
    sink?: (entry: AuditEntry) => void;
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
  enabled?: boolean;              // default: true
}
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
import { VarkRuntime } from '@saturn/vark';

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
