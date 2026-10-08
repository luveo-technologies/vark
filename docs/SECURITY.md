# Security Model

## Threat Matrix

| Threat | Gate | Mitigation |
|--------|------|------------|
| Command injection (`;`, `&&`, pipes) | 3: Circuit Breaker | Pre-compiled regex patterns, sub-ms inspection |
| Path traversal (`../`, `/etc/passwd`) | 2: Capability Sandbox | Glob/prefix grants, `path.resolve` normalization |
| Shell injection (`curl \| sh`, `eval(`) | 3: Circuit Breaker | 12 shell pattern detectors |
| Credential leakage | 4/6: DLP | 10 secret scanners, `[REDACTED_SECRET: TYPE]` |
| Indirect prompt injection | 7: Injection Filter | 7 payload detectors, sanitize/block/flag |
| Infinite loops | 1: Anomaly Guard | Identical-call fingerprinting, session halt |
| Velocity attacks | 1: Anomaly Guard | Sliding-window rate limiting |
| Token budget exhaustion | 1: Anomaly Guard | Per-session token budget |
| Schema manipulation | 3b: Schema Gate | JSON Schema validation with coercion |
| Context reflection | 7: Entropy Scanner | Entropy + similarity analysis |
| Prompt leaking | 7: Entropy Scanner | System context similarity scoring |
| PII exposure | 7: PII Anonymizer | Deterministic token replacement |
| SSRF | 2: Egress Proxy | Domain allowlist, DNS pinning |
| Data exfiltration | 7: Canary/Honeytoken | Session-bound trap tokens |
| Unauthorized high-risk ops | HITL Gate | Human approval for critical capabilities |
| Skipped verification steps | DAG Enforcer | Dependency graph enforcement |
| Long-lived credential theft | Credential Manager | Ephemeral tokens, immediate scrubbing |
| Audit tampering | 8: Audit Logger | SHA-256 hash chain, optional Ed25519 signing |

## Sandboxing Guarantees

### Capability Sandbox (Gate 2)

- **Filesystem**: Glob and prefix grants resolved against `process.cwd()`. `../` physically escapes grants.
- **Network**: Allowlist with wildcard support (`*.example.com`). Empty allowlist = deny.
- **Defense in depth**: `ctx.sandbox.readFile()` and `ctx.sandbox.fetch()` re-check grants at point of use.

### Isolated Execution (Gate 5)

- **True isolation**: `isolated-vm` provides a separate V8 heap with configurable memory ceiling (default 64 MB).
- **Timeout**: `Promise.race` against wall-clock budget (default 10,000 ms).
- **Fallback**: When `isolated-vm` is unavailable, falls back to `'process'` mode (configurable).

### Ephemeral Virtual Filesystem

- **Copy-on-write**: Writes are captured in memory, reads fall through to host FS.
- **Rollback**: All in-memory writes discarded on session termination or error.
- **Commit**: Optional flush to host FS for persistent changes.

### Resource Quotas

- **CPU time**: Per-execution limit (default 5,000 ms).
- **Memory**: Per-execution limit (default 256 MB).
- **Subprocesses**: Configurable limit (default 0 = no subprocesses).
- **File descriptors**: Configurable limit (default 32).
- **Output size**: Configurable limit (default 1 MB).

## DLP Policies

### Built-in Scanners (Priority Order)

| # | Type | Pattern |
|---|------|---------|
| 1 | `PRIVATE_KEY` | `-----BEGIN ... PRIVATE KEY-----` |
| 2 | `ANTHROPIC_KEY` | `sk-ant-...` |
| 3 | `OPENAI_KEY` | `sk-...` (≥20 chars) |
| 4 | `AWS_KEY` | `AKIA...` / `ASIA...` |
| 5 | `JWT` | `eyJ...` |
| 6 | `GITHUB_TOKEN` | `ghp_` / `gho_` / etc. |
| 7 | `SLACK_TOKEN` | `xox...` |
| 8 | `STRIPE_KEY` | `sk_live_...` / `rk_test_...` |
| 9 | `BEARER_TOKEN` | `Authorization: Bearer ...` |
| 10 | `ENV_CREDENTIAL` | `API_KEY=` / `SECRET=` / etc. |

### Redaction Modes

- **`redact`** (default): Replace secrets with `[REDACTED_SECRET: TYPE]`, continue execution.
- **`block`**: Refuse the call with `blockedBy: 'DLP_REDACTED'`.

### Non-Plain Object Support

The extended DLP scanner (`dlp-extended.ts`) handles:
- `Buffer` — decoded as UTF-8, capped at 1 MB
- `ReadableStream` — first chunk peeked without consuming
- Class instances — own enumerable properties + `toString()` output
- `Date`, `Error` — ISO string / name + message

## Audit Trail Integrity

### Hash Chain

```
hash(n) = SHA-256( stableStringify( record[n] + prevHash ) )
```

- Genesis `prevHash` = 64 zeros
- Records are `Object.freeze`d — no mutation API
- `verify()` recomputes the entire chain and reports the first broken `seq`

### Asymmetric Signing (KMS)

- Ed25519 signatures for tamper-proof public verification
- Private key signs each entry; public key distributed to verifiers
- Key rotation supported via `keyId` field

### Persistent Sinks

- **FileAuditSink**: Append-only JSON Lines to a file
- **StreamAuditSink**: Any Node writable stream
- **MultiAuditSink**: Fan-out to multiple sinks with error isolation

All sinks swallow persistence errors by default (best-effort). Constructed
with `failClosed: true` they surface failures to the caller — pair with
`audit.failClosed` on the runtime so an unpersistable trail refuses new
calls (`AUDIT_UNAVAILABLE`) until a write succeeds again.

## Security Guarantees

| # | Guarantee |
|---|-----------|
| G1 | No escape from the pipeline — all 8 gates run in order |
| G2 | No throws at the call site — always resolves with `ToolExecutionResult` |
| G3 | Secrets never reach the model, tool, or log |
| G4 | Refusals are attributable — `blockedBy` + `error` + audit record |
| G5 | Audit trail is append-only and hash-chained |
| G6 | Authorisation re-checked at point of use |
| G7 | Guard never crashes the host — no `process.exit()` |
| G8 | Deterministic limits — enforced by code, not model cooperation |
