# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0-beta.2] - 2026-10-08

Second prerelease cut, incorporating the next adversarial-eval round plus CI
workflow fixes. Same promotion path as `0.2.0-beta.1`: on sign-off this
content ships as `0.2.0` (stable dist-tag); only the version/tag changes.

### Added

- **Wrapper-aware decode parity (P1):** the runtime's strict decoder now
  sees what `vark scan` sees — markup wrappers (`<html>…</html>`) are
  stripped into their own scannable variant, and hex/base64 runs embedded
  inside any string are extracted (same printability + depth discipline).
  Payloads smuggled through wrappers no longer pass the runtime while the
  CLI blocks them; decode provenance includes `html-strip`.
- **`circuitBreaker.maxDecodeDepth` + `circuitBreaker.strictDecode` (P2):**
  the decode-depth cap is now configurable (default still 5) and
  `strictDecode: true` refuses any argument that decodes from an explicit
  encoding instead of scanning it. Env equivalents `VARK_MAX_DECODE_DEPTH`
  and `VARK_STRICT_DECODE`.
- **Baseline SSRF policy on `ctx.sandbox.fetch`:** cloud-metadata endpoints,
  private/loopback/link-local ranges, `localhost` names, embedded
  credentials, and non-http(s) schemes are refused in every capability mode
  — including unrestricted egress — with pre-fetch DNS verification
  (fail-closed) and per-hop redirect revalidation, so a 302 can never reach
  a target the original URL could not. `network.allowPrivate` opts in to
  local-dev targets (metadata stays blocked regardless).
- **DLP decode parity:** argument strings are scanned through the same
  strict decoder, so a base64-wrapped AWS key or credit card is redacted /
  blocked exactly as `vark scan` reports it (the carrier string itself is
  replaced wholesale).
- **`VarkMCPAdapter.reconcile()`:** feed freshly fetched `tools/list`
  results back into the adapter. A server that re-lists a *changed*
  descriptor — the real schema rug pull, invisible to the wrap-time
  in-place pin — is permanently refused with `DESCRIPTOR_PIN_VIOLATION`
  and audited once; `clear()` releases recorded violations so a deliberate
  re-wrap re-establishes trust.

### Fixed

- Duplicate `export *` statements in the root barrel (spurious duplicate
  symbols in `index.d.ts`).
- OpenSSF Scorecard workflow referenced the nonexistent
  `ossf/scorecard-action@v2` tag — pinned to the `v2.4.4` commit.
- Node 20 glob expansion for `vark check` (fallout from the Node-22-only
  `fs.promises.glob`).
- Install docs (README + EVAL) now carry the stale-shim hint for npm's
  `EEXIST …/npm/vark` global-install failure
  (`npm install -g --force @luveo-tech/vark`).

### Changed

- New 39-test regression suite: decode-parity corpus (runtime verdict
  matches CLI verdict per payload), depth/strict configuration, SSRF
  defaults incl. redirect revalidation, DLP encoded carriers, descriptor-pin
  lifecycle, sanitizer fixpoint, and normalization idempotency.

## [0.2.0-beta.1] - 2026-10-08

Prerelease cut of the 0.2.0 line for adversarial evaluation — tagged
`v0.2.0-beta.1` so a defect found during eval can't squat the final `0.2.0`
version on npm. On sign-off the same content ships as `0.2.0` (stable
dist-tag); only the version/tag changes.

Major security update driven by an adversarial eval against 0.1.2. All three
P1 blockers are fixed; the P2 gaps are closed.

### Added

- **Encoded-payload decoding in the runtime circuit breaker (P1):** a third
  pass scans strictly-decoded variants of every string argument —
  percent-encoding, HTML entities, hex, base64, and nested chains
  (`base64→hex→…`, depth-capped) — with decode provenance in the refusal
  reason (`(decoded base64→hex)`). Only strings with explicit encoding
  markers are decoded and only text-like results are scanned, so opaque
  tokens (git SHAs, UUIDs, session ids) can never trip the gate.
  `decodeEncodedLayers()` is exported for direct use.
- **MCP descriptor pinning (P1):** `wrapTools()` pins a SHA-256 of
  `{ name, description, inputSchema }`; every `check()`/`execute()`
  recomputes it. A mutated descriptor (MCP "rug pull") is refused with the
  new `DESCRIPTOR_PIN_VIOLATION` code and audited. `hashDescriptor()` is
  exported.
- **HITL gate wired into the runtime:** `VarkConfig.hitl` maps tool names
  to capabilities; mapped tools pause in gate 5 until approved. Denials and
  timeouts fail closed with `blockedBy: 'HITL_DENIED'` (configurable
  `timeoutMs`, default 60 s; pending timers always cleared).
- **Session freeze:** `runtime.freezeSession()` / `AnomalyGuard.freeze()`
  administratively lock a session (`SESSION_FROZEN` until reset), opt-in
  `anomaly.freezeOnInjectionBlock` locks the session when gate 7 blocks,
  `unfreeze()` lifts the lock without wiping counters, and
  `anomaly.sessionTTLMs` + `sweepExpired()` evict idle sessions (halted and
  frozen sessions are retained).
- **Machine-readable quota codes:** `QuotaCheckResult.code` —
  `QUOTA_CPU_TIME`, `QUOTA_MEMORY`, `QUOTA_SUBPROCESS`,
  `QUOTA_FILE_DESCRIPTORS`, `QUOTA_OUTPUT`.
- **DLP coverage:** Luhn-validated `CREDIT_CARD` numbers, `SSN` shape, and a
  `HIGH_ENTROPY_SECRET` Shannon-entropy heuristic (≥ 4.5 bits/char over
  ≥ 32 chars). `luhnCheck()`, `shannonEntropy()` and
  `HIGH_ENTROPY_THRESHOLD` are exported. New `MD_IMAGE_EXFIL` detector
  flags markdown-image beacons with long query payloads.
- **Recursive schema coercion:** `coerceValueDeep()` walks object properties
  and array items (copy-on-write); the runtime gate now actually coerces
  nested values like `{ n: '42' }` → `{ n: 42 }`.
- **Per-gate benchmark rows** in `vark bench` — anomaly, capability,
  breaker, schema, input-dlp, output-dlp+injection and audit each report
  avg/p50/p99/max.
- **`vark audit tail --alert [--webhook <url>]`** prints a loud alert line
  for security refusals and optionally POSTs them to a webhook
  (`$VARK_SIEM_WEBHOOK_URL` default). `isAlertable()` / `emitAlert()` exported.
- **`vark audit export --format ndjson`** (one JSON object per line) and a
  full-field CSV (now includes `reason`, `findings`, `prevHash`,
  `sanitizedInputs`, and untruncated hashes).
- **Environment configuration:** `applyEnvOverrides()` / `VARK_*` variables
  (`VARK_ISOLATION`, `VARK_DLP_MODE`, `VARK_INJECTION_MODE`,
  `VARK_ANOMALY_*`, `VARK_SESSION_TTL_MS`,
  `VARK_FREEZE_ON_INJECTION_BLOCK`, `VARK_SCHEMA_STRICT`,
  `VARK_AUDIT_HMAC_KEY`) fill only what the programmatic config left unset.
  `vark audit …` commands accept an optional `[log]` defaulting to
  `$VARK_AUDIT_PATH`.
- **Public exports for previously internal modules:** normalizer
  (`normalizeInput`, `decodeEncodedLayers`, …), SSRF guard, path security,
  shell security, and the HITL gate (`HitlGate`,
  `DEFAULT_HITL_CAPABILITIES`) are importable from the package root.
- npm `keywords` and sharper package descriptions so `@luveo-tech/vark`
  (the security runtime) is what npm search surfaces for "vark".

### Fixed

- **ESM sandbox crash (P1):** `executeInSandbox()` / the `node:vm` fallback
  used `require()` and threw `ReferenceError: Cannot determine intended
  module format` under ESM. `node:vm` and `node:fs` are now static imports
  (`isolated-vm.ts`, `path-security.ts`).
- **Silent isolation downgrade:** `resolveIsolationMode('wasm')` without
  `isolated-vm` installed now returns an explicit `warning` describing the
  in-process fallback instead of degrading silently.
- `coerceValue()` docstring no longer overclaims (single-level; use
  `coerceValueDeep()` for recursion).
- `preserve-caught-error`: parse failures in `vark check` / `vark policy`
  now attach `{ cause }`.

### Changed

- **BREAKING (minor):** `ToolExecutionResult<T>` now defaults to `unknown`
  (was `any`); `MCPToolLike.inputSchema`/`WrappedMCPTool.inputSchema` are
  `Record<string, unknown>`; `wrapTools()` accepts `unknown[]`;
  `MCPExecutor` receives `args: Record<string, unknown>`. `ToolDefinition`
  and `WrappedTool` keep their `any` generic defaults (consumer inference).
- `AnomalyGuardConfig` gained `sessionTTLMs` and `freezeOnInjectionBlock`;
  `AnomalyCause` gained `'frozen'`.
- ESLint (flat config, recommended + typescript-eslint + security plugin)
  passes with 0 errors.

## [0.1.2] - 2026-10-08

### Added

- Distinct refusal codes for anomaly halts: `VELOCITY_EXCEEDED` (rate halt)
  and `BUDGET_EXCEEDED` (call/token budget halt). `LOOP_BLOCKED` now means
  only the identical-call loop. `AnomalyVerdict.cause` (`'loop' |
  'velocity' | 'budget'`) drives the mapping in both `execute()` and the
  `check()` dry run; halted sessions keep reporting their original cause.

### Changed

- **BREAKING (minor):** `compact()` / `compressSchema()` emit a single line —
  an inline `/* description */` comment followed by the `type` signature —
  instead of a `//` comment line plus signature line. No more `\n`-split
  double-count hazard for consumers.

## [0.1.1] - 2026-10-08

### Fixed

- **Gate normalization bypass**: circuit breaker (gate 3) and injection
  filter (gate 7) now scan the canonical form of every string (NFKC,
  zero-width/bidi strip, homoglyph fold), closing zero-width and
  full-width-homoglyph evasion. Pure-ASCII payloads take a fast path, so the
  sub-millisecond budget holds.
- **`vark check` broken-by-default**: auto-registers a permissive stand-in
  tool per payload tool name so gates 1–3 evaluate real arguments; malformed
  files fail their own entry instead of aborting the batch.
- **`vark policy test` now evaluates `run` bodies** instead of echoing args.

### Changed

- Docs: redaction format, `compact()` shape, shared `LOOP_BLOCKED` code,
  and audit decision semantics documented precisely.

## [0.1.0] - 2026-10-03

### Added

- 8-gate zero-trust security pipeline
- Sub-millisecond circuit breaker with shell injection and path traversal detection
- Capability-based sandboxing with filesystem and network grants
- Input/output DLP with 10 secret scanners
- Indirect prompt injection defense with 7 detectors
- Anomaly guard with session loop detection and velocity limits
- Hash-chained audit logger with optional HMAC signing
- Compact Tool Protocol (CTP) for 60-80% token compression
- Zero-rewrite Anthropic MCP adapter
- Enterprise security modules:
  - Isolated-VM / QuickJS sandbox
  - Ephemeral virtual filesystem
  - Resource quotas (CPU, memory, subprocess, output)
  - Semantic injection detector
  - Canary / honeytoken trap
  - Entropy & reflection scanner
  - Reversible PII anonymization
  - HITL approval gate
  - DAG flow enforcement
  - Ephemeral credential injection
  - Egress proxy with domain pinning
  - KMS audit signing (Ed25519)
  - Deterministic replay engine
  - SIEM telemetry broadcaster
- Comprehensive test suite (80 tests)
- Full documentation suite in `/docs`
