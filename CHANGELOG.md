# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
