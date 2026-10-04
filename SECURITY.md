# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Vulnerability Disclosure

We take the security of `@saturn/vark` seriously. If you discover a security vulnerability, please report it responsibly.

### Reporting Process

1. **Email**: Send details to `security@saturn.ai`
2. **Subject**: `[vark-security] <brief description>`
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Any suggested mitigations

### SLA

| Stage | Timeline |
|-------|----------|
| Initial response | 48 hours |
| Triage & assessment | 5 business days |
| Fix or mitigation | 15 business days |
| Public disclosure | After fix is released |

### Scope

In scope:
- Bypass of the 8-gate security pipeline
- Sandbox escape or isolation failure
- Secret leakage through DLP bypass
- Audit trail tampering or forgery
- Denial of service against the runtime
- Prototype pollution or injection attacks

Out of scope:
- Vulnerabilities in third-party dependencies (report upstream)
- Social engineering of operators
- Physical access attacks

## Threat Model

See `docs/SECURITY.md` for the full threat matrix mapping to OWASP LLM Top 10, OWASP Agentic AI, and MITRE ATLAS frameworks.

## Security Features

- 8-gate zero-trust execution pipeline
- Sub-millisecond circuit breaker with ReDoS-safe patterns
- Secret detection and redaction (DLP)
- Indirect prompt injection defense
- Capability-based sandboxing
- Hash-chained audit trail with optional HMAC signing
- Resource quotas and anomaly detection
