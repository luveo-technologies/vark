import { describe, it, expect } from 'vitest';
import { EgressProxy, COMMON_EGRESS_RULES } from '../packages/core/src/security/egress/egress-proxy.js';
import { generateAuditKeyPair, KmsAuditSigner, verifyAuditEntry } from '../packages/core/src/security/audit/kms-signing.js';
import type { AuditEntry } from '../packages/core/src/types.js';

describe('Feature 12 — Egress Proxy', () => {
  it('allows requests to allowlisted domains', async () => {
    const egress = new EgressProxy({ rules: COMMON_EGRESS_RULES });
    const result = await egress.checkRequest({ url: 'https://api.stripe.com/v1/charges', method: 'POST' });
    expect(result.allowed).toBe(true);
  });

  it('blocks requests to non-allowlisted domains', async () => {
    const egress = new EgressProxy({ rules: COMMON_EGRESS_RULES, defaultPolicy: 'deny' });
    const result = await egress.checkRequest({ url: 'https://evil.example.com/steal', method: 'POST' });
    expect(result.allowed).toBe(false);
  });

  it('blocks non-allowlisted ports', async () => {
    const egress = new EgressProxy({ rules: [{ domain: 'api.example.com', ports: [443] }] });
    const result = await egress.checkRequest({ url: 'https://api.example.com:8080/data', method: 'GET' });
    expect(result.allowed).toBe(false);
  });

  it('supports wildcard domains', async () => {
    const egress = new EgressProxy({ rules: [{ domain: '*.example.com' }] });
    const result = await egress.checkRequest({ url: 'https://sub.example.com/api', method: 'GET' });
    expect(result.allowed).toBe(true);
  });

  it('handles invalid URLs', async () => {
    const egress = new EgressProxy({ rules: [] });
    const result = await egress.checkRequest({ url: 'not-a-url', method: 'GET' });
    expect(result.allowed).toBe(false);
  });
});

describe('Feature 13 — KMS Audit Signing', () => {
  it('generates Ed25519 key pairs', () => {
    const { privateKey, publicKey } = generateAuditKeyPair();
    expect(privateKey).toContain('PRIVATE KEY');
    expect(publicKey).toContain('PUBLIC KEY');
  });

  it('signs and verifies audit entries', () => {
    const { privateKey, publicKey } = generateAuditKeyPair();
    const signer = new KmsAuditSigner({ privateKey, publicKey, keyId: 'test-key' });

    const entry = { seq: 1, hash: 'abc123' } as unknown as AuditEntry;
    const signed = signer.sign(entry);

    expect(signed.signature).toBeDefined();
    expect(signed.keyId).toBe('test-key');
    expect(signer.verify(signed)).toBe(true);
  });

  it('detects tampered entries', () => {
    const { privateKey, publicKey } = generateAuditKeyPair();
    const signer = new KmsAuditSigner({ privateKey, publicKey });

    const entry = { seq: 1, hash: 'abc123' } as unknown as AuditEntry;
    const signed = signer.sign(entry);

    // Tamper with the hash
    const tampered = { ...signed, hash: 'tampered' };
    expect(signer.verify(tampered)).toBe(false);
  });

  it('verifies with public key only', () => {
    const { privateKey, publicKey } = generateAuditKeyPair();
    const signer = new KmsAuditSigner({ privateKey, publicKey });

    const entry = { seq: 1, hash: 'abc123' } as unknown as AuditEntry;
    const signed = signer.sign(entry);

    expect(verifyAuditEntry(signed, publicKey)).toBe(true);
  });
});
