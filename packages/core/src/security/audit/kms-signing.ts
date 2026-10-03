/**
 * Asymmetric KMS Audit Signing
 *
 * Upgrades audit hash-chaining to support Ed25519 asymmetric signatures for
 * tamper-proof public verification. The private key signs each audit entry;
 * the public key can be distributed to verifiers without compromising the
 * signing key.
 */

import { generateKeyPairSync, sign, verify, createPrivateKey, createPublicKey, KeyObject } from 'node:crypto';
import type { AuditEntry } from '../../types.js';

export interface KmsSigningConfig {
  /** Ed25519 private key (PEM string or KeyObject). */
  privateKey: string | KeyObject;
  /** Ed25519 public key (PEM string or KeyObject) for verification. */
  publicKey: string | KeyObject;
  /** Key identifier for key rotation. */
  keyId?: string;
}

export interface SignedAuditEntry extends AuditEntry {
  /** Ed25519 signature of the entry hash. */
  signature: string;
  /** Key identifier used for signing. */
  keyId: string;
}

/**
 * Signs audit entries with Ed25519 asymmetric signatures.
 * Provides tamper-proof public verification without exposing the private key.
 */
export class KmsAuditSigner {
  readonly #config: KmsSigningConfig;
  readonly #privateKey: KeyObject;
  readonly #publicKey: KeyObject;

  constructor(config: KmsSigningConfig) {
    this.#config = config;
    this.#privateKey = typeof config.privateKey === 'string'
      ? createPrivateKey(config.privateKey)
      : config.privateKey;
    this.#publicKey = typeof config.publicKey === 'string'
      ? createPublicKey(config.publicKey)
      : config.publicKey;
  }

  /** Sign an audit entry, returning a signed copy. */
  sign(entry: AuditEntry): SignedAuditEntry {
    const signature = signData(entry.hash, this.#privateKey);

    return {
      ...entry,
      signature,
      keyId: this.#config.keyId ?? 'default',
    };
  }

  /** Verify a signed audit entry. */
  verify(entry: SignedAuditEntry): boolean {
    return verifyData(entry.hash, entry.signature, this.#publicKey);
  }

  /** Get the public key in PEM format for distribution to verifiers. */
  getPublicKeyPem(): string {
    return this.#publicKey.export({ type: 'spki', format: 'pem' }).toString();
  }

  /** Get the key identifier. */
  getKeyId(): string {
    return this.#config.keyId ?? 'default';
  }
}

/**
 * Generate a new Ed25519 key pair for audit signing.
 */
export function generateAuditKeyPair(): { privateKey: string; publicKey: string } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  return {
    privateKey: privateKey.toString(),
    publicKey: publicKey.toString(),
  };
}

/**
 * Verify a signed entry using only the public key (no private key needed).
 * Useful for external verifiers and SIEM systems.
 */
export function verifyAuditEntry(
  entry: SignedAuditEntry,
  publicKeyPem: string,
): boolean {
  try {
    const publicKey = createPublicKey(publicKeyPem);
    return verifyData(entry.hash, entry.signature, publicKey);
  } catch {
    return false;
  }
}

/**
 * Sign data with an Ed25519 private key. Ed25519 does not use a separate
 * digest algorithm — the signature is computed over the raw data.
 */
function signData(data: string, privateKey: KeyObject): string {
  return sign(null, Buffer.from(data, 'utf8'), privateKey).toString('base64');
}

/**
 * Verify data against an Ed25519 signature.
 */
function verifyData(data: string, signature: string, publicKey: KeyObject): boolean {
  try {
    return verify(null, Buffer.from(data, 'utf8'), publicKey, Buffer.from(signature, 'base64'));
  } catch {
    return false;
  }
}
