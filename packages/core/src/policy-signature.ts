/**
 * Signed policy bundles (Ed25519 via `node:crypto` — zero dependencies).
 *
 * A signature is a detached sidecar (`<policy>.sig`) binding the **exact
 * bytes** of a policy file to a key pair:
 *
 * ```json
 * {
 *   "alg": "ed25519",
 *   "keyId": "sha256:…",          // fingerprint of the signing public key
 *   "publicKey": "-----BEGIN PUBLIC KEY-----…",
 *   "policyHash": "sha256:…",     // digest of the signed policy bytes
 *   "signature": "base64…",       // Ed25519 signature over `policyHash`
 *   "signedAt": "2026-10-09T…Z"
 * }
 * ```
 *
 * Verification is drift detection by construction: any byte change to the
 * policy (an edit, an attack, a bad merge) changes `policyHash` and the
 * bundle no longer verifies.
 *
 * Trust model:
 * - **Pinned key** (`verifyPolicy(..., { publicKeyPem })`, CLI `--key`):
 *   the embedded key is ignored for trust — the signature must come from
 *   the pinned key. This is the enterprise mode.
 * - **Embedded key** (no pin): proves integrity against third-party
 *   corruption, NOT origin — whoever holds the private key could have
 *   produced the bundle. The CLI says so.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';

export const POLICY_SIGNATURE_ALG = 'ed25519' as const;

export interface PolicySignature {
  alg: typeof POLICY_SIGNATURE_ALG;
  /** `sha256:<hex>` fingerprint of the signing public key (SPKI DER). */
  keyId: string;
  /** PEM public key — embedded for keyless integrity verification. */
  publicKey: string;
  /** `sha256:<hex>` digest of the exact signed policy bytes. */
  policyHash: string;
  /** Base64 Ed25519 signature over the ASCII bytes of `policyHash`. */
  signature: string;
  /** ISO-8601 signing time. */
  signedAt: string;
}

export interface VerifyResult {
  ok: boolean;
  /** Machine-readable failure class. */
  reason?: 'unsigned' | 'malformed' | 'wrong-key' | 'drift' | 'bad-signature';
  /** Human-readable explanation (present when `ok` is false). */
  detail?: string;
  signature?: PolicySignature;
}

/** SHA-256 digest of policy bytes, `sha256:<hex>` formatted. */
export function hashPolicy(content: string | Buffer): string {
  return `sha256:${createHash('sha256').update(content).digest('hex')}`;
}

/** `sha256:<hex>` fingerprint of a PEM public key (SPKI DER). */
export function policyKeyId(publicKeyPem: string): string {
  const der = createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
  return `sha256:${createHash('sha256').update(der).digest('hex')}`;
}

/** Generate an Ed25519 key pair as PEM strings (private = PKCS#8). */
export function generatePolicyKeyPair(): { privateKey: string; publicKey: string } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKey: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

/** Sign policy bytes with a PKCS#8 Ed25519 private key (PEM). */
export function signPolicy(content: string | Buffer, privateKeyPem: string): PolicySignature {
  const privateKey = createPrivateKey(privateKeyPem);
  const policyHash = hashPolicy(content);
  const signature = cryptoSign(null, Buffer.from(policyHash, 'ascii'), privateKey).toString('base64');
  const publicKey = createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString();
  return {
    alg: POLICY_SIGNATURE_ALG,
    keyId: policyKeyId(publicKey),
    publicKey,
    policyHash,
    signature,
    signedAt: new Date().toISOString(),
  };
}

/**
 * Verify policy bytes against a signature bundle.
 *
 * Order matters: drift is reported before signature validity (a modified
 * file that still carries a *valid-for-the-old-bytes* signature is drift,
 * not forgery), and a pinned key turns "somebody signed this" into
 * "the holder of THIS key signed this".
 */
export function verifyPolicy(
  content: string | Buffer,
  signature: PolicySignature | undefined,
  opts: { publicKeyPem?: string } = {},
): VerifyResult {
  if (!signature) {
    return { ok: false, reason: 'unsigned', detail: 'no signature bundle provided' };
  }
  if (signature.alg !== POLICY_SIGNATURE_ALG) {
    return {
      ok: false,
      reason: 'malformed',
      detail: `unsupported algorithm "${String(signature.alg)}" (expected ${POLICY_SIGNATURE_ALG})`,
      signature,
    };
  }

  // Which key do we trust? The pin wins; the embedded key is the fallback.
  const trustedKeyPem = opts.publicKeyPem ?? signature.publicKey;
  let trustedKeyId: string;
  try {
    trustedKeyId = policyKeyId(trustedKeyPem);
  } catch (error) {
    return {
      ok: false,
      reason: 'malformed',
      detail: `public key does not parse: ${error instanceof Error ? error.message : String(error)}`,
      signature,
    };
  }
  if (opts.publicKeyPem && trustedKeyId !== signature.keyId) {
    return {
      ok: false,
      reason: 'wrong-key',
      detail: `policy was signed with a different key (bundle ${signature.keyId}, pinned ${trustedKeyId})`,
      signature,
    };
  }

  const actualHash = hashPolicy(content);
  if (actualHash !== signature.policyHash) {
    return {
      ok: false,
      reason: 'drift',
      detail: `policy bytes changed since signing: expected ${signature.policyHash}, got ${actualHash}`,
      signature,
    };
  }

  let valid: boolean;
  try {
    valid = cryptoVerify(
      null,
      Buffer.from(signature.policyHash, 'ascii'),
      createPublicKey(trustedKeyPem),
      Buffer.from(signature.signature, 'base64'),
    );
  } catch (error) {
    return {
      ok: false,
      reason: 'malformed',
      detail: `signature does not parse: ${error instanceof Error ? error.message : String(error)}`,
      signature,
    };
  }
  if (!valid) {
    return {
      ok: false,
      reason: 'bad-signature',
      detail: 'Ed25519 signature does not verify against the policy hash',
      signature,
    };
  }
  return { ok: true, signature };
}
