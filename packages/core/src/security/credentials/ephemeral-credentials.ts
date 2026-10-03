/**
 * Zero-Trust Ephemeral Credential Injection
 *
 * Intercepts tool execution to fetch and inject short-lived tokens/IAM
 * credentials from a secret vault right before execution, scrubbing them
 * immediately after. Tools never see long-lived credentials.
 */

export interface CredentialRequest {
  /** Credential type, e.g. `aws:iam`, `gcp:service_account`, `db:password`. */
  type: string;
  /** Resource the credential is for. */
  resource: string;
  /** How long the credential is valid in seconds. @default 300 (5 min) */
  ttlSeconds?: number;
  /** Additional options for the credential provider. */
  options?: Record<string, unknown>;
}

export interface EphemeralCredential {
  /** The credential value (token, password, etc.). */
  value: string;
  /** When the credential expires. */
  expiresAt: number;
  /** Credential type. */
  type: string;
  /** Resource this credential is for. */
  resource: string;
  /** Whether the credential has been scrubbed. */
  scrubbed: boolean;
}

export interface CredentialProvider {
  /** Provider name. */
  name: string;
  /** Fetch a credential. */
  fetch(request: CredentialRequest): Promise<EphemeralCredential>;
  /** Scrub a credential after use. */
  scrub?(credential: EphemeralCredential): Promise<void>;
}

export interface CredentialInjectionConfig {
  /** Registered credential providers. */
  providers: CredentialProvider[];
  /** Default TTL in seconds. @default 300 */
  defaultTtlSeconds?: number;
  /** Whether to scrub credentials after execution. @default true */
  scrubAfterUse?: boolean;
}

/**
 * Manages ephemeral credential lifecycle: fetch, inject, scrub.
 */
export class EphemeralCredentialManager {
  readonly #config: Required<CredentialInjectionConfig>;
  readonly #providers = new Map<string, CredentialProvider>();
  readonly #activeCredentials = new Map<string, EphemeralCredential>();

  constructor(config: CredentialInjectionConfig) {
    this.#config = {
      providers: config.providers,
      defaultTtlSeconds: config.defaultTtlSeconds ?? 300,
      scrubAfterUse: config.scrubAfterUse ?? true,
    };
    for (const provider of config.providers) {
      this.#providers.set(provider.name, provider);
    }
  }

  /**
   * Fetch an ephemeral credential for a tool execution.
   * The credential is automatically scrubbed after the callback completes.
   */
  async withCredential<T>(
    request: CredentialRequest,
    fn: (credential: EphemeralCredential) => Promise<T> | T,
  ): Promise<T> {
    const provider = this.#providers.get(request.type);
    if (!provider) {
      throw new Error(`No credential provider registered for type "${request.type}"`);
    }

    const credential = await provider.fetch(request);
    this.#activeCredentials.set(credential.value, credential);

    try {
      return await fn(credential);
    } finally {
      if (this.#config.scrubAfterUse) {
        await this.scrub(credential.value);
      }
    }
  }

  /** Scrub a credential, removing it from active use. */
  async scrub(credentialValue: string): Promise<void> {
    const credential = this.#activeCredentials.get(credentialValue);
    if (!credential) return;

    credential.scrubbed = true;
    this.#activeCredentials.delete(credentialValue);

    // Find the provider and call its scrub method.
    for (const provider of this.#providers.values()) {
      if (provider.scrub) {
        await provider.scrub(credential);
      }
    }
  }

  /** Scrub all active credentials. */
  async scrubAll(): Promise<void> {
    const values = [...this.#activeCredentials.keys()];
    for (const value of values) {
      await this.scrub(value);
    }
  }

  /** Get all active (non-scrubbed) credentials. */
  getActiveCredentials(): EphemeralCredential[] {
    return [...this.#activeCredentials.values()];
  }

  /** Check if a credential is still active. */
  isActive(credentialValue: string): boolean {
    return this.#activeCredentials.has(credentialValue);
  }

  get activeCount(): number {
    return this.#activeCredentials.size;
  }
}

/**
 * In-memory credential provider for testing.
 */
export class InMemoryCredentialProvider implements CredentialProvider {
  readonly name: string;
  readonly #credentials = new Map<string, string>();

  constructor(name: string) {
    this.name = name;
  }

  /** Pre-register a credential value. */
  register(resource: string, value: string): void {
    this.#credentials.set(resource, value);
  }

  async fetch(request: CredentialRequest): Promise<EphemeralCredential> {
    const value = this.#credentials.get(request.resource);
    if (!value) {
      throw new Error(`No credential registered for resource "${request.resource}"`);
    }
    const ttl = request.ttlSeconds ?? 300;
    return {
      value,
      expiresAt: Date.now() + ttl * 1000,
      type: request.type,
      resource: request.resource,
      scrubbed: false,
    };
  }

  async scrub(credential: EphemeralCredential): Promise<void> {
    this.#credentials.delete(credential.resource);
  }
}
