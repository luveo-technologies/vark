/**
 * Human-In-The-Loop (HITL) Gate
 *
 * Authorization gate for designated high-risk capabilities (`db:drop`,
 * `stripe:refund`, etc.). Pauses execution and awaits an external signature
 * or webhook trigger before allowing the tool to run.
 */

export interface HitlCapability {
  /** Capability identifier, e.g. `db:drop`, `stripe:refund`. */
  id: string;
  /** Human-readable description. */
  description: string;
  /** Risk level. */
  risk: 'low' | 'medium' | 'high' | 'critical';
}

export interface HitlRequest {
  /** Unique request identifier. */
  requestId: string;
  /** The capability being requested. */
  capability: HitlCapability;
  /** Session that initiated the request. */
  sessionId: string;
  /** Tool name. */
  tool: string;
  /** Tool arguments (sanitized). */
  args: unknown;
  /** When the request was created. */
  createdAt: number;
  /** When the request expires. */
  expiresAt: number;
  /** Current status. */
  status: 'pending' | 'approved' | 'denied' | 'expired';
  /** Who approved/denied the request. */
  decidedBy?: string;
  /** When the decision was made. */
  decidedAt?: number;
}

export interface HitlConfig {
  /** Capabilities that require HITL approval. */
  requiredCapabilities: HitlCapability[];
  /** Default request TTL in ms. @default 300_000 (5 min) */
  defaultTtlMs?: number;
  /** Custom approval checker. Return true to auto-approve. */
  autoApprove?: (request: HitlRequest) => boolean;
}

export interface HitlDecision {
  approved: boolean;
  requestId: string;
  decidedBy: string;
  reason?: string;
}

/**
 * Manages HITL approval requests. Integrates with external approval systems
 * via webhooks or manual review.
 */
export class HitlGate {
  readonly #config: Required<HitlConfig>;
  readonly #requests = new Map<string, HitlRequest>();
  readonly #pendingResolvers = new Map<string, (decision: HitlDecision) => void>();

  constructor(config: HitlConfig) {
    this.#config = {
      requiredCapabilities: config.requiredCapabilities,
      defaultTtlMs: config.defaultTtlMs ?? 300_000,
      autoApprove: config.autoApprove ?? (() => false),
    };
  }

  /** Check if a capability requires HITL approval. */
  requiresApproval(capabilityId: string): HitlCapability | undefined {
    return this.#config.requiredCapabilities.find((c) => c.id === capabilityId);
  }

  /**
   * Request approval for a high-risk capability.
   * Returns a promise that resolves when the request is approved or denied.
   * With `opts.timeoutMs`, an undecided request expires into a denial after
   * the budget elapses (fail-closed); the timer is always cleared on settle
   * so pending approvals never leak.
   */
  async requestApproval(
    capabilityId: string,
    sessionId: string,
    tool: string,
    args: unknown,
    opts?: { timeoutMs?: number },
  ): Promise<HitlDecision> {
    const capability = this.requiresApproval(capabilityId);
    if (!capability) {
      return { approved: true, requestId: '', decidedBy: 'auto' };
    }

    const requestId = `hitl_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
    const now = Date.now();
    const request: HitlRequest = {
      requestId,
      capability,
      sessionId,
      tool,
      args,
      createdAt: now,
      expiresAt: now + this.#config.defaultTtlMs,
      status: 'pending',
    };

    // Check auto-approve first.
    if (this.#config.autoApprove(request)) {
      request.status = 'approved';
      request.decidedBy = 'auto';
      request.decidedAt = Date.now();
      this.#requests.set(requestId, request);
      return { approved: true, requestId, decidedBy: 'auto' };
    }

    this.#requests.set(requestId, request);

    return new Promise<HitlDecision>((resolve) => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const settle = (decision: HitlDecision): void => {
        if (timer !== undefined) {
          clearTimeout(timer);
          timer = undefined;
        }
        this.#pendingResolvers.delete(requestId);
        resolve(decision);
      };
      this.#pendingResolvers.set(requestId, (decision) => settle(decision));

      if (opts?.timeoutMs !== undefined && opts.timeoutMs > 0) {
        timer = setTimeout(() => {
          if (request.status !== 'pending') return;
          request.status = 'expired';
          request.decidedBy = 'system';
          request.decidedAt = Date.now();
          settle({ approved: false, requestId, decidedBy: 'system', reason: 'approval timed out' });
        }, opts.timeoutMs);
      }
    });
  }

  /** Approve a pending request. */
  approve(requestId: string, decidedBy: string, reason?: string): boolean {
    const request = this.#requests.get(requestId);
    if (!request || request.status !== 'pending') return false;
    if (Date.now() > request.expiresAt) {
      request.status = 'expired';
      return false;
    }

    request.status = 'approved';
    request.decidedBy = decidedBy;
    request.decidedAt = Date.now();

    const resolver = this.#pendingResolvers.get(requestId);
    if (resolver) {
      this.#pendingResolvers.delete(requestId);
      resolver({ approved: true, requestId, decidedBy, reason });
    }
    return true;
  }

  /** Deny a pending request. */
  deny(requestId: string, decidedBy: string, reason?: string): boolean {
    const request = this.#requests.get(requestId);
    if (!request || request.status !== 'pending') return false;

    request.status = 'denied';
    request.decidedBy = decidedBy;
    request.decidedAt = Date.now();

    const resolver = this.#pendingResolvers.get(requestId);
    if (resolver) {
      this.#pendingResolvers.delete(requestId);
      resolver({ approved: false, requestId, decidedBy, reason });
    }
    return true;
  }

  /** Get a request by ID. */
  getRequest(requestId: string): HitlRequest | undefined {
    return this.#requests.get(requestId);
  }

  /** Get all pending requests. */
  getPendingRequests(): HitlRequest[] {
    return [...this.#requests.values()].filter((r) => r.status === 'pending');
  }

  /** Get requests for a session. */
  getSessionRequests(sessionId: string): HitlRequest[] {
    return [...this.#requests.values()].filter((r) => r.sessionId === sessionId);
  }

  /** Clean up expired requests. */
  cleanupExpired(): number {
    const now = Date.now();
    let cleaned = 0;
    for (const [id, request] of this.#requests) {
      if (request.status === 'pending' && now > request.expiresAt) {
        request.status = 'expired';
        const resolver = this.#pendingResolvers.get(id);
        if (resolver) {
          this.#pendingResolvers.delete(id);
          resolver({ approved: false, requestId: id, decidedBy: 'system', reason: 'Request expired' });
        }
        cleaned += 1;
      }
    }
    return cleaned;
  }

  get pendingCount(): number {
    return this.getPendingRequests().length;
  }
}

/**
 * Default high-risk capabilities that require HITL approval.
 */
export const DEFAULT_HITL_CAPABILITIES: HitlCapability[] = [
  { id: 'db:drop', description: 'Drop database tables', risk: 'critical' },
  { id: 'db:delete', description: 'Delete database records', risk: 'high' },
  { id: 'stripe:refund', description: 'Process refunds', risk: 'high' },
  { id: 'stripe:charge', description: 'Charge credit cards', risk: 'high' },
  { id: 'aws:delete', description: 'Delete AWS resources', risk: 'critical' },
  { id: 'k8s:delete', description: 'Delete Kubernetes resources', risk: 'critical' },
  { id: 'email:send', description: 'Send emails to external recipients', risk: 'medium' },
  { id: 'file:delete', description: 'Delete files from filesystem', risk: 'medium' },
];
