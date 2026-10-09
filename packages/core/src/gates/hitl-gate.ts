/**
 * Human-In-The-Loop (HITL) Gate
 *
 * Authorization gate for designated high-risk capabilities (`db:drop`,
 * `stripe:refund`, etc.). Pauses execution and awaits an external signature
 * or webhook trigger before allowing the tool to run.
 *
 * Approval can be **quorum-gated** (`quorum.required` distinct approvers),
 * and the request can be **fanned out by webhook** so external systems
 * (Slack, PagerDuty, a custom console) learn about it. The fail-closed
 * rules are deliberate:
 *
 * - one distinct **denial vetoes** the request immediately, regardless of
 *   quorum;
 * - undecided requests **time out into denials**;
 * - a webhook delivery failure denies only when `webhook.required` is set
 *   (otherwise the request stays pending for in-band approvers);
 * - when `quorum.approvers` is configured, only those ids may decide.
 *
 * Webhooks are outbound notifications: responders call back through your
 * control plane (`gate.approve(requestId, approverId)` /
 * `gate.deny(requestId, approverId)`).
 */

import { createHmac } from 'node:crypto';

export interface HitlCapability {
  /** Capability identifier, e.g. `db:drop`, `stripe:refund`. */
  id: string;
  /** Human-readable description. */
  description: string;
  /** Risk level. */
  risk: 'low' | 'medium' | 'high' | 'critical';
}

export interface HitlDecisionRecord {
  /** Approver id. */
  by: string;
  approved: boolean;
  at: number;
  reason?: string;
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
  /** Who approved/denied the request (settling approver, or `a+b` under quorum). */
  decidedBy?: string;
  /** When the decision was made. */
  decidedAt?: number;
  /** Every recorded decision, in order (the quorum ledger). */
  decisions: HitlDecisionRecord[];
}

/** Distinct-approver quorum for approvals (denials always veto). */
export interface HitlQuorum {
  /** Distinct approvals required to approve. @default 1 */
  required: number;
  /** Restrict decisions to these approver ids (anyone when omitted). */
  approvers?: string[];
}

/** Outbound webhook that fans an approval request out to external systems. */
export interface HitlWebhookTarget {
  /** Endpoint that receives `POST hitl.approval.requested` JSON. */
  url: string;
  /** HMAC-SHA256 secret; signs the body as `x-vark-signature: sha256=<hex>`. */
  secret?: string;
  /** Extra headers (e.g. auth). */
  headers?: Record<string, string>;
  /** Delivery timeout in ms. @default 5_000 */
  timeoutMs?: number;
  /** Fail closed: a delivery error denies the request. @default false */
  required?: boolean;
}

export interface HitlConfig {
  /** Capabilities that require HITL approval. */
  requiredCapabilities: HitlCapability[];
  /** Default request TTL in ms. @default 300_000 (5 min) */
  defaultTtlMs?: number;
  /** Custom approval checker. Return true to auto-approve. */
  autoApprove?: (request: HitlRequest) => boolean;
  /** Approval quorum (denials always veto). @default { required: 1 } */
  quorum?: HitlQuorum;
  /** Fan requests out to an external system on creation. */
  webhook?: HitlWebhookTarget;
  /** Called when webhook delivery fails and `webhook.required` is false. */
  onWebhookError?: (error: Error, request: HitlRequest) => void;
}

export interface HitlDecision {
  approved: boolean;
  requestId: string;
  decidedBy: string;
  reason?: string;
}

/** `sha256=<hex>` HMAC of `body` — what `x-vark-signature` carries. */
export function signWebhookBody(secret: string, body: string): string {
  return `sha256=${createHmac('sha256', secret).update(body, 'utf8').digest('hex')}`;
}

/** Constant-time check of a received `x-vark-signature` against the body. */
export function verifyWebhookSignature(secret: string, body: string, header: string): boolean {
  const expected = Buffer.from(signWebhookBody(secret, body));
  const received = Buffer.from(header);
  return expected.length === received.length && timingSafeEqual(expected, received);
}

/** Minimal timing-safe compare (lengths pre-checked by the caller). */
function timingSafeEqual(a: Buffer, b: Buffer): boolean {
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

/**
 * Manages HITL approval requests. Integrates with external approval systems
 * via webhooks or manual review.
 */
export class HitlGate {
  readonly #config: HitlConfig & {
    requiredCapabilities: HitlCapability[];
    defaultTtlMs: number;
    autoApprove: (request: HitlRequest) => boolean;
  };
  readonly #requests = new Map<string, HitlRequest>();
  readonly #pendingResolvers = new Map<string, (decision: HitlDecision) => void>();

  constructor(config: HitlConfig) {
    this.#config = {
      requiredCapabilities: config.requiredCapabilities,
      defaultTtlMs: config.defaultTtlMs ?? 300_000,
      autoApprove: config.autoApprove ?? (() => false),
      quorum: config.quorum,
      webhook: config.webhook,
      onWebhookError: config.onWebhookError,
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
   *
   * `opts.capability` supplies a synthetic capability (used by adaptive risk
   * escalation) instead of requiring a pre-registered id.
   */
  async requestApproval(
    capabilityId: string,
    sessionId: string,
    tool: string,
    args: unknown,
    opts?: { timeoutMs?: number; capability?: HitlCapability },
  ): Promise<HitlDecision> {
    const capability = opts?.capability ?? this.requiresApproval(capabilityId);
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
      decisions: [],
    };

    // Check auto-approve first.
    if (this.#config.autoApprove(request)) {
      request.status = 'approved';
      request.decidedBy = 'auto';
      request.decidedAt = Date.now();
      request.decisions.push({ by: 'auto', approved: true, at: request.decidedAt });
      this.#requests.set(requestId, request);
      return { approved: true, requestId, decidedBy: 'auto' };
    }

    // Synchronous from here through #requests.set so callers observe the
    // pending request immediately after invoking requestApproval().
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
          request.decisions.push({ by: 'system', approved: false, at: request.decidedAt, reason: 'approval timed out' });
          settle({ approved: false, requestId, decidedBy: 'system', reason: 'approval timed out' });
        }, opts.timeoutMs);
      }

      // Outbound fan-out: notify external approvers. Delivery failure only
      // denies outright when the target is marked required — otherwise the
      // request stays pending for in-band approvers (the timeout still
      // fails closed).
      if (this.#config.webhook) {
        void this.#dispatchWebhook(request).catch((error: unknown) => {
          const err = error instanceof Error ? error : new Error(String(error));
          this.#config.onWebhookError?.(err, request);
          if (this.#config.webhook?.required && request.status === 'pending') {
            request.status = 'denied';
            request.decidedBy = 'webhook';
            request.decidedAt = Date.now();
            const reason = `webhook delivery failed: ${err.message}`;
            request.decisions.push({ by: 'webhook', approved: false, at: request.decidedAt, reason });
            settle({ approved: false, requestId, decidedBy: 'webhook', reason });
          }
        });
      }
    });
  }

  /**
   * Approve a pending request. Under quorum, records the decision and only
   * settles once `quorum.required` DISTINCT approvers have approved; the
   * same approver cannot vote twice. Returns false when the decision was
   * not recorded (unknown/settled request, ineligible approver, duplicate).
   */
  approve(requestId: string, decidedBy: string, reason?: string): boolean {
    if (!this.#eligible(requestId, decidedBy)) return false;
    const request = this.#requests.get(requestId)!;
    if (Date.now() > request.expiresAt) {
      request.status = 'expired';
      return false;
    }

    if (request.decisions.some((d) => d.by === decidedBy)) return false; // one vote per approver
    request.decisions.push({ by: decidedBy, approved: true, at: Date.now(), reason });

    const approvals = request.decisions.filter((d) => d.approved).map((d) => d.by);
    const needed = Math.max(1, this.#config.quorum?.required ?? 1);
    if (approvals.length < needed) return true; // recorded, still pending

    request.status = 'approved';
    request.decidedBy = approvals.join('+');
    request.decidedAt = Date.now();

    const resolver = this.#pendingResolvers.get(requestId);
    if (resolver) {
      this.#pendingResolvers.delete(requestId);
      resolver({ approved: true, requestId, decidedBy, reason });
    }
    return true;
  }

  /**
   * Deny a pending request. A single denial vetoes regardless of quorum —
   * fail-closed: approval needs consensus, refusal needs one voice.
   */
  deny(requestId: string, decidedBy: string, reason?: string): boolean {
    if (!this.#eligible(requestId, decidedBy)) return false;
    const request = this.#requests.get(requestId)!;

    if (request.decisions.some((d) => d.by === decidedBy)) return false;
    request.status = 'denied';
    request.decidedBy = decidedBy;
    request.decidedAt = Date.now();
    request.decisions.push({ by: decidedBy, approved: false, at: request.decidedAt, reason });

    const resolver = this.#pendingResolvers.get(requestId);
    if (resolver) {
      this.#pendingResolvers.delete(requestId);
      resolver({ approved: false, requestId, decidedBy, reason });
    }
    return true;
  }

  /** Is this a pending, unexpired request the approver may decide on? */
  #eligible(requestId: string, decidedBy: string): boolean {
    const request = this.#requests.get(requestId);
    if (!request || request.status !== 'pending') return false;
    const approvers = this.#config.quorum?.approvers;
    if (approvers && !approvers.includes(decidedBy)) return false;
    return true;
  }

  /** The quorum ledger for one request. */
  getDecisions(requestId: string): HitlDecisionRecord[] {
    return [...(this.#requests.get(requestId)?.decisions ?? [])];
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
        request.decidedBy = 'system';
        request.decidedAt = now;
        request.decisions.push({ by: 'system', approved: false, at: now, reason: 'Request expired' });
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

  /** POST the request to the configured webhook (HMAC-signed when a secret is set). */
  async #dispatchWebhook(request: HitlRequest): Promise<void> {
    const target = this.#config.webhook;
    if (!target) return;

    const body = JSON.stringify({
      event: 'hitl.approval.requested',
      issuedAt: new Date().toISOString(),
      request: {
        requestId: request.requestId,
        capability: request.capability,
        sessionId: request.sessionId,
        tool: request.tool,
        args: request.args,
        createdAt: request.createdAt,
        expiresAt: request.expiresAt,
      },
      quorum: {
        required: Math.max(1, this.#config.quorum?.required ?? 1),
        approvals: 0,
        approvers: this.#config.quorum?.approvers,
      },
      respond: 'POST the requestId back to gate.approve(requestId, approverId) or gate.deny(requestId, approverId)',
    });

    const headers: Record<string, string> = {
      'content-type': 'application/json',
      'user-agent': 'vark-hitl',
      ...(target.headers ?? {}),
    };
    if (target.secret) headers['x-vark-signature'] = signWebhookBody(target.secret, body);

    const response = await fetch(target.url, {
      method: 'POST',
      headers,
      body,
      signal: AbortSignal.timeout(target.timeoutMs ?? 5_000),
    });
    if (!response.ok) {
      throw new Error(`webhook POST ${target.url} responded ${response.status}`);
    }
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
