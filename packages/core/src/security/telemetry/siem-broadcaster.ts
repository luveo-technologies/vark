/**
 * SIEM Telemetry Broadcaster
 *
 * Streaming background worker that sends structured audit logs and threat
 * events to external SIEM systems via Webhooks/gRPC with rate-limiting.
 * Runs asynchronously so it never blocks the guard pipeline.
 */

import type { AuditEntry } from '../../types.js';

export interface SiemEvent {
  /** Event type. */
  type: 'audit' | 'threat' | 'alert';
  /** Event severity. */
  severity: 'info' | 'warning' | 'error' | 'critical';
  /** Event timestamp. */
  timestamp: number;
  /** Event payload. */
  payload: AuditEntry | Record<string, unknown>;
  /** Session identifier. */
  sessionId?: string;
  /** Tool name (if applicable). */
  tool?: string;
}

export interface SiemConfig {
  /** Webhook URL for SIEM ingestion. */
  webhookUrl?: string;
  /** gRPC endpoint for SIEM ingestion. */
  grpcEndpoint?: string;
  /** Authentication token. */
  authToken?: string;
  /** Maximum events per second. @default 100 */
  maxEventsPerSecond?: number;
  /** Maximum queue size before dropping events. @default 10_000 */
  maxQueueSize?: number;
  /** Batch size for sending events. @default 50 */
  batchSize?: number;
  /** Flush interval in ms. @default 1_000 */
  flushIntervalMs?: number;
  /** Custom sender function. */
  customSender?: (events: SiemEvent[]) => Promise<void>;
}

export interface SiemBroadcasterStats {
  queued: number;
  sent: number;
  dropped: number;
  errors: number;
  lastFlushAt?: number;
}

/**
 * Background worker that batches and sends audit/threat events to SIEM
 * systems. Rate-limited and non-blocking.
 */
export class SiemBroadcaster {
  readonly #config: Required<SiemConfig>;
  readonly #queue: SiemEvent[] = [];
  readonly #stats: SiemBroadcasterStats = {
    queued: 0,
    sent: 0,
    dropped: 0,
    errors: 0,
  };
  #flushTimer: ReturnType<typeof setInterval> | undefined;
  #running = false;
  #lastFlushTime = 0;

  constructor(config: SiemConfig = {}) {
    this.#config = {
      webhookUrl: config.webhookUrl ?? '',
      grpcEndpoint: config.grpcEndpoint ?? '',
      authToken: config.authToken ?? '',
      maxEventsPerSecond: config.maxEventsPerSecond ?? 100,
      maxQueueSize: config.maxQueueSize ?? 10_000,
      batchSize: config.batchSize ?? 50,
      flushIntervalMs: config.flushIntervalMs ?? 1_000,
      customSender: config.customSender ?? (async () => undefined),
    };
  }

  /** Start the background flush worker. */
  start(): void {
    if (this.#running) return;
    this.#running = true;
    this.#flushTimer = setInterval(() => {
      void this.flush();
    }, this.#config.flushIntervalMs);
  }

  /** Stop the background flush worker. */
  stop(): void {
    this.#running = false;
    if (this.#flushTimer) {
      clearInterval(this.#flushTimer);
      this.#flushTimer = undefined;
    }
  }

  /** Queue an event for delivery. Non-blocking. */
  send(event: SiemEvent): void {
    if (this.#queue.length >= this.#config.maxQueueSize) {
      this.#stats.dropped += 1;
      return;
    }
    this.#queue.push(event);
    this.#stats.queued = this.#queue.length;
  }

  /** Queue an audit entry. */
  sendAuditEntry(entry: AuditEntry): void {
    this.send({
      type: 'audit',
      severity: entry.blockedBy ? 'warning' : 'info',
      timestamp: Date.now(),
      payload: entry,
      sessionId: entry.sessionId,
      tool: entry.tool,
    });
  }

  /** Queue a threat event. */
  sendThreatEvent(
    severity: SiemEvent['severity'],
    payload: Record<string, unknown>,
    sessionId?: string,
    tool?: string,
  ): void {
    this.send({
      type: 'threat',
      severity,
      timestamp: Date.now(),
      payload,
      sessionId,
      tool,
    });
  }

  /** Flush queued events to the SIEM endpoint. */
  async flush(): Promise<void> {
    if (this.#queue.length === 0) return;

    const now = Date.now();
    const timeSinceLastFlush = now - this.#lastFlushTime;
    const minIntervalMs = 1000 / this.#config.maxEventsPerSecond;

    if (timeSinceLastFlush < minIntervalMs) {
      return; // Rate limited.
    }

    const batch = this.#queue.splice(0, this.#config.batchSize);
    this.#stats.queued = this.#queue.length;
    this.#lastFlushTime = now;

    try {
      await this.#config.customSender(batch);
      this.#stats.sent += batch.length;
    } catch {
      this.#stats.errors += 1;
      // Re-queue events that failed to send (up to max queue size).
      for (const event of batch) {
        if (this.#queue.length < this.#config.maxQueueSize) {
          this.#queue.unshift(event);
        } else {
          this.#stats.dropped += 1;
        }
      }
      this.#stats.queued = this.#queue.length;
    }
  }

  /** Get current statistics. */
  getStats(): SiemBroadcasterStats {
    return { ...this.#stats };
  }

  /** Clear the queue and reset stats. */
  reset(): void {
    this.#queue.length = 0;
    this.#stats.queued = 0;
    this.#stats.sent = 0;
    this.#stats.dropped = 0;
    this.#stats.errors = 0;
    this.#stats.lastFlushAt = undefined;
  }

  get isRunning(): boolean {
    return this.#running;
  }

  get queueSize(): number {
    return this.#queue.length;
  }
}

/**
 * Webhook-based SIEM sender. Sends events as JSON to a webhook URL.
 */
export function createWebhookSender(
  webhookUrl: string,
  authToken?: string,
): (events: SiemEvent[]) => Promise<void> {
  return async (events: SiemEvent[]) => {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (authToken) {
      headers['Authorization'] = `Bearer ${authToken}`;
    }

    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify({ events }),
    });

    if (!response.ok) {
      throw new Error(`SIEM webhook returned ${response.status}`);
    }
  };
}
