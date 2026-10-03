/**
 * Canary / Honeytoken Trap
 *
 * Automatically seeds tool outputs and context with session-bound honeytokens
 * (fake keys, URLs, credentials). If a honeytoken is echoed back into a tool
 * input, execution is halted and the session is locked — a strong signal that
 * the agent is being manipulated by an injection attack.
 */

import { randomBytes, createHash } from 'node:crypto';

export interface Honeytoken {
  /** Unique identifier for this honeytoken. */
  id: string;
  /** The fake secret value. */
  value: string;
  /** Type of honeytoken (api_key, url, credential, etc.). */
  type: 'api_key' | 'url' | 'credential' | 'token';
  /** Session this honeytoken belongs to. */
  sessionId: string;
  /** When the honeytoken was created. */
  createdAt: number;
}

export interface CanaryEvent {
  honeytoken: Honeytoken;
  /** The input that contained the honeytoken. */
  detectedIn: string;
  /** When the detection occurred. */
  detectedAt: number;
}

export interface CanaryConfig {
  /** Number of honeytokens to seed per session. @default 3 */
  tokensPerSession?: number;
  /** Automatically halt session on detection. @default true */
  haltOnDetection?: boolean;
  /** Custom token generator. */
  generateToken?: (type: Honeytoken['type']) => string;
}

const DEFAULT_TOKENS_PER_SESSION = 3;

function generateApiKey(): string {
  return `sk-${randomBytes(24).toString('hex')}`;
}

function generateUrl(): string {
  const id = randomBytes(8).toString('hex');
  return `https://canary-${id}.example.com/collect`;
}

function generateCredential(): string {
  return `canary_${randomBytes(16).toString('hex')}`;
}

function generateToken(): string {
  return `ct_${randomBytes(20).toString('base64url')}`;
}

const GENERATORS: Record<Honeytoken['type'], () => string> = {
  api_key: generateApiKey,
  url: generateUrl,
  credential: generateCredential,
  token: generateToken,
};

/**
 * Manages honeytoken lifecycle: seeding, detection, and session locking.
 */
export class CanaryManager {
  readonly #config: Required<CanaryConfig>;
  readonly #tokens = new Map<string, Honeytoken>();
  readonly #sessionTokens = new Map<string, Set<string>>();
  readonly #lockedSessions = new Set<string>();
  readonly #events: CanaryEvent[] = [];

  constructor(config: CanaryConfig = {}) {
    this.#config = {
      tokensPerSession: config.tokensPerSession ?? DEFAULT_TOKENS_PER_SESSION,
      haltOnDetection: config.haltOnDetection ?? true,
      generateToken: config.generateToken ?? ((type) => GENERATORS[type]()),
    };
  }

  /** Seed honeytokens for a session. Returns the created tokens. */
  seedSession(sessionId: string): Honeytoken[] {
    const existing = this.#sessionTokens.get(sessionId);
    if (existing && existing.size > 0) {
      return [...existing].map((id) => this.#tokens.get(id)!).filter(Boolean);
    }

    const tokens: Honeytoken[] = [];
    const types: Honeytoken['type'][] = ['api_key', 'url', 'credential'];

    for (let i = 0; i < this.#config.tokensPerSession; i += 1) {
      const type = types[i % types.length] ?? 'api_key';
      const token: Honeytoken = {
        id: createHash('sha256').update(randomBytes(32)).digest('hex').slice(0, 16),
        value: this.#config.generateToken(type),
        type,
        sessionId,
        createdAt: Date.now(),
      };
      this.#tokens.set(token.id, token);
      tokens.push(token);
    }

    const ids = new Set(tokens.map((t) => t.id));
    this.#sessionTokens.set(sessionId, ids);
    return tokens;
  }

  /** Get all honeytokens for a session. */
  getSessionTokens(sessionId: string): Honeytoken[] {
    const ids = this.#sessionTokens.get(sessionId);
    if (!ids) return [];
    return [...ids].map((id) => this.#tokens.get(id)!).filter(Boolean);
  }

  /**
   * Check if any honeytoken appears in the given text.
   * Returns the first match, or null if none found.
   */
  detect(text: string): Honeytoken | null {
    for (const token of this.#tokens.values()) {
      if (text.includes(token.value)) return token;
    }
    return null;
  }

  /**
   * Scan input text for honeytokens. If found, records an event and
   * optionally locks the session.
   */
  scanInput(sessionId: string, text: string): CanaryEvent | null {
    const token = this.detect(text);
    if (!token) return null;

    const event: CanaryEvent = {
      honeytoken: token,
      detectedIn: text.slice(0, 200),
      detectedAt: Date.now(),
    };
    this.#events.push(event);

    if (this.#config.haltOnDetection) {
      this.#lockedSessions.add(sessionId);
    }

    return event;
  }

  /** Check if a session is locked due to honeytoken detection. */
  isSessionLocked(sessionId: string): boolean {
    return this.#lockedSessions.has(sessionId);
  }

  /** Unlock a session (e.g., after manual review). */
  unlockSession(sessionId: string): void {
    this.#lockedSessions.delete(sessionId);
  }

  /** Get all detection events. */
  getEvents(): readonly CanaryEvent[] {
    return [...this.#events];
  }

  /** Get events for a specific session. */
  getSessionEvents(sessionId: string): CanaryEvent[] {
    return this.#events.filter((e) => e.honeytoken.sessionId === sessionId);
  }

  /** Clear all honeytokens and events for a session. */
  clearSession(sessionId: string): void {
    const ids = this.#sessionTokens.get(sessionId);
    if (ids) {
      for (const id of ids) this.#tokens.delete(id);
      this.#sessionTokens.delete(sessionId);
    }
    this.#lockedSessions.delete(sessionId);
  }

  /** Clear all state. */
  clearAll(): void {
    this.#tokens.clear();
    this.#sessionTokens.clear();
    this.#lockedSessions.clear();
    this.#events.length = 0;
  }

  get tokenCount(): number {
    return this.#tokens.size;
  }

  get lockedSessionCount(): number {
    return this.#lockedSessions.size;
  }
}
