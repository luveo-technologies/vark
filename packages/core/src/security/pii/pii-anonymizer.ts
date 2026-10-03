/**
 * Reversible PII Anonymization
 *
 * Masks sensitive PII (emails, SSNs, credit cards, phone numbers) with
 * session-scoped deterministic tokens (`[USER_REF_1]`) and securely reverses
 * them only at authorized boundary egress.
 *
 * The anonymization is deterministic within a session: the same PII value
 * always maps to the same token, so tool logic that depends on consistency
 * continues to work.
 */

import { createHash, randomBytes } from 'node:crypto';

export type PiiType = 'email' | 'ssn' | 'credit_card' | 'phone' | 'ip_address' | 'api_key';

export interface PiiMatch {
  type: PiiType;
  start: number;
  end: number;
  value: string;
  token: string;
}

export interface PiiScanResult {
  /** Text with PII replaced by tokens. */
  anonymized: string;
  /** All PII matches found. */
  matches: PiiMatch[];
  /** Mapping from token to original value (for reversal). */
  tokenMap: Map<string, string>;
}

export interface PiiConfig {
  /** Salt for deterministic token generation. @default random per session */
  salt?: string;
  /** Custom PII patterns. */
  customPatterns?: Array<{ type: PiiType; pattern: RegExp }>;
}

const PII_PATTERNS: Array<{ type: PiiType; pattern: RegExp }> = [
  { type: 'email', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { type: 'ssn', pattern: /\b\d{3}-\d{2}-\d{4}\b/g },
  { type: 'credit_card', pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g },
  { type: 'phone', pattern: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g },
  { type: 'ip_address', pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g },
  { type: 'api_key', pattern: /\b(?:sk|pk|ak|key|token|secret)_[A-Za-z0-9_-]{16,}\b/gi },
];

/**
 * Session-scoped PII anonymizer. Deterministic within a session.
 */
export class PiiAnonymizer {
  readonly #salt: string;
  readonly #customPatterns: Array<{ type: PiiType; pattern: RegExp }>;
  readonly #tokenMap = new Map<string, string>();
  readonly #valueToToken = new Map<string, string>();
  #counter = 0;

  constructor(config: PiiConfig = {}) {
    this.#salt = config.salt ?? randomBytes(16).toString('hex');
    this.#customPatterns = config.customPatterns ?? [];
  }

  /** Anonymize PII in text, replacing with deterministic session tokens. */
  anonymize(text: string): PiiScanResult {
    const allPatterns = [...PII_PATTERNS, ...this.#customPatterns];
    const matches: PiiMatch[] = [];
    const tokenMap = new Map<string, string>();

    // Collect all matches first, then replace from end to start to preserve indices.
    for (const { type, pattern } of allPatterns) {
      pattern.lastIndex = 0;
      for (const match of text.matchAll(pattern)) {
        const value = match[0];
        const start = match.index ?? 0;
        const token = this.#getOrCreateToken(value);
        matches.push({ type, start, end: start + value.length, value, token });
        tokenMap.set(token, value);
      }
    }

    // Sort by start position descending so replacements don't shift indices.
    matches.sort((a, b) => b.start - a.start);

    let anonymized = text;
    for (const match of matches) {
      anonymized = anonymized.slice(0, match.start) + match.token + anonymized.slice(match.end);
    }

    return { anonymized, matches, tokenMap };
  }

  /** Reverse anonymization, restoring original PII values. */
  denormalize(text: string): string {
    let result = text;
    for (const [token, value] of this.#tokenMap) {
      result = result.split(token).join(value);
    }
    return result;
  }

  /** Check if a token is a valid anonymization token. */
  isToken(token: string): boolean {
    return this.#tokenMap.has(token);
  }

  /** Get the original value for a token. */
  getTokenValue(token: string): string | undefined {
    return this.#tokenMap.get(token);
  }

  /** Get all token mappings. */
  getAllTokens(): ReadonlyMap<string, string> {
    return new Map(this.#tokenMap);
  }

  /** Clear all token mappings. */
  clear(): void {
    this.#tokenMap.clear();
    this.#valueToToken.clear();
    this.#counter = 0;
  }

  get tokenCount(): number {
    return this.#tokenMap.size;
  }

  #getOrCreateToken(value: string): string {
    const existing = this.#valueToToken.get(value);
    if (existing) return existing;

    this.#counter += 1;
    const hash = createHash('sha256').update(this.#salt + value).digest('hex').slice(0, 8);
    const token = `[USER_REF_${this.#counter}_${hash}]`;
    this.#tokenMap.set(token, value);
    this.#valueToToken.set(value, token);
    return token;
  }
}

/**
 * Create a session-scoped anonymizer with a fixed salt.
 */
export function createPiiAnonymizer(sessionId: string, config?: Omit<PiiConfig, 'salt'>): PiiAnonymizer {
  const salt = createHash('sha256').update(`vark-pii-${sessionId}`).digest('hex');
  return new PiiAnonymizer({ ...config, salt });
}
