/**
 * Output DLP & Secret Redactor.
 *
 * Scans **incoming arguments** (before `run()`) and **raw tool output**
 * (before it re-enters the LLM context) for credentials and masks them as
 * `[REDACTED_SECRET: <TYPE>]`.
 *
 * Scanners are applied in priority order: specific token formats claim their
 * span first, so `AWS_SECRET_ACCESS_KEY=AKIA…` redacts as `AWS_KEY` (the
 * value) rather than swallowing the whole line as a generic `.env` pair.
 * Overlapping matches are merged, so a key embedded in a private key block is
 * reported once, by the outer pattern.
 */

import type { DlpConfig } from './types.js';
import { decodeEncodedLayers } from './security/sanitization/normalizer.js';

/** Maximum nesting depth walked in argument / output values. */
const MAX_DEPTH = 12;

export interface DlpMatch {
  type: string;
  start: number;
  end: number;
}

export interface DlpScanResult {
  /** Input text with every match replaced by `[REDACTED_SECRET: <TYPE>]`. */
  text: string;
  redacted: number;
  /** Distinct secret types found. */
  types: string[];
  matches: DlpMatch[];
}

export interface DlpValueResult {
  /** Deep copy of the value with every string redacted. */
  value: unknown;
  redacted: number;
  types: string[];
}

interface SecretPattern {
  type: string;
  regex: RegExp;
  /**
   * Optional post-filter on the matched text. Return false to drop the hit.
   * Used where shape alone over-matches (Luhn check digits, entropy floors).
   */
  verify?: (match: string) => boolean;
}

/** Luhn check-digit validation for payment card numbers. */
export function luhnCheck(digits: string): boolean {
  const nums = digits.replace(/\D/g, '');
  if (nums.length < 13 || nums.length > 19) return false;
  let sum = 0;
  let double = false;
  for (let i = nums.length - 1; i >= 0; i -= 1) {
    let digit = Number(nums[i]);
    if (double) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    double = !double;
  }
  return sum % 10 === 0;
}

/** Shannon entropy in bits per character. */
export function shannonEntropy(text: string): number {
  if (text.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const char of text) freq.set(char, (freq.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / text.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Minimum entropy for an opaque token to count as secret-shaped.
 * Hex UUIDs top out near 4.0 bits/char; base64 session tokens, API secrets
 * and key material sit well above 4.5.
 */
export const HIGH_ENTROPY_THRESHOLD = 4.5;

/** Minimum token length for the entropy heuristic (avoids prose words). */
export const HIGH_ENTROPY_MIN_LENGTH = 32;

const BUILT_IN_PATTERNS: readonly SecretPattern[] = [
  {
    type: 'PRIVATE_KEY',
    regex:
      /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]{0,8192}?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
  },
  { type: 'ANTHROPIC_KEY', regex: /\bsk-ant-[A-Za-z0-9_-]{10,}\b/g },
  { type: 'OPENAI_KEY', regex: /\bsk-[A-Za-z0-9_-]{20,}\b/g },
  { type: 'AWS_KEY', regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { type: 'JWT', regex: /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b/g },
  { type: 'GITHUB_TOKEN', regex: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g },
  { type: 'SLACK_TOKEN', regex: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g },
  { type: 'STRIPE_KEY', regex: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  { type: 'BEARER_TOKEN', regex: /\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b/gi },
  {
    type: 'ENV_CREDENTIAL',
    regex:
      /\b[A-Z0-9_]*(?:API_?KEY|SECRET(?:_?KEY)?|PASS(?:WORD|WD)?|TOKEN|CREDENTIALS?|PRIVATE_?KEY)[A-Z0-9_]*\s*=\s*[^\s'"`]+/gi,
  },
  {
    type: 'CREDIT_CARD',
    regex: /\b(?:\d[-\s]?){13,19}\b/g,
    verify: (match) => luhnCheck(match),
  },
  { type: 'SSN', regex: /\b\d{3}-\d{2}-\d{4}\b/g },
  {
    // Last by design: specific formats above claim their spans first, so
    // this only fires on otherwise-unrecognized opaque tokens. Private-key
    // bodies without markers, session tokens and API secrets land here.
    type: 'HIGH_ENTROPY_SECRET',
    regex: /[A-Za-z0-9_+\-/=]{32,}/g,
    verify: (match) => shannonEntropy(match) >= HIGH_ENTROPY_THRESHOLD,
  },
];

function asGlobal(regex: RegExp): RegExp {
  return regex.flags.includes('g') ? regex : new RegExp(regex.source, `${regex.flags}g`);
}

/**
 * Only JSON-shaped values are copied. Class instances, `Buffer`, streams and
 * `Response` objects are passed through untouched — flattening them into a
 * plain object would silently break the tool.
 */
export function isPlainContainer(node: object): boolean {
  if (Array.isArray(node)) return true;
  const proto = Object.getPrototypeOf(node);
  return proto === Object.prototype || proto === null;
}

function collectMatches(text: string, patterns: readonly SecretPattern[]): DlpMatch[] {
  const occupied: Array<[number, number]> = [];
  const hits: DlpMatch[] = [];

  for (const { type, regex, verify } of patterns) {
    const scanner = asGlobal(regex);
    for (const match of text.matchAll(scanner)) {
      const start = match.index ?? 0;
      const length = match[0].length;
      if (length === 0) continue;
      if (verify && !verify(match[0])) continue;
      const end = start + length;
      if (occupied.some(([from, to]) => start < to && end > from)) continue;
      occupied.push([start, end]);
      hits.push({ type, start, end });
    }
  }

  return hits.sort((a, b) => a.start - b.start);
}

function patternsFrom(config?: DlpConfig): SecretPattern[] {
  if (config?.patterns && config.patterns.length > 0) {
    const custom = config.patterns.map(({ type, pattern }) => ({ type, regex: pattern }));
    return [...BUILT_IN_PATTERNS, ...custom];
  }
  return [...BUILT_IN_PATTERNS];
}

/** Locate secrets without modifying the text. */
export function scanSecrets(text: string, config?: DlpConfig): DlpMatch[] {
  if (!text || config?.enabled === false) return [];
  return collectMatches(text, patternsFrom(config));
}

/** Redact every secret in a string. */
export function redactText(text: string, config?: DlpConfig): DlpScanResult {
  const empty: DlpScanResult = { text, redacted: 0, types: [], matches: [] };
  if (typeof text !== 'string' || text.length === 0 || config?.enabled === false) return empty;

  const matches = collectMatches(text, patternsFrom(config));
  if (matches.length === 0) return empty;

  let out = '';
  let cursor = 0;
  for (const match of matches) {
    out += text.slice(cursor, match.start);
    out += `[REDACTED_SECRET: ${match.type}]`;
    cursor = match.end;
  }
  out += text.slice(cursor);

  const types = [...new Set(matches.map((match) => match.type))];
  return { text: out, redacted: matches.length, types, matches };
}

/**
 * Deep-redact every string inside an argument / output value.
 * Non-string primitives are returned untouched; the input object is never
 * mutated (a copy is returned).
 */
export function redactValue(value: unknown, config?: DlpConfig): DlpValueResult {
  if (config?.enabled === false) return { value, redacted: 0, types: [] };

  const types = new Set<string>();
  let redacted = 0;

  const walk = (node: unknown, depth: number): unknown => {
    if (typeof node === 'string') {
      let scan = redactText(node, config);
      if (scan.redacted === 0) {
        // Parity with `vark scan`: a secret hidden behind an encoding is
        // still a secret. Scan strict-decoded variants (marker-gated, so
        // opaque tokens never qualify); a hit means the whole string is an
        // exfil carrier — replace it wholesale, since the encoded form is
        // the secret itself.
        for (const variant of decodeEncodedLayers(node)) {
          const hidden = redactText(variant.text, config);
          if (hidden.redacted > 0) {
            scan = {
              text: `[REDACTED_SECRET: ${hidden.types.join(', ')}]`,
              redacted: hidden.redacted,
              types: hidden.types,
              matches: hidden.matches,
            };
            break;
          }
        }
      }
      redacted += scan.redacted;
      for (const type of scan.types) types.add(type);
      return scan.text;
    }
    if (depth > MAX_DEPTH) return node;
    if (node !== null && typeof node === 'object') {
      if (!isPlainContainer(node)) return node;
      if (Array.isArray(node)) return node.map((child) => walk(child, depth + 1));
      const copy: Record<string, unknown> = {};
      for (const [key, child] of Object.entries(node)) copy[key] = walk(child, depth + 1);
      return copy;
    }
    return node;
  };

  return { value: walk(value, 0), redacted, types: [...types] };
}
