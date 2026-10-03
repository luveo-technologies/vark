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
}

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

  for (const { type, regex } of patterns) {
    const scanner = asGlobal(regex);
    for (const match of text.matchAll(scanner)) {
      const start = match.index ?? 0;
      const length = match[0].length;
      if (length === 0) continue;
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
      const scan = redactText(node, config);
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
