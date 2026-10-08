import { describe, it, expect } from 'vitest';
import { inspectPayload } from '../packages/core/src/circuit-breaker.js';
import { decodeEncodedLayers } from '../packages/core/src/security/sanitization/normalizer.js';
import { VarkRuntime } from '../packages/core/src/index.js';

/**
 * Strict runtime decoding (gate 3, third pass): smuggled encodings are
 * blocked with decode provenance, while opaque tokens (hashes, UUIDs,
 * session tokens) pass untouched.
 */
describe('decodeEncodedLayers unit', () => {
  it('decodes nested base64→hex chains with provenance', () => {
    const variants = decodeEncodedLayers('NzI2ZDIwMmQ3MjY2MjAyZg==');
    const texts = variants.map((v) => v.text);
    expect(texts).toContain('rm -rf /');
    const terminal = variants.find((v) => v.text === 'rm -rf /');
    expect(terminal?.via).toEqual(['base64', 'hex']);
  });

  it('returns no variants for plain text', () => {
    expect(decodeEncodedLayers('ls -la workspace')).toEqual([]);
  });

  it('returns no variants for opaque tokens', () => {
    expect(decodeEncodedLayers('da39a3ee5e6b4b0d3255bfef95601890afd80709')).toEqual([]);
    expect(decodeEncodedLayers('550e8400-e29b-41d4-a716-446655440000')).toEqual([]);
  });
});

describe('circuit breaker strict decoding (gate 3, third pass)', () => {
  it.each([
    ['percent-encoded', 'run %72m%20-rf%20/', 'url'],
    ['base64', 'cm0gLXJmIC8=', 'base64'],
    ['hex', '726d202d7266202f', 'hex'],
  ])('blocks %s smuggled rm -rf with decode provenance', (_label, payload, via) => {
    const result = inspectPayload({ command: payload });
    expect(result.safe).toBe(false);
    expect(result.reason).toContain(`(decoded ${via})`);
  });

  it('blocks nested base64→hex chains', () => {
    const result = inspectPayload({ command: 'NzI2ZDIwMmQ3MjY2MjAyZg==' });
    expect(result.safe).toBe(false);
    expect(result.reason).toContain('(decoded base64');
  });

  it.each([
    ['git SHA', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'],
    ['uuid', '550e8400-e29b-41d4-a716-446655440000'],
    ['hex session token', 'a1b2c3d4e5f60718293a4b5c6d7e8f90'],
    ['base64 session token', 'c2Vzc2lvbi10b2tlbi0xMjM0NTY3ODkwMTIzNA=='],
    ['plain prose with a percent sign', 'save 20% off today, no code needed'],
  ])('lets opaque %s through untouched', (_label, payload) => {
    expect(inspectPayload({ note: payload }).safe).toBe(true);
  });

  it('blocks smuggled payloads end-to-end via execute()', async () => {
    const runtime = new VarkRuntime({});
    runtime.tool({
      name: 'cmd',
      description: 'Run a command.',
      schema: { type: 'object', properties: { command: { type: 'string' } } },
      run: async () => 'ok',
    });
    const result = await runtime.execute('cmd', { command: 'cm0gLXJmIC8=' });
    expect(result.success).toBe(false);
    expect(result.blockedBy).toBe('CIRCUIT_BREAKER');
    expect(result.error).toContain('(decoded base64)');
  });
});
