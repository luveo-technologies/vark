import { describe, it, expect } from 'vitest';
import { validateSchema, coerceValue } from '../packages/core/src/schema-validator.js';
import { scanValueSync, redactBuffer } from '../packages/core/src/dlp-extended.js';
import { FileAuditSink, MultiAuditSink } from '../packages/core/src/audit-sink.js';
import { resolveIsolationMode, isTrueIsolationAvailable } from '../packages/core/src/isolated-vm.js';
import type { AuditEntry } from '../packages/core/src/types.js';

describe('Phase 0 — Schema Validator', () => {
  it('validates a simple object', () => {
    const result = validateSchema(
      { name: 'test', age: 25 },
      { type: 'object', properties: { name: { type: 'string' }, age: { type: 'integer' } }, required: ['name'] },
    );
    expect(result.valid).toBe(true);
  });

  it('rejects missing required properties', () => {
    const result = validateSchema(
      { age: 25 },
      { type: 'object', properties: { name: { type: 'string' } }, required: ['name'] },
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('name');
  });

  it('rejects wrong types', () => {
    const result = validateSchema(
      { age: 'not-a-number' },
      { type: 'object', properties: { age: { type: 'integer' } } },
    );
    expect(result.valid).toBe(false);
  });

  it('coerces string numbers to integers', () => {
    const result = coerceValue('42', { type: 'integer' });
    expect(result.coerced).toBe(true);
    expect(result.value).toBe(42);
  });

  it('validates email format', () => {
    const result = validateSchema(
      { email: 'test@example.com' },
      { type: 'object', properties: { email: { type: 'string', format: 'email' } } },
    );
    expect(result.valid).toBe(true);
  });

  it('rejects invalid email format', () => {
    const result = validateSchema(
      { email: 'not-an-email' },
      { type: 'object', properties: { email: { type: 'string', format: 'email' } } },
    );
    expect(result.valid).toBe(false);
  });

  it('validates nested objects', () => {
    const result = validateSchema(
      { user: { name: 'test', address: { city: 'NYC' } } },
      {
        type: 'object',
        properties: {
          user: {
            type: 'object',
            properties: {
              name: { type: 'string' },
              address: { type: 'object', properties: { city: { type: 'string' } } },
            },
          },
        },
      },
    );
    expect(result.valid).toBe(true);
  });

  it('validates arrays with items schema', () => {
    const result = validateSchema(
      [1, 2, 3],
      { type: 'array', items: { type: 'integer' }, minItems: 1 },
    );
    expect(result.valid).toBe(true);
  });

  it('rejects arrays with wrong item types', () => {
    const result = validateSchema(
      [1, 'two', 3],
      { type: 'array', items: { type: 'integer' } },
    );
    expect(result.valid).toBe(false);
  });
});

describe('Phase 0 — Extended DLP', () => {
  it('scans Buffer for secrets', () => {
    const buffer = Buffer.from('AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE');
    const result = scanValueSync(buffer);
    expect(result.redacted).toBeGreaterThan(0);
    expect(result.types).toContain('AWS_KEY');
  });

  it('scans class instances', () => {
    class Config {
      apiKey = 'AKIAIOSFODNN7EXAMPLE';
      toString() { return `Config(${this.apiKey})`; }
    }
    const result = scanValueSync(new Config());
    expect(result.redacted).toBeGreaterThan(0);
  });

  it('redacts Buffer without mutating original', () => {
    const original = Buffer.from('key=AKIAIOSFODNN7EXAMPLE');
    const result = redactBuffer(original);
    expect(result.redacted).toBe(1);
    expect(original.toString()).toContain('AKIAIOSFODNN7EXAMPLE');
    expect(result.buffer.toString()).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });

  it('handles empty values', () => {
    const result = scanValueSync('');
    expect(result.redacted).toBe(0);
  });
});

describe('Phase 0 — Audit Sink', () => {
  it('FileAuditSink writes JSON lines', async () => {
    const path = './test-audit.jsonl';
    const sink = new FileAuditSink(path);
    const entry = { seq: 1, hash: 'abc' } as unknown as AuditEntry;
    sink.write(entry);
    await sink.flush();
    await sink.close();
    const { readFileSync, unlinkSync } = await import('node:fs');
    const content = readFileSync(path, 'utf8');
    expect(content).toContain('"seq":1');
    unlinkSync(path);
  });

  it('MultiAuditSink fans out to multiple sinks', async () => {
    const path1 = './test-audit-1.jsonl';
    const path2 = './test-audit-2.jsonl';
    const sink1 = new FileAuditSink(path1);
    const sink2 = new FileAuditSink(path2);
    const multi = new MultiAuditSink([sink1, sink2]);
    const entry = { seq: 1, hash: 'abc' } as unknown as AuditEntry;
    multi.write(entry);
    await multi.flush();
    await multi.close();
    const { readFileSync, unlinkSync } = await import('node:fs');
    expect(readFileSync(path1, 'utf8')).toContain('"seq":1');
    expect(readFileSync(path2, 'utf8')).toContain('"seq":1');
    unlinkSync(path1);
    unlinkSync(path2);
  });
});

describe('Phase 0 — Isolated VM', () => {
  it('resolves isolation mode', async () => {
    const result = await resolveIsolationMode('process');
    expect(result.mode).toBe('process');
    expect(result.trueIsolation).toBe(false);
  });

  it('checks availability without throwing', async () => {
    const available = await isTrueIsolationAvailable();
    expect(typeof available).toBe('boolean');
  });
});
