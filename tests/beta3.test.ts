import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdir, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runCheck } from '../packages/core/src/cli/commands/check.js';
import { runPolicyTest } from '../packages/core/src/cli/commands/policy.js';
import { resolveOutputFormat, writeEvent } from '../packages/core/src/cli/stream.js';

/**
 * 0.2.0-beta.3 suite — enterprise-readiness round:
 *  - P0: `--output-format streaming-json` (NDJSON) on check / scan /
 *    policy test / session stats for log-shipper ingestion. Results must
 *    stream per item (not after the batch), every line must be a complete
 *    JSON object, and text mode must stay byte-for-byte the default.
 */

const FIXTURE_DIR = join(tmpdir(), 'vark-beta3-tests');

async function writeFixture(name: string, content: string): Promise<string> {
  const path = join(FIXTURE_DIR, name);
  await writeFile(path, content, 'utf8');
  return path;
}

beforeEach(async () => {
  await mkdir(FIXTURE_DIR, { recursive: true });
});

afterEach(async () => {
  await rm(FIXTURE_DIR, { recursive: true, force: true });
  vi.restoreAllMocks();
});

describe('--output-format validation', () => {
  it('defaults to text for undefined and "text"', () => {
    expect(resolveOutputFormat(undefined)).toBe('text');
    expect(resolveOutputFormat('text')).toBe('text');
  });

  it('accepts streaming-json', () => {
    expect(resolveOutputFormat('streaming-json')).toBe('streaming-json');
  });

  it('rejects unknown formats loudly instead of silently falling back', () => {
    expect(() => resolveOutputFormat('yaml')).toThrow('unknown output format "yaml"');
    expect(() => resolveOutputFormat('json')).toThrow('expected: text | streaming-json');
  });
});

describe('runCheck streams results per payload', () => {
  it('invokes onResult once per file, in batch order, with the same results', async () => {
    await writeFixture('a-benign.json', JSON.stringify({ tool: 'read_file', args: { path: './workspace/data.json' } }));
    await writeFixture('b-blocked.json', JSON.stringify({ tool: 'run_command', args: { command: 'cat file.txt; rm -rf /' } }));
    await writeFixture('c-invalid.json', '{ not valid json');

    const streamed: unknown[] = [];
    const results = await runCheck(join(FIXTURE_DIR, '*.json'), {}, (result) => {
      // The callback must fire before runCheck returns — that is the whole
      // point of streaming. JSON round-trip proves each event is NDJSON-safe.
      streamed.push(JSON.parse(JSON.stringify(result)));
    });

    expect(results).toHaveLength(3);
    expect(streamed).toHaveLength(3);
    // In-order delivery: streamed[i] mirrors results[i] field-for-field.
    expect(streamed).toEqual(results.map((r) => JSON.parse(JSON.stringify(r))));

    const blocked = streamed.find((r) => (r as { file: string }).file.endsWith('b-blocked.json')) as Record<string, unknown>;
    expect(blocked.success).toBe(false);
    expect(blocked.blockedBy).toBe('CIRCUIT_BREAKER');

    const malformed = streamed.find((r) => (r as { file: string }).file.endsWith('c-invalid.json')) as Record<string, unknown>;
    expect(malformed.success).toBe(false);
    expect(malformed.blockedBy).toBe('EXECUTION_ERROR');
  });

  it('works without a callback (text mode stays untouched)', async () => {
    await writeFixture('only.json', JSON.stringify({ tool: 't1', args: {} }));
    const results = await runCheck(join(FIXTURE_DIR, 'only.json'), {});
    expect(results).toHaveLength(1);
    expect(results[0]!.success).toBe(true);
  });
});

describe('writeEvent NDJSON framing', () => {
  it('writes exactly one newline-terminated JSON object per event', () => {
    const written: string[] = [];
    const spy = vi.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown) => {
      written.push(String(chunk));
      return true;
    });

    writeEvent({ type: 'summary', command: 'check', ok: true, passed: 2, blocked: 0 });
    writeEvent({ type: 'error', command: 'scan', message: 'boom' });

    expect(written).toHaveLength(2);
    for (const line of written) {
      expect(line.endsWith('\n')).toBe(true);
      const parsed = JSON.parse(line.trim()) as { type: string; command: string };
      expect(typeof parsed.type).toBe('string');
      expect(typeof parsed.command).toBe('string');
    }
    expect((JSON.parse(written[0]!.trim()) as { ok: boolean }).ok).toBe(true);
    expect((JSON.parse(written[1]!.trim()) as { message: string }).message).toBe('boom');
    spy.mockRestore();
  });
});

describe('policy test quiet mode (keeps stdout pure NDJSON)', () => {
  const policyWithoutTests = JSON.stringify({ config: {}, tools: [] });

  it('suppresses the "No tests found" banner when quiet', async () => {
    const path = await writeFixture('policy-empty.json', policyWithoutTests);
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await runPolicyTest(path, { quiet: true });
    expect(result.results).toHaveLength(0);
    expect(log).not.toHaveBeenCalled();
  });

  it('still prints the banner in text mode', async () => {
    const path = await writeFixture('policy-empty.json', policyWithoutTests);
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    await runPolicyTest(path);
    expect(log).toHaveBeenCalledTimes(1);
    expect(String(log.mock.calls[0]![0])).toContain('No tests found');
  });
});
