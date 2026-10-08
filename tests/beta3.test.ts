import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdir, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runCheck } from '../packages/core/src/cli/commands/check.js';
import { runPolicyTest } from '../packages/core/src/cli/commands/policy.js';
import { resolveOutputFormat, writeEvent } from '../packages/core/src/cli/stream.js';
import { resolveIsolationMode, isTrueIsolationAvailable } from '../packages/core/src/isolated-vm.js';
import { FileAuditSink } from '../packages/core/src/audit-sink.js';
import { VarkRuntime } from '../packages/core/src/index.js';
import type { AuditEntry } from '../packages/core/src/types.js';

/**
 * 0.2.0-beta.3 suite — enterprise-readiness round:
 *  - P0: `--output-format streaming-json` (NDJSON) on check / scan /
 *    policy test / session stats for log-shipper ingestion. Results must
 *    stream per item (not after the batch), every line must be a complete
 *    JSON object, and text mode must stay byte-for-byte the default.
 *  - P0: fail-closed on dependency loss — no true isolate boundary (or an
 *    unpersistable audit trail with `audit.failClosed`) refuses instead of
 *    silently degrading.
 */

// isolated-vm is an OPTIONAL dependency and absent from CI: runtime-level
// refusal tests are skipped on machines that happen to have it installed.
const IVM_AVAILABLE = await isTrueIsolationAvailable();

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

// ── P0-5: fail-closed on dependency loss ────────────────────────────────────

describe('fail-closed isolation', () => {
  const noopTool = {
    name: 'noop',
    description: 'No-op.',
    schema: { type: 'object', properties: {} },
    run: () => 'ok',
  };

  it('resolveIsolationMode refuses when wasm is unavailable and allowFallback is false', async () => {
    const resolved = await resolveIsolationMode('wasm', {
      allowFallback: false,
      isAvailable: async () => false,
    });
    expect(resolved.mode).toBe('process');
    expect(resolved.trueIsolation).toBe(false);
    expect(resolved.refusal).toContain('allowFallback is false');
    expect(resolved.refusal).toContain('isolated-vm');
  });

  it('resolveIsolationMode warns (never refuses) when fallback is allowed', async () => {
    const resolved = await resolveIsolationMode('wasm', { isAvailable: async () => false });
    expect(resolved.refusal).toBeUndefined();
    expect(resolved.warning).toContain('isolated-vm is not installed');
  });

  it('resolveIsolationMode reports true isolation when the isolate is available', async () => {
    const resolved = await resolveIsolationMode('wasm', {
      allowFallback: false,
      isAvailable: async () => true,
    });
    expect(resolved.mode).toBe('wasm');
    expect(resolved.trueIsolation).toBe(true);
    expect(resolved.refusal).toBeUndefined();
  });

  it.skipIf(IVM_AVAILABLE)('runtime refuses EVERY call with ISOLATION_UNAVAILABLE when allowFallback is false', async () => {
    const runtime = new VarkRuntime({ isolation: 'wasm', isolationConfig: { allowFallback: false } });
    runtime.tool(noopTool);

    const first = await runtime.execute('noop', {});
    expect(first.success).toBe(false);
    expect(first.blockedBy).toBe('ISOLATION_UNAVAILABLE');
    expect(first.error).toContain('allowFallback is false');

    // Fail-closed on dependency loss: the availability probe runs once, but
    // the refusal holds for every subsequent call — not just the first.
    const second = await runtime.execute('noop', {});
    expect(second.success).toBe(false);
    expect(second.blockedBy).toBe('ISOLATION_UNAVAILABLE');

    expect(runtime.audit.trail().at(-1)?.decision).toBe('ISOLATION_UNAVAILABLE');
  });

  it.skipIf(IVM_AVAILABLE)('default fallback still executes, with exactly one warning per runtime', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const runtime = new VarkRuntime({ isolation: 'wasm' });
    runtime.tool(noopTool);

    const result = await runtime.execute('noop', {});
    expect(result.success).toBe(true);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0]![0])).toContain('isolated-vm is not installed');

    await runtime.execute('noop', {});
    expect(warn).toHaveBeenCalledTimes(1); // warned once per runtime instance
  });
});

describe('fail-closed audit trail', () => {
  const noopTool = {
    name: 'noop',
    description: 'No-op.',
    schema: { type: 'object', properties: {} },
    run: () => 'ok',
  };

  /** Sink that throws until `recover()` — models a full disk / dead SIEM. */
  function toggleSink(): { sink: (entry: AuditEntry) => void; recover: () => void } {
    let failing = true;
    return {
      sink: (entry: AuditEntry): void => {
        if (failing) throw new Error('ENOSPC: disk full');
        void entry;
      },
      recover: (): void => {
        failing = false;
      },
    };
  }

  it('refuses before gate 1 while the sink is broken; the refusal probe restores service', async () => {
    const { sink, recover } = toggleSink();
    const runtime = new VarkRuntime({ audit: { failClosed: true, sink } });
    runtime.tool(noopTool);

    // Call 1 executes — the trail breaks during its own commit.
    const call1 = await runtime.execute('noop', {});
    expect(call1.success).toBe(true);
    expect(runtime.audit.degraded).toBe(true);

    // Call 2+ refuse before gate 1: no execution without a durable record.
    const call2 = await runtime.execute('noop', {});
    expect(call2.success).toBe(false);
    expect(call2.blockedBy).toBe('AUDIT_UNAVAILABLE');
    expect(call2.error).toContain('audit.failClosed');

    // Disk freed: the next refusal record's append probes the sink and
    // clears the degraded flag — recovery is automatic.
    recover();
    const call3 = await runtime.execute('noop', {});
    expect(call3.blockedBy).toBe('AUDIT_UNAVAILABLE');
    expect(runtime.audit.degraded).toBe(false);

    const call4 = await runtime.execute('noop', {});
    expect(call4.success).toBe(true);
  });

  it('best-effort mode (default) never refuses on sink failure', async () => {
    const runtime = new VarkRuntime({
      audit: {
        sink: (): void => {
          throw new Error('boom');
        },
      },
    });
    runtime.tool(noopTool);
    const result = await runtime.execute('noop', {});
    expect(result.success).toBe(true);
    // Visible for operators, but not enforced without audit.failClosed.
    expect(runtime.audit.degraded).toBe(true);
  });

  it('FileAuditSink with failClosed surfaces persistence failures synchronously', async () => {
    const dirAsFile = join(FIXTURE_DIR, 'eisdir-target');
    await mkdir(dirAsFile, { recursive: true }); // appendFile at this path always fails

    const errors: string[] = [];
    const sink = new FileAuditSink(dirAsFile, {
      failClosed: true,
      onError: (error) => errors.push(error.message),
    });
    const entry = { seq: 1 } as AuditEntry;

    // First attempt fails asynchronously on the internal queue.
    sink.write(entry);
    await sink.flush();
    expect(errors).toHaveLength(1);

    // The next write surfaces the previous failure synchronously (and its
    // queued probe re-arms the failure when the path is still broken).
    expect(() => sink.write(entry)).toThrow();
    await sink.flush();
    expect(errors).toHaveLength(2);

    await sink.close();
  });

  it('FileAuditSink without failClosed keeps swallowing errors (default unchanged)', async () => {
    const dirAsFile = join(FIXTURE_DIR, 'eisdir-default');
    await mkdir(dirAsFile, { recursive: true });

    const errors: string[] = [];
    const sink = new FileAuditSink(dirAsFile, { onError: (error) => errors.push(error.message) });
    const entry = { seq: 1 } as AuditEntry;

    sink.write(entry);
    await sink.flush();
    expect(errors).toHaveLength(1);
    expect(() => sink.write(entry)).not.toThrow();

    await sink.close();
  });
});
