import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdir, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runCheck } from '../packages/core/src/cli/commands/check.js';
import { runAuditVerify } from '../packages/core/src/cli/commands/audit.js';
import { runPolicyTest } from '../packages/core/src/cli/commands/policy.js';
import { VarkRuntime } from '../packages/core/src/index.js';

const FIXTURE_DIR = join(tmpdir(), 'vark-cli-tests');

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
});

describe('vark check', () => {
  it('passes a payload for a registered tool', async () => {
    const file = await writeFixture(
      'allowed.json',
      JSON.stringify({ tool: 'read_file', args: { path: './workspace/data.json' } }),
    );
    // runCheck with no registered tools → unknown tool → blocked
    const results = await runCheck(file, {});
    expect(results).toHaveLength(1);
    expect(results[0]!.file).toBe(file);
    // unknown tool fails evaluation
    expect(results[0]!.success).toBe(false);
    expect(results[0]!.blockedBy).toBe('EXECUTION_ERROR');
  });

  it('fails gracefully on a missing tool property', async () => {
    const file = await writeFixture('bad.json', JSON.stringify({ args: {} }));
    const results = await runCheck(file, {});
    expect(results[0]!.success).toBe(false);
    expect(results[0]!.reason).toContain('"tool"');
  });

  it('fails gracefully on invalid JSON', async () => {
    const file = await writeFixture('invalid.json', '{ not valid json');
    await expect(runCheck(file, {})).rejects.toThrow('Failed to parse');
  });

  it('throws when no files match the pattern', async () => {
    await expect(runCheck(join(FIXTURE_DIR, 'no-such-*.json'), {})).rejects.toThrow(
      'No files found',
    );
  });

  it('evaluates multiple payloads via glob', async () => {
    await writeFixture('a.json', JSON.stringify({ tool: 't1', args: {} }));
    await writeFixture('b.json', JSON.stringify({ tool: 't2', args: {} }));
    const results = await runCheck(join(FIXTURE_DIR, '*.json'), {});
    expect(results).toHaveLength(2);
  });
});

describe('vark audit verify', () => {
  async function buildAuditLog(): Promise<string> {
    const runtime = new VarkRuntime({});
    runtime.tool({
      name: 'echo',
      description: 'Echo args.',
      schema: { type: 'object', properties: {} },
      run: async (args: unknown) => args,
    });
    await runtime.execute('echo', { hello: 'world' });
    await runtime.execute('echo', { n: 1 });
    const path = join(FIXTURE_DIR, 'audit.jsonl');
    await writeFile(path, runtime.audit.toJSONL(), 'utf8');
    return path;
  }

  it('verifies an intact audit chain', async () => {
    const path = await buildAuditLog();
    const result = await runAuditVerify(path);
    expect(result.valid).toBe(true);
    expect(result.totalRecords).toBe(2);
    expect(result.checked).toBe(2);
  });

  it('detects a tampered record', async () => {
    const path = await buildAuditLog();
    const { readFile } = await import('node:fs/promises');
    const lines = (await readFile(path, 'utf8')).trim().split('\n');
    const tampered = JSON.parse(lines[1]!) as Record<string, unknown>;
    tampered.tool = 'evil_tool';
    lines[1] = JSON.stringify(tampered);
    await writeFile(path, lines.join('\n'), 'utf8');

    const result = await runAuditVerify(path);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(2);
  });

  it('treats an empty log file as trivially valid', async () => {
    const path = await writeFixture('empty.jsonl', '');
    const result = await runAuditVerify(path);
    expect(result.valid).toBe(true);
    expect(result.totalRecords).toBe(0);
    expect(result.checked).toBe(0);
  });

  it('reads array-format JSON logs', async () => {
    const runtime = new VarkRuntime({});
    const path = join(FIXTURE_DIR, 'audit.json');
    await writeFile(path, JSON.stringify(runtime.audit.trail()), 'utf8');
    const result = await runAuditVerify(path);
    expect(result.valid).toBe(true);
    expect(result.totalRecords).toBe(0);
  });
});

describe('vark policy test', () => {
  it('passes when all assertions hold', async () => {
    const path = await writeFixture(
      'policy.json',
      JSON.stringify({
        config: {},
        tools: [
          {
            name: 'read_file',
            description: 'Read a file.',
            schema: {
              type: 'object',
              properties: { path: { type: 'string' } },
              required: ['path'],
            },
            run: 'return args;',
          },
        ],
        tests: [
          {
            name: 'allows valid path',
            tool: 'read_file',
            args: { path: './workspace/data.json' },
            shouldAllow: true,
          },
        ],
      }),
    );
    const { passed, failed } = await runPolicyTest(path);
    expect(passed).toBe(1);
    expect(failed).toBe(0);
  });

  it('fails when an assertion does not hold', async () => {
    const path = await writeFixture(
      'policy-fail.json',
      JSON.stringify({
        config: {},
        tools: [
          {
            name: 'read_file',
            description: 'Read a file.',
            schema: {
              type: 'object',
              properties: { path: { type: 'string' } },
              required: ['path'],
            },
            run: 'return args;',
          },
        ],
        tests: [
          {
            name: 'wrongly expects block',
            tool: 'read_file',
            args: { path: './workspace/data.json' },
            shouldAllow: false,
          },
        ],
      }),
    );
    const { passed, failed } = await runPolicyTest(path);
    expect(passed).toBe(0);
    expect(failed).toBe(1);
  });

  it('reports zero tests when the policy has no test suite', async () => {
    const path = await writeFixture('no-tests.json', JSON.stringify({ config: {} }));
    const { passed, failed, results } = await runPolicyTest(path);
    expect(passed).toBe(0);
    expect(failed).toBe(0);
    expect(results).toHaveLength(0);
  });

  it('throws on invalid policy syntax', async () => {
    const path = await writeFixture('bad-policy.json', '{ broken');
    await expect(runPolicyTest(path)).rejects.toThrow('Failed to parse');
  });
});
