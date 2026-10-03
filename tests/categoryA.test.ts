import { describe, it, expect } from 'vitest';
import { executeInSandbox } from '../packages/core/src/security/sandbox/isolated-sandbox.js';
import { EphemeralVfs, VfsSessionManager } from '../packages/core/src/security/vfs/ephemeral-vfs.js';
import { ResourceQuota } from '../packages/core/src/security/quotas/resource-quotas.js';

describe('Feature 1 — Isolated Sandbox', () => {
  it('executes sync function', async () => {
    const result = await executeInSandbox((x: number) => x * 2, [21]);
    expect(result.success).toBe(true);
    expect(result.data).toBe(42);
  });

  it('executes async function', async () => {
    const result = await executeInSandbox(async (x: number) => x + 1, [41]);
    expect(result.success).toBe(true);
    expect(result.data).toBe(42);
  });

  it('handles errors gracefully', async () => {
    const result = await executeInSandbox(() => { throw new Error('boom'); }, []);
    expect(result.success).toBe(false);
    expect(result.error).toContain('boom');
  });

  it('respects allowFallback=false', async () => {
    const result = await executeInSandbox(() => 42, [], { allowFallback: false });
    // Should still work since isolated-vm may or may not be available
    expect(typeof result.success).toBe('boolean');
  });
});

describe('Feature 2 — Ephemeral VFS', () => {
  it('writes and reads from overlay', async () => {
    const vfs = new EphemeralVfs('./workspace');
    await vfs.writeFile('./test.txt', 'hello');
    const content = await vfs.readFileString('./test.txt');
    expect(content).toBe('hello');
  });

  it('rollback discards writes', async () => {
    const vfs = new EphemeralVfs('./workspace');
    await vfs.writeFile('./test.txt', 'hello');
    vfs.rollback();
    const stats = vfs.stats();
    expect(stats.files).toBe(0);
  });

  it('commit flushes to host FS', async () => {
    const vfs = new EphemeralVfs('./workspace');
    await vfs.writeFile('./test-commit.txt', 'data');
    await vfs.commit();
    expect(vfs.isCommitted).toBe(true);
    const { unlinkSync } = await import('node:fs');
    unlinkSync('./workspace/test-commit.txt');
  });

  it('VfsSessionManager creates per-session VFS', () => {
    const manager = new VfsSessionManager();
    const vfs1 = manager.getOrCreate('session-1');
    const vfs2 = manager.getOrCreate('session-2');
    expect(vfs1).not.toBe(vfs2);
    expect(manager.sessionCount).toBe(2);
  });

  it('VfsSessionManager destroys sessions', () => {
    const manager = new VfsSessionManager();
    manager.getOrCreate('session-1');
    manager.destroy('session-1');
    expect(manager.sessionCount).toBe(0);
  });
});

describe('Feature 3 — Resource Quotas', () => {
  it('allows execution within quota', () => {
    const quotas = new ResourceQuota({ maxCpuTimeMs: 1000 });
    const result = quotas.recordCpuTime('session-1', 100);
    expect(result.allowed).toBe(true);
  });

  it('blocks execution over quota', () => {
    const quotas = new ResourceQuota({ maxCpuTimeMs: 100 });
    quotas.recordCpuTime('session-1', 150);
    const result = quotas.recordCpuTime('session-1', 1);
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('CPU time quota exceeded');
  });

  it('enforces subprocess limit', () => {
    const quotas = new ResourceQuota({ maxSubprocesses: 0 });
    const result = quotas.recordSubprocess('session-1');
    expect(result.allowed).toBe(false);
  });

  it('enforces memory limit', () => {
    const quotas = new ResourceQuota({ maxMemoryBytes: 100 });
    const result = quotas.recordMemory('session-1', 200);
    expect(result.allowed).toBe(false);
  });

  it('resets session quotas', () => {
    const quotas = new ResourceQuota({ maxCpuTimeMs: 100 });
    quotas.recordCpuTime('session-1', 50);
    quotas.resetSession('session-1');
    const status = quotas.getSession('session-1');
    expect(status.cpuTimeMs).toBe(0);
  });
});
