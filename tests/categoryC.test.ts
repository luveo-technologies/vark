import { describe, it, expect } from 'vitest';
import { HitlGate, DEFAULT_HITL_CAPABILITIES } from '../packages/core/src/gates/hitl-gate.js';
import { DagFlowEnforcer, COMMON_DAG_PATTERNS } from '../packages/core/src/security/flow/dag-enforcer.js';
import { EphemeralCredentialManager, InMemoryCredentialProvider } from '../packages/core/src/security/credentials/ephemeral-credentials.js';

describe('Feature 9 — HITL Gate', () => {
  it('identifies high-risk capabilities', () => {
    const hitl = new HitlGate({ requiredCapabilities: DEFAULT_HITL_CAPABILITIES });
    const cap = hitl.requiresApproval('db:drop');
    expect(cap).toBeDefined();
    expect(cap!.risk).toBe('critical');
  });

  it('auto-approves non-HITL capabilities', async () => {
    const hitl = new HitlGate({ requiredCapabilities: DEFAULT_HITL_CAPABILITIES });
    const decision = await hitl.requestApproval('read_file', 'session-1', 'read', {});
    expect(decision.approved).toBe(true);
  });

  it('creates pending requests for HITL capabilities', async () => {
    const hitl = new HitlGate({ requiredCapabilities: DEFAULT_HITL_CAPABILITIES });
    const promise = hitl.requestApproval('db:drop', 'session-1', 'drop_table', { table: 'users' });
    expect(hitl.pendingCount).toBe(1);
    const pending = hitl.getPendingRequests();
    expect(pending.length).toBe(1);
    expect(pending[0]!.status).toBe('pending');
    // Clean up by denying
    hitl.deny(pending[0]!.requestId, 'test');
    const decision = await promise;
    expect(decision.approved).toBe(false);
  });

  it('approves pending requests', async () => {
    const hitl = new HitlGate({ requiredCapabilities: DEFAULT_HITL_CAPABILITIES });
    const promise = hitl.requestApproval('stripe:refund', 'session-1', 'refund', { amount: 100 });
    const pending = hitl.getPendingRequests();
    hitl.approve(pending[0]!.requestId, 'admin');
    const decision = await promise;
    expect(decision.approved).toBe(true);
    expect(decision.decidedBy).toBe('admin');
  });
});

describe('Feature 10 — DAG Flow Enforcer', () => {
  it('allows execution when no dependencies', () => {
    const dag = new DagFlowEnforcer({ nodes: COMMON_DAG_PATTERNS.payment });
    const result = dag.checkExecution('session-1', 'verify_cart');
    expect(result.allowed).toBe(true);
  });

  it('blocks execution when dependencies missing', () => {
    const dag = new DagFlowEnforcer({ nodes: COMMON_DAG_PATTERNS.payment });
    const result = dag.checkExecution('session-1', 'execute_payment');
    expect(result.allowed).toBe(false);
    expect(result.missingDependencies.length).toBeGreaterThan(0);
  });

  it('allows execution after dependencies met', () => {
    const dag = new DagFlowEnforcer({ nodes: COMMON_DAG_PATTERNS.payment });
    dag.recordExecution('session-1', 'verify_cart');
    dag.recordExecution('session-1', 'check_inventory');
    const result = dag.checkExecution('session-1', 'execute_payment');
    expect(result.allowed).toBe(true);
  });

  it('enforces max executions', () => {
    const dag = new DagFlowEnforcer({
      nodes: [{ tool: 'deploy', description: 'Deploy', dependsOn: [], maxExecutions: 1 }],
    });
    dag.recordExecution('session-1', 'deploy');
    const result = dag.checkExecution('session-1', 'deploy');
    expect(result.allowed).toBe(false);
  });

  it('tracks execution order', () => {
    const dag = new DagFlowEnforcer({ nodes: COMMON_DAG_PATTERNS.payment });
    dag.recordExecution('session-1', 'verify_cart');
    dag.recordExecution('session-1', 'check_inventory');
    const order = dag.getExecutionOrder('session-1');
    expect(order).toEqual(['verify_cart', 'check_inventory']);
  });
});

describe('Feature 11 — Ephemeral Credentials', () => {
  it('fetches and scrubs credentials', async () => {
    const provider = new InMemoryCredentialProvider('test');
    provider.register('resource-1', 'secret-token-123');
    const manager = new EphemeralCredentialManager({ providers: [provider] });

    let seenValue = '';
    await manager.withCredential(
      { type: 'test', resource: 'resource-1' },
      async (cred) => {
        seenValue = cred.value;
      },
    );

    expect(seenValue).toBe('secret-token-123');
    expect(manager.activeCount).toBe(0);
  });

  it('throws for unknown provider', async () => {
    const manager = new EphemeralCredentialManager({ providers: [] });
    await expect(
      manager.withCredential({ type: 'unknown', resource: 'x' }, async () => undefined),
    ).rejects.toThrow('No credential provider');
  });

  it('scrubs all active credentials', async () => {
    const provider = new InMemoryCredentialProvider('test');
    provider.register('r1', 'token1');
    provider.register('r2', 'token2');
    const manager = new EphemeralCredentialManager({ providers: [provider] });

    // Manually add credentials to active set
    await manager.withCredential({ type: 'test', resource: 'r1' }, async () => undefined);
    await manager.scrubAll();
    expect(manager.activeCount).toBe(0);
  });
});
