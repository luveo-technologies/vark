import { describe, it, expect } from 'vitest';
import { ReplayEngine, DeterministicTimeSource, DeterministicRandomSource } from '../packages/core/src/security/replay/replay-engine.js';
import { SiemBroadcaster, createWebhookSender } from '../packages/core/src/security/telemetry/siem-broadcaster.js';

describe('Feature 14 — Replay Engine', () => {
  it('records and retrieves replays', () => {
    const engine = new ReplayEngine();
    const replay = engine.record({
      sessionId: 'session-1',
      tool: 'read_file',
      args: { path: './test.txt' },
      result: 'content',
      executionTimeMs: 1.5,
      timestamp: Date.now(),
      envSnapshot: {},
      mockCalls: [],
    });

    expect(replay.replayId).toBeDefined();
    const retrieved = engine.getReplay(replay.replayId);
    expect(retrieved).toBeDefined();
    expect(retrieved!.tool).toBe('read_file');
  });

  it('tracks replays by session', () => {
    const engine = new ReplayEngine();
    engine.record({
      sessionId: 'session-1', tool: 'a', args: {}, result: null,
      executionTimeMs: 1, timestamp: Date.now(), envSnapshot: {}, mockCalls: [],
    });
    engine.record({
      sessionId: 'session-1', tool: 'b', args: {}, result: null,
      executionTimeMs: 2, timestamp: Date.now(), envSnapshot: {}, mockCalls: [],
    });
    const replays = engine.getSessionReplays('session-1');
    expect(replays.length).toBe(2);
  });

  it('enforces max replays limit', () => {
    const engine = new ReplayEngine({ maxReplays: 2 });
    for (let i = 0; i < 5; i += 1) {
      engine.record({
        sessionId: 's', tool: `t${i}`, args: {}, result: null,
        executionTimeMs: 1, timestamp: Date.now(), envSnapshot: {}, mockCalls: [],
      });
    }
    expect(engine.replayCount).toBeLessThanOrEqual(2);
  });

  it('deterministic time source', () => {
    const time = new DeterministicTimeSource(1000);
    const t1 = time.now();
    const t2 = time.now();
    expect(t2).toBeGreaterThanOrEqual(t1);
  });

  it('deterministic random source', () => {
    const rand = new DeterministicRandomSource(42);
    const r1 = rand.random();
    const r2 = rand.random();
    expect(r1).not.toBe(r2);
    expect(r1).toBeGreaterThanOrEqual(0);
    expect(r1).toBeLessThan(1);
  });
});

describe('Feature 15 — SIEM Broadcaster', () => {
  it('queues events', () => {
    const broadcaster = new SiemBroadcaster({ customSender: async () => undefined });
    broadcaster.send({ type: 'audit', severity: 'info', timestamp: Date.now(), payload: {} });
    expect(broadcaster.queueSize).toBe(1);
  });

  it('flushes events', async () => {
    let received = 0;
    const broadcaster = new SiemBroadcaster({
      customSender: async (events) => { received += events.length; },
    });
    broadcaster.send({ type: 'audit', severity: 'info', timestamp: Date.now(), payload: {} });
    await broadcaster.flush();
    expect(received).toBe(1);
  });

  it('respects max queue size', () => {
    const broadcaster = new SiemBroadcaster({
      maxQueueSize: 2,
      customSender: async () => undefined,
    });
    for (let i = 0; i < 5; i += 1) {
      broadcaster.send({ type: 'audit', severity: 'info', timestamp: Date.now(), payload: {} });
    }
    expect(broadcaster.queueSize).toBeLessThanOrEqual(2);
  });

  it('tracks stats', async () => {
    const broadcaster = new SiemBroadcaster({ customSender: async () => undefined });
    broadcaster.send({ type: 'audit', severity: 'info', timestamp: Date.now(), payload: {} });
    await broadcaster.flush();
    const stats = broadcaster.getStats();
    expect(stats.sent).toBe(1);
  });

  it('creates webhook sender', async () => {
    const sender = createWebhookSender('https://example.com/webhook', 'token');
    expect(typeof sender).toBe('function');
  });
});
