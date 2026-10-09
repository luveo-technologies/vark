/**
 * Redis-backed session state store (shared anomaly-guard state).
 *
 * Zero dependencies on purpose: the store talks to whatever Redis client
 * the host application already runs (ioredis, node-redis with a one-line
 * wrapper, a managed-platform client) through a single injected `eval`
 * method — vark never opens its own connections, so TLS, clusters,
 * reconnection and pooling stay the client's job.
 *
 * Layout (prefix default `vark:session`):
 *   `<prefix>:<sessionId>`        → JSON {@link SessionRecord}
 *   `<prefix>:<sessionId>:ver`    → version counter (integer)
 *
 * Writes are atomic via one Lua script (compare version → write record →
 * INCR version → optional PEXPIRE), so concurrent instances never overwrite
 * each other's accounting: a stale writer gets `false`, reloads, and
 * re-evaluates against fresh state.
 */

import type { LoadedSession, SessionRecord, StateStore } from './state-store.js';

/** ioredis-compatible client shape (node-redis: wrap `eval` — see docs). */
export interface RedisEvalClient {
  eval(script: string, numberOfKeys: number, ...args: Array<string | number>): Promise<unknown>;
}

export interface RedisStateStoreOptions {
  client: RedisEvalClient;
  /**
   * Optional ioredis-style `scan` for `list()` (needed by `sessions()` /
   * `sweepExpired()`): `scan(cursor, 'MATCH', pattern, 'COUNT', n)`.
   */
  scan?: (cursor: number, matchPattern: string, count: number) => Promise<[string, string[]]>;
  /** Key prefix. @default 'vark:session' */
  prefix?: string;
  /** Optional key TTL in ms, refreshed on every write. @default 0 (none) */
  ttlMs?: number;
}

/** CAS write: KEYS = [record, version]; ARGV = [expected, json, ttl]. */
const SAVE_SCRIPT = `
local cur = redis.call('GET', KEYS[2])
if ARGV[1] == '' then
  if cur then return 0 end
elseif cur ~= ARGV[1] then
  return 0
end
redis.call('SET', KEYS[1], ARGV[2])
redis.call('INCR', KEYS[2])
if tonumber(ARGV[3]) > 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[3])
  redis.call('PEXPIRE', KEYS[2], ARGV[3])
end
return 1
`;

/** Atomic read of both keys: KEYS = [record, version]. */
const LOAD_SCRIPT = `
local rec = redis.call('GET', KEYS[1])
local ver = redis.call('GET', KEYS[2])
return {rec, ver}
`;

const DELETE_SCRIPT = `
return redis.call('DEL', KEYS[1], KEYS[2])
`;

export class RedisStateStore implements StateStore {
  readonly #client: RedisEvalClient;
  readonly #scanFn: RedisStateStoreOptions['scan'];
  readonly #prefix: string;
  readonly #ttlMs: number;

  constructor(options: RedisStateStoreOptions) {
    this.#client = options.client;
    this.#scanFn = options.scan;
    this.#prefix = options.prefix ?? 'vark:session';
    this.#ttlMs = options.ttlMs ?? 0;
  }

  #keys(id: string): [string, string] {
    return [`${this.#prefix}:${id}`, `${this.#prefix}:${id}:ver`];
  }

  async load(id: string): Promise<LoadedSession | undefined> {
    const [recordKey, versionKey] = this.#keys(id);
    const reply = (await this.#client.eval(LOAD_SCRIPT, 2, recordKey, versionKey)) as [
      string | null,
      string | null,
    ];
    const [raw, version] = reply ?? [null, null];
    if (raw === null || raw === undefined) return undefined;
    const record = JSON.parse(raw) as SessionRecord;
    return { record, version: Number(version ?? '0') };
  }

  async save(id: string, record: SessionRecord, expectedVersion: number | undefined): Promise<boolean> {
    const [recordKey, versionKey] = this.#keys(id);
    const reply = await this.#client.eval(
      SAVE_SCRIPT,
      2,
      recordKey,
      versionKey,
      expectedVersion === undefined ? '' : String(expectedVersion),
      JSON.stringify(record),
      String(this.#ttlMs),
    );
    return Number(reply) === 1;
  }

  async delete(id: string): Promise<void> {
    const [recordKey, versionKey] = this.#keys(id);
    await this.#client.eval(DELETE_SCRIPT, 2, recordKey, versionKey);
  }

  async clear(): Promise<void> {
    for (const id of await this.list()) await this.delete(id);
  }

  async list(): Promise<string[]> {
    if (!this.#scanFn) {
      throw new Error(
        'RedisStateStore.list() requires the scan option — pass your client\'s scan() so sessions()/sweepExpired() can enumerate keys',
      );
    }
    const ids = new Set<string>();
    let cursor = 0;
    do {
      const [next, keys] = await this.#scanFn(cursor, `${this.#prefix}:*`, 100);
      cursor = Number(next);
      for (const key of keys) {
        if (key.endsWith(':ver')) continue;
        ids.add(key.slice(this.#prefix.length + 1));
      }
    } while (cursor !== 0);
    return [...ids];
  }
}
