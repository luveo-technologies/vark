/**
 * Environment-variable configuration.
 *
 * `VARK_*` variables supply defaults for configuration the programmatic
 * `VarkConfig` left unset. Precedence: **explicit config > environment >
 * built-in default** — an environment variable never overrides a field the
 * caller set in code, and values that fail to parse are ignored rather than
 * throwing (a bad env var must not crash a security runtime at boot).
 *
 * Supported variables (each maps onto exactly one `VarkConfig` field):
 *
 * | Variable                        | Field                            |
 * |---------------------------------|----------------------------------|
 * | `VARK_ISOLATION`                | `isolation`                      |
 * | `VARK_DLP_MODE`                 | `dlp.mode`                       |
 * | `VARK_INJECTION_MODE`           | `indirectInjection.mode`         |
 * | `VARK_ANOMALY_MAX_CALLS_PER_MIN`| `anomaly.maxCallsPerMinute`      |
 * | `VARK_ANOMALY_MAX_IDENTICAL_CALLS` | `anomaly.maxIdenticalCalls`   |
 * | `VARK_SESSION_TTL_MS`           | `anomaly.sessionTTLMs`           |
 * | `VARK_FREEZE_ON_INJECTION_BLOCK`| `anomaly.freezeOnInjectionBlock` |
 * | `VARK_SCHEMA_STRICT`            | `schema.strict`                  |
 * | `VARK_AUDIT_HMAC_KEY`           | `audit.hmacKey`                  |
 *
 * `VARK_SIEM_WEBHOOK_URL` is read by `vark audit tail --alert` and
 * `VARK_AUDIT_PATH` by the `vark audit …` CLI commands (default log path).
 */

import type { VarkConfig } from './types.js';

type Env = Record<string, string | undefined>;

/** Positive finite integer, or undefined when absent/invalid. */
function asPositiveInt(value: string | undefined): number | undefined {
  if (value === undefined || value.trim() === '') return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : undefined;
}

/** Boolean from `true|1` / `false|0`, or undefined when absent/invalid. */
function asBool(value: string | undefined): boolean | undefined {
  if (value === 'true' || value === '1') return true;
  if (value === 'false' || value === '0') return false;
  return undefined;
}

/** Member of a fixed set, or undefined when absent/invalid. */
function asEnum<T extends string>(value: string | undefined, allowed: readonly T[]): T | undefined {
  return allowed.includes(value as T) ? (value as T) : undefined;
}

/**
 * Apply `VARK_*` environment defaults onto `config`. Pure with respect to
 * the input (returns a new object); nested objects are only rebuilt when
 * an environment variable actually contributed a value.
 */
export function applyEnvOverrides(config: VarkConfig, env: Env = process.env): VarkConfig {
  const out: VarkConfig = { ...config };

  if (out.isolation === undefined) {
    const mode = asEnum(env.VARK_ISOLATION, ['process', 'wasm', 'mock'] as const);
    if (mode !== undefined) out.isolation = mode;
  }

  const dlpMode = asEnum(env.VARK_DLP_MODE, ['redact', 'block'] as const);
  if (dlpMode !== undefined) out.dlp = { mode: dlpMode, ...out.dlp };

  const injectionMode = asEnum(env.VARK_INJECTION_MODE, ['sanitize', 'block', 'flag'] as const);
  if (injectionMode !== undefined) out.indirectInjection = { mode: injectionMode, ...out.indirectInjection };

  const maxCallsPerMinute = asPositiveInt(env.VARK_ANOMALY_MAX_CALLS_PER_MIN);
  const maxIdenticalCalls = asPositiveInt(env.VARK_ANOMALY_MAX_IDENTICAL_CALLS);
  const sessionTTLMs = asPositiveInt(env.VARK_SESSION_TTL_MS);
  const freezeOnInjectionBlock = asBool(env.VARK_FREEZE_ON_INJECTION_BLOCK);
  if (
    maxCallsPerMinute !== undefined ||
    maxIdenticalCalls !== undefined ||
    sessionTTLMs !== undefined ||
    freezeOnInjectionBlock !== undefined
  ) {
    out.anomaly = {
      ...(maxCallsPerMinute !== undefined ? { maxCallsPerMinute } : {}),
      ...(maxIdenticalCalls !== undefined ? { maxIdenticalCalls } : {}),
      ...(sessionTTLMs !== undefined ? { sessionTTLMs } : {}),
      ...(freezeOnInjectionBlock !== undefined ? { freezeOnInjectionBlock } : {}),
      ...out.anomaly,
    };
  }

  const schemaStrict = asBool(env.VARK_SCHEMA_STRICT);
  if (schemaStrict !== undefined) out.schema = { strict: schemaStrict, ...out.schema };

  const hmacKey = env.VARK_AUDIT_HMAC_KEY;
  if (hmacKey !== undefined && hmacKey !== '' && out.audit?.hmacKey === undefined) {
    out.audit = { ...out.audit, hmacKey };
  }

  return out;
}
