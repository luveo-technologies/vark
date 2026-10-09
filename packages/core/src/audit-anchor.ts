/**
 * Audit anchors — external checkpoints against an append-only trail.
 *
 * Both `AuditLogger.verify()` and `vark audit verify` recompute the chain
 * *from whichever record the log starts at*: that localises tampering but
 * cannot see records that are **gone** (ring-buffer trim, `head` of a log, or
 * an attacker truncating the suffix — all look identical from inside).
 *
 * An anchor pins a specific `{ seq, hash }` **outside** the log (a sidecar
 * file you ship elsewhere, optionally POSTed to a webhook witness), so
 * `checkAuditAnchors()` can later answer the questions the chain cannot:
 *
 * - records the anchor pins still exist?  → truncation / roll detection
 * - their hashes are still identical?     → rewrite detection
 * - the chain under them still recomputes? → in-place edit detection
 *
 * Verification is fail-closed: `createAuditAnchor()` refuses to attest a
 * trail whose chain does not recompute.
 */

import { createHash, createHmac } from 'node:crypto';
import type { AuditEntry } from './types.js';
import { stableStringify } from './audit-logger.js';

/** One external checkpoint of the trail head (or any pinned record). */
export interface AuditAnchor {
  /** `seq` of the anchored record. */
  seq: number;
  /** The record's stored hash — the checkpoint value. */
  hash: string;
  /** ISO-8601 timestamp of anchoring. */
  anchoredAt: string;
  /** Number of records in the log when the anchor was cut. */
  totalEntries: number;
}

export interface ChainVerifyResult {
  ok: boolean;
  checked: number;
  /** `seq` of the first record that failed recomputation. */
  brokenAt?: number;
}

export type AnchorCreateResult =
  | { ok: true; anchor: AuditAnchor }
  | { ok: false; reason: 'empty' | 'broken-chain'; detail: string };

export interface AnchorCheckResult {
  ok: boolean;
  checked: number;
  reason?: 'no-anchors' | 'truncated' | 'hash-mismatch' | 'broken-chain';
  detail?: string;
}

/** Digest one record body exactly like `AuditLogger.sign` (HMAC when keyed). */
function digest(body: Record<string, unknown>, key?: string | Uint8Array): string {
  const canonical = stableStringify(body);
  if (key) return createHmac('sha256', key).update(canonical).digest('hex');
  return createHash('sha256').update(canonical).digest('hex');
}

/**
 * Recompute the whole chain starting at `entries[0]` (a ring-buffer-trimmed
 * log is internally consistent: linkage starts wherever the log starts —
 * losing records is what anchors detect). `key` is required to validate an
 * `audit.hmacKey` trail; without it, HMAC links cannot recompute.
 */
export function verifyAuditChain(
  entries: AuditEntry[],
  key?: string | Uint8Array,
): ChainVerifyResult {
  const first = entries[0];
  if (!first) return { ok: true, checked: 0 };

  let prevHash = first.prevHash;
  let expectedSeq = first.seq;
  let checked = 0;
  for (const entry of entries) {
    if (entry.seq !== expectedSeq || entry.prevHash !== prevHash) {
      return { ok: false, checked, brokenAt: entry.seq };
    }
    const { hash: entryHash, ...body } = entry;
    if (digest({ ...body, prevHash }, key) !== entryHash) {
      return { ok: false, checked, brokenAt: entry.seq };
    }
    prevHash = entryHash;
    expectedSeq += 1;
    checked += 1;
  }
  return { ok: true, checked };
}

/**
 * Cut an anchor for the current trail head. Refuses (fail-closed) when the
 * chain does not recompute — a broken trail must never be attested.
 */
export function createAuditAnchor(
  entries: AuditEntry[],
  opts: { key?: string | Uint8Array; now?: Date } = {},
): AnchorCreateResult {
  const head = entries[entries.length - 1];
  if (!head) {
    return { ok: false, reason: 'empty', detail: 'trail has no records to anchor' };
  }
  const chain = verifyAuditChain(entries, opts.key);
  if (!chain.ok) {
    return {
      ok: false,
      reason: 'broken-chain',
      detail:
        `hash chain broken at seq ${chain.brokenAt} — refusing to anchor ` +
        '(if the trail is HMAC-signed, set VARK_AUDIT_HMAC_KEY so it can be verified)',
    };
  }
  return {
    ok: true,
    anchor: {
      seq: head.seq,
      hash: head.hash,
      anchoredAt: (opts.now ?? new Date()).toISOString(),
      totalEntries: entries.length,
    },
  };
}

/**
 * Verify stored anchors against the log. Anchor-specific failures are
 * reported first (they are the more precise diagnosis), then the chain.
 */
export function checkAuditAnchors(
  entries: AuditEntry[],
  anchors: AuditAnchor[],
  opts: { key?: string | Uint8Array } = {},
): AnchorCheckResult {
  if (anchors.length === 0) {
    return {
      ok: false,
      checked: 0,
      reason: 'no-anchors',
      detail: 'anchor file contains no anchors',
    };
  }

  for (const [i, anchor] of anchors.entries()) {
    const entry = entries.find((e) => e.seq === anchor.seq);
    if (!entry) {
      const last = entries[entries.length - 1];
      return {
        ok: false,
        checked: i,
        reason: 'truncated',
        detail:
          `anchor #${i + 1} pins seq ${anchor.seq} but the log ends at seq ${last?.seq ?? 0} — ` +
          'the anchored records are gone (truncated, rolled, or rebuilt)',
      };
    }
    if (entry.hash !== anchor.hash) {
      return {
        ok: false,
        checked: i,
        reason: 'hash-mismatch',
        detail:
          `anchor #${i + 1} pins seq ${anchor.seq} = ${anchor.hash.slice(0, 16)}… but the log has ` +
          `${entry.hash.slice(0, 16)}… — the record was rewritten after anchoring`,
      };
    }
  }

  const chain = verifyAuditChain(entries, opts.key);
  if (!chain.ok) {
    return {
      ok: false,
      checked: anchors.length,
      reason: 'broken-chain',
      detail: `hash chain broken at seq ${chain.brokenAt} (the anchors themselves still match)`,
    };
  }
  return { ok: true, checked: anchors.length };
}
