/**
 * `vark audit` command handlers: verify, tail, export.
 *
 * Verify recomputes the cryptographic hash chain; tail streams records
 * color-coded by decision; export renders JSON, CSV, or a styled HTML report.
 */

import { appendFile, readFile, watch } from 'node:fs/promises';
import { extname, resolve } from 'node:path';
import type { AuditEntry } from '../../types.js';
import { stableStringify } from '../../audit-logger.js';
import { createHash, createHmac } from 'node:crypto';
import { checkAuditAnchors, createAuditAnchor } from '../../audit-anchor.js';
import type { AnchorCheckResult, AuditAnchor } from '../../audit-anchor.js';
import { signWebhookBody } from '../../gates/hitl-gate.js';
import pkg from 'picocolors';
const { green, red, yellow, bold, dim } = pkg;
import { printBanner, printSummaryLine, chainDots, decisionChip } from '../ux.js';

/** Extended entry for verification (same as AuditEntry but with optional fields for partial logs) */
export type AuditLogEntry = AuditEntry;

export interface VerifyResult {
  valid: boolean;
  totalRecords: number;
  checked: number;
  brokenAt?: number;
  firstBrokenRecord?: AuditLogEntry;
}

export async function runAuditVerify(
  logPath: string,
): Promise<VerifyResult> {
  const resolvedPath = resolve(logPath);
  const entries = await loadAuditLog(resolvedPath);

  if (entries.length === 0) {
    return {
      valid: true,
      totalRecords: 0,
      checked: 0,
    };
  }

  // HMAC-signed trails (audit.hmacKey) only recompute with the key.
  const key = process.env.VARK_AUDIT_HMAC_KEY || undefined;
  return verifyChain(entries, key);
}

async function loadAuditLog(filePath: string): Promise<AuditLogEntry[]> {
  const content = await readFile(filePath, 'utf8');
  const ext = extname(filePath).toLowerCase();

  let entries: AuditLogEntry[];

  if (ext === '.json') {
    const parsed = JSON.parse(content);
    if (Array.isArray(parsed)) {
      entries = parsed;
    } else {
      entries = [parsed];
    }
  } else if (ext === '.jsonl' || ext === '.ndjson' || ext === '.log') {
    entries = content
      .trim()
      .split('\n')
      .filter((line) => line.trim())
      .map((line) => JSON.parse(line));
  } else {
    const lines = content.trim().split('\n').filter((line) => line.trim());
    entries = lines.map((line) => JSON.parse(line));
  }

  entries.sort((a, b) => a.seq - b.seq);
  return entries;
}

/**
 * Recompute the chain. Starts at `entries[0]` — the same contract as
 * `AuditLogger.verify()` — so a ring-buffer-trimmed log stays valid; lost
 * records are what `audit anchor --check` detects (an anchor pins a `seq`
 * the chain alone can never prove still exists). HMAC-signed links
 * recompute only when `key` is provided (`$VARK_AUDIT_HMAC_KEY`).
 */
function verifyChain(entries: AuditLogEntry[], key?: string | Uint8Array): VerifyResult {
  if (entries.length === 0) {
    return { valid: true, totalRecords: 0, checked: 0 };
  }

  const first = entries[0]!;
  let prevHash = first.prevHash;
  let expectedSeq = first.seq;

  for (let i = 0; i < entries.length; i += 1) {
    const entry = entries[i]!;

    // Check sequence number
    if (entry.seq !== expectedSeq) {
      return {
        valid: false,
        totalRecords: entries.length,
        checked: i,
        brokenAt: expectedSeq,
        firstBrokenRecord: entry,
      };
    }

    // Check prevHash
    if (entry.prevHash !== prevHash) {
      return {
        valid: false,
        totalRecords: entries.length,
        checked: i,
        brokenAt: entry.seq,
        firstBrokenRecord: entry,
      };
    }

    // Recompute hash
    const { hash, prevHash: _, ...entryBody } = entry;
    const computedHash = computeEntryHash(entryBody, prevHash, key);

    if (computedHash !== entry.hash) {
      return {
        valid: false,
        totalRecords: entries.length,
        checked: i,
        brokenAt: entry.seq,
        firstBrokenRecord: entry,
      };
    }

    // Update for next iteration
    prevHash = entry.hash;
    expectedSeq += 1;
  }

  return {
    valid: true,
    totalRecords: entries.length,
    checked: entries.length,
  };
}

function computeEntryHash(
  body: Record<string, unknown>,
  prevHash: string,
  key?: string | Uint8Array,
): string {
  const bodyWithPrev = { ...body, prevHash };
  const canonical = stableStringify(bodyWithPrev);
  if (key) return createHmac('sha256', key).update(canonical).digest('hex');
  return createHash('sha256').update(canonical).digest('hex');
}

export function printVerifyResult(result: VerifyResult, elapsedMs?: number): void {
  printBanner('audit verify  ·  hash-chain integrity');

  console.log(`  chain:  ${chainDots(result.totalRecords, result.valid ? undefined : result.brokenAt)}`);
  console.log(`  scanned ${result.checked}/${result.totalRecords} records`);

  if (result.valid) {
    printSummaryLine(
      [green(`✔ VALID`), dim(`${result.totalRecords} records, 0 breaks`)],
      elapsedMs,
    );
  } else {
    console.log(`\n  ${red('✗ CORRUPTED')} — first break at ${bold(`seq ${result.brokenAt}`)}`);

    if (result.firstBrokenRecord) {
      console.log(`\n  ${yellow('First broken record:')}`);
      console.log(`    seq:       ${result.firstBrokenRecord.seq}`);
      console.log(`    timestamp: ${result.firstBrokenRecord.timestamp}`);
      console.log(`    tool:      ${result.firstBrokenRecord.tool}`);
      console.log(`    decision:  ${result.firstBrokenRecord.decision}`);
    }

    if (!process.env.VARK_AUDIT_HMAC_KEY) {
      console.log(
        `\n  ${dim('HMAC-signed trail? Set VARK_AUDIT_HMAC_KEY — it only verifies with the key.')}`,
      );
    }

    printSummaryLine(
      [red(`✘ CORRUPTED at seq ${result.brokenAt}`), dim(`${result.checked} verified before the break`)],
      elapsedMs,
    );

    process.exitCode = 1;
  }
}

// ── anchor ──────────────────────────────────────────────────────────────────

export type AnchorOutcome =
  | {
      kind: 'created';
      anchor: AuditAnchor;
      anchorsPath: string;
      total: number;
      webhookPosted: boolean;
      webhookError?: string;
    }
  | { kind: 'already'; anchor: AuditAnchor; anchorsPath: string }
  | { kind: 'refused'; reason: string; detail: string; anchorsPath: string }
  | { kind: 'checked'; check: AnchorCheckResult; anchorsPath: string; totalAnchors: number };

async function readAnchorsFile(path: string, required: boolean): Promise<AuditAnchor[]> {
  let raw: string;
  try {
    raw = await readFile(path, 'utf8');
  } catch (error) {
    if (!required && (error as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw error;
  }
  return raw
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as AuditAnchor);
}

/**
 * `vark audit anchor` — cut (or check) an external checkpoint of the trail
 * head. Sidecar defaults to `<log>.anchors.jsonl`; `--webhook` additionally
 * POSTs the anchor as an HMAC-signed witness. Exit contract (via the
 * printer): 0 = anchored/intact/already-anchored, 1 = refused or drifted,
 * 2 = unreadable log or anchor file (thrown).
 */
export async function runAuditAnchor(
  logPath: string,
  opts: { check?: boolean; outPath?: string; webhook?: string; secret?: string } = {},
): Promise<AnchorOutcome> {
  const resolvedPath = resolve(logPath);
  const anchorsPath = opts.outPath ? resolve(opts.outPath) : `${resolvedPath}.anchors.jsonl`;
  const key = process.env.VARK_AUDIT_HMAC_KEY || undefined;
  const entries = await loadEntries(resolvedPath);

  if (opts.check) {
    const anchors = await readAnchorsFile(anchorsPath, true); // missing file → throws → exit 2
    const check = checkAuditAnchors(entries, anchors, key ? { key } : {});
    return { kind: 'checked', check, anchorsPath, totalAnchors: anchors.length };
  }

  const created = createAuditAnchor(entries, key ? { key } : {});
  if (!created.ok) {
    return { kind: 'refused', reason: created.reason, detail: created.detail, anchorsPath };
  }

  // Idempotent: the identical head is already anchored (append-only file).
  const existing = await readAnchorsFile(anchorsPath, false);
  const duplicate = existing.some(
    (a) => a.seq === created.anchor.seq && a.hash === created.anchor.hash,
  );
  if (duplicate) return { kind: 'already', anchor: created.anchor, anchorsPath };

  await appendFile(anchorsPath, `${JSON.stringify(created.anchor)}\n`, 'utf8');

  let webhookPosted = false;
  let webhookError: string | undefined;
  if (opts.webhook) {
    const body = JSON.stringify({
      event: 'audit.anchor',
      issuedAt: new Date().toISOString(),
      anchor: created.anchor,
      log: resolvedPath,
    });
    try {
      const headers: Record<string, string> = {
        'content-type': 'application/json',
        'user-agent': 'vark-audit',
      };
      if (opts.secret) headers['x-vark-signature'] = signWebhookBody(opts.secret, body);
      const response = await fetch(opts.webhook, {
        method: 'POST',
        headers,
        body,
        signal: AbortSignal.timeout(5_000),
      });
      if (!response.ok) throw new Error(`witness responded ${response.status}`);
      webhookPosted = true;
    } catch (error) {
      webhookError = error instanceof Error ? error.message : String(error);
    }
  }

  return {
    kind: 'created',
    anchor: created.anchor,
    anchorsPath,
    total: entries.length,
    webhookPosted,
    webhookError,
  };
}

export function printAuditAnchor(outcome: AnchorOutcome, elapsedMs?: number): void {
  const checking = outcome.kind === 'checked';
  printBanner(checking ? 'audit anchor  ·  checkpoint verification' : 'audit anchor  ·  external checkpoint');
  console.log(`  file:  ${dim('anchorsPath' in outcome ? outcome.anchorsPath : '')}`);

  switch (outcome.kind) {
    case 'created': {
      console.log(`  head:  seq ${outcome.anchor.seq} · ${dim(`${outcome.anchor.hash.slice(0, 16)}…`)}`);
      if (outcome.webhookError) {
        console.log(`  ${red(`✘ witness delivery failed: ${outcome.webhookError}`)}`);
        printSummaryLine(
          [red(`✘ anchor written locally but witness failed (seq ${outcome.anchor.seq})`), dim('retry once the endpoint recovers')],
          elapsedMs,
        );
        process.exitCode = 1;
        return;
      }
      if (outcome.webhookPosted) console.log(`  ${dim('witness: POSTed ✓')}`);
      printSummaryLine(
        [green(`✔ ANCHORED seq ${outcome.anchor.seq}`), dim(`${outcome.total} records in log`)],
        elapsedMs,
      );
      return;
    }
    case 'already': {
      console.log(`  head:  seq ${outcome.anchor.seq} · ${dim(`${outcome.anchor.hash.slice(0, 16)}…`)}`);
      printSummaryLine(
        [green('✔ already anchored'), dim(`seq ${outcome.anchor.seq} — nothing new to anchor`)],
        elapsedMs,
      );
      return;
    }
    case 'refused': {
      console.log(`  ${red(`✘ ${outcome.reason}`)}: ${outcome.detail}`);
      printSummaryLine([red('✘ REFUSED'), dim(outcome.detail)], elapsedMs);
      process.exitCode = 1;
      return;
    }
    case 'checked': {
      const { check } = outcome;
      console.log(`  ${dim(`${outcome.totalAnchors} anchor(s) on file`)}`);
      if (check.ok) {
        printSummaryLine(
          [green(`✔ INTACT — ${check.checked} anchor(s) hold`), dim('no truncation, no rewrite, chain recomputes')],
          elapsedMs,
        );
        return;
      }
      console.log(`  ${red(`✘ ${check.reason ?? 'failed'}`)}: ${check.detail ?? ''}`);
      printSummaryLine([red(`✘ DRIFTED (${check.reason ?? 'failed'})`), dim(check.detail ?? '')], elapsedMs);
      process.exitCode = 1;
      return;
    }
  }
}

// ── tail ────────────────────────────────────────────────────────────────────

/** Shared loader: NDJSON, JSON-lines, or a JSON array — sorted by seq. */
export async function loadEntries(logPath: string): Promise<AuditEntry[]> {
  return loadAuditLog(resolve(logPath));
}

export interface TailOptions {
  lines?: number;
  follow?: boolean;
  /**
   * Print a prominent alert line for security-relevant refusals
   * (injection, capability violations, freezes, …) as they stream in.
   */
  alert?: boolean;
  /** Webhook to POST alert entries to. Defaults to `$VARK_SIEM_WEBHOOK_URL`. */
  webhook?: string;
}

/** Decisions loud enough to warrant an operator alert while tailing. */
const ALERTABLE: ReadonlySet<string> = new Set([
  'CIRCUIT_BREAKER',
  'CAPABILITY_VIOLATION',
  'INDIRECT_INJECTION',
  'VELOCITY_EXCEEDED',
  'BUDGET_EXCEEDED',
  'SESSION_FROZEN',
  'DESCRIPTOR_PIN_VIOLATION',
  'HITL_DENIED',
  'LOOP_BLOCKED',
  'TIMEOUT',
  'ISOLATION_UNAVAILABLE',
  'AUDIT_UNAVAILABLE',
]);

/** Whether an entry deserves an alert line (refusal of a security gate). */
export function isAlertable(entry: AuditEntry): boolean {
  return entry.decision !== 'ALLOWED' && ALERTABLE.has(entry.decision);
}

/**
 * Print (and optionally webhook) an alert for a security-relevant entry.
 * The webhook POST is fire-and-forget: a dead endpoint must never break
 * the tail loop.
 */
export function emitAlert(entry: AuditEntry, webhook?: string): void {
  const url = webhook ?? process.env['VARK_SIEM_WEBHOOK_URL'];
  console.log(
    `  ${red('⚠ ALERT')} ${bold(entry.decision)} ${bold(entry.tool)} ` +
      `${dim(entry.sessionId)} — ${(entry.reason ?? 'refused').slice(0, 120)}`,
  );
  if (url) {
    void fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ type: 'threat', severity: 'warning', payload: entry }),
    }).catch(() => undefined);
  }
}

function formatEntry(entry: AuditEntry): string {
  const time = entry.timestamp.slice(11, 19);
  const redactions: string[] = [];
  if (entry.inputRedactions > 0) redactions.push(`in:${entry.inputRedactions}`);
  if (entry.outputRedactions > 0) redactions.push(`out:${entry.outputRedactions}`);
  if (entry.injectionSanitized > 0) redactions.push(`inj:${entry.injectionSanitized}`);
  const extra = redactions.length > 0 ? dim(` [${redactions.join(' ')}]`) : '';
  const reason = entry.blockedBy && entry.reason ? dim(` — ${entry.reason.slice(0, 90)}`) : '';
  return `  ${dim(time)}  ${decisionChip(entry.decision)} ${bold(entry.tool)} ${dim(`#${entry.seq}`)} ${dim(entry.sessionId)}${extra}${reason}`;
}

export async function runTail(logPath: string, options: TailOptions = {}): Promise<void> {
  const path = resolve(logPath);
  const entries = await loadEntries(path);
  const tailCount = options.lines ?? 10;
  for (const entry of entries.slice(-tailCount)) {
    console.log(formatEntry(entry));
    if (options.alert && isAlertable(entry)) emitAlert(entry, options.webhook);
  }
  if (!options.follow) return;

  console.log(dim(`  ── following ${path} (Ctrl+C to exit) ──`));
  let size = entries.length;
  const watcher = watch(path);
  const onSigint = (): void => {
    process.stdout.write('\n');
    process.exit(0);
  };
  process.on('SIGINT', onSigint);

  try {
    for await (const _event of watcher) {
      void _event;
      const fresh = await loadEntries(path);
      for (const entry of fresh.slice(size)) {
        console.log(formatEntry(entry));
        if (options.alert && isAlertable(entry)) emitAlert(entry, options.webhook);
      }
      size = fresh.length;
    }
  } finally {
    process.off('SIGINT', onSigint);
  }
}

// ── export ──────────────────────────────────────────────────────────────────

/** Export formats for `vark audit export`. */
export type ExportFormat = 'json' | 'csv' | 'html' | 'ndjson';

/** Minimal CSV escaping: quote fields containing commas, quotes or newlines. */
function csvCell(value: unknown): string {
  const text = value === undefined || value === null ? '' : String(value);
  return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

export function exportAudit(entries: AuditEntry[], format: ExportFormat): string {
  if (format === 'json') {
    return JSON.stringify(entries, null, 2);
  }
  if (format === 'ndjson') {
    return entries.map((e) => JSON.stringify(e)).join('\n');
  }
  if (format === 'csv') {
    const header = 'seq,timestamp,session,tool,decision,blockedBy,reason,ms,inspectMs,redactedIn,redactedOut,injectionStripped,tokensSaved,findings,prevHash,hash,sanitizedInputs';
    const rows = entries.map((e) =>
      [
        e.seq,
        e.timestamp,
        e.sessionId,
        e.tool,
        e.decision,
        e.blockedBy ?? '',
        e.reason ?? '',
        e.executionTimeMs,
        e.inspectionMs,
        e.inputRedactions,
        e.outputRedactions,
        e.injectionSanitized,
        e.tokensSaved,
        (e.findings ?? []).join('|'),
        e.prevHash,
        e.hash,
        JSON.stringify(e.sanitizedInputs ?? null),
      ]
        .map(csvCell)
        .join(','),
    );
    return [header, ...rows].join('\n');
  }
  // html — single-file styled report
  const rows = entries
    .map((e) => {
      const cls = e.decision === 'ALLOWED' ? 'ok' : 'bad';
      return `<tr class="${cls}"><td>${e.seq}</td><td>${e.timestamp}</td><td>${e.sessionId}</td><td>${e.tool}</td><td>${e.decision}</td><td>${e.blockedBy ?? ''}</td><td>${e.executionTimeMs}</td><td>${(e.reason ?? '').slice(0, 120)}</td></tr>`;
    })
    .join('\n');
  return `<!doctype html><html><head><meta charset="utf8"><title>vark audit report</title><style>body{font-family:monospace;background:#0b0e14;color:#c9d1d9;padding:2em}table{border-collapse:collapse;width:100%}td,th{border:1px solid #30363d;padding:4px 8px;font-size:12px}.ok td:nth-child(5){color:#3fb950}.bad td:nth-child(5){color:#f85149}h1{font-size:18px}</style></head><body><h1>🛡 vark audit report — ${entries.length} records</h1><table><tr><th>seq</th><th>time</th><th>session</th><th>tool</th><th>decision</th><th>gate</th><th>ms</th><th>reason</th></tr>${rows}</table></body></html>`;
}