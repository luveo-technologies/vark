/**
 * `vark audit` command handlers: verify, tail, export.
 *
 * Verify recomputes the cryptographic hash chain; tail streams records
 * color-coded by decision; export renders JSON, CSV, or a styled HTML report.
 */

import { readFile, watch } from 'node:fs/promises';
import { extname, resolve } from 'node:path';
import type { AuditEntry } from '../../types.js';
import { GENESIS_HASH, stableStringify } from '../../audit-logger.js';
import { createHash } from 'node:crypto';
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

  const result = verifyChain(entries);
  return result;
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

function verifyChain(entries: AuditLogEntry[]): VerifyResult {
  if (entries.length === 0) {
    return { valid: true, totalRecords: 0, checked: 0 };
  }

  let prevHash = GENESIS_HASH;
  let expectedSeq = 1;

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
    const computedHash = computeEntryHash(entryBody, prevHash);

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

function computeEntryHash(body: Record<string, unknown>, prevHash: string): string {
  const bodyWithPrev = { ...body, prevHash };
  const canonical = stableStringify(bodyWithPrev);
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

    printSummaryLine(
      [red(`✘ CORRUPTED at seq ${result.brokenAt}`), dim(`${result.checked} verified before the break`)],
      elapsedMs,
    );

    process.exitCode = 1;
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