/**
 * `vark audit verify` command handler
 *
 * Verify the cryptographic integrity of an append-only audit log hash chain.
 */

import { readFile } from 'node:fs/promises';
import { extname, resolve } from 'node:path';
import type { AuditEntry } from '../../types.js';
import { GENESIS_HASH, stableStringify } from '../../audit-logger.js';
import { createHash } from 'node:crypto';
import pkg from 'picocolors';
const { green, red, yellow, bold, dim } = pkg;
import { printBanner, printSummaryLine, chainDots } from '../ux.js';

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