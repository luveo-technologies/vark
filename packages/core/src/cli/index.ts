#!/usr/bin/env node
/**
 * Vark CLI - Zero-trust security runtime for AI agent tool calls
 *
 * @packageDocumentation
 */

import { program } from 'commander';
import { watch } from 'node:fs';
import { runCheck, printCheckResults } from './commands/check.js';
import { runAuditVerify, printVerifyResult, runTail, exportAudit, loadEntries } from './commands/audit.js';
import type { ExportFormat } from './commands/audit.js';
import {
  runPolicyTest,
  printTestResults,
  signPolicyFile,
  verifyPolicyFile,
  generatePolicyKeyFiles,
  diffPolicyFiles,
  printPolicySign,
  printPolicyVerify,
  printPolicyKeygen,
  printPolicyDiff,
} from './commands/policy.js';
import { runScan, printScanResult } from './commands/scan.js';
import { runBench, printBenchReport } from './commands/bench.js';
import {
  runCanaryDemo,
  printCanaryDemo,
  runPiiScan,
  printPiiResult,
  runEntropyScan,
  printEntropyResult,
  runCompress,
  printCompressResult,
} from './commands/analyze.js';
import {
  runSessionStats,
  printGateExplanation,
  runDoctor,
  printDoctor,
  lintPolicy,
  printLint,
  initPolicy,
  printInit,
} from './commands/ops.js';
import { printSessionStats } from './commands/analyze.js';
import { resolveOutputFormat, writeEvent } from './stream.js';
import { readFile, writeFile } from 'node:fs/promises';
import pkg from 'picocolors';
const { red } = pkg;

let version = '0.1.2';
// Read version from package.json
try {
  const pkgContent = await readFile(new URL('../../package.json', import.meta.url), 'utf8');
  version = JSON.parse(pkgContent).version;
} catch {
  // Use default version
}

program
  .name('vark')
  .description('Zero-trust security runtime for AI agent tool calls')
  .version(version);

// ── check (+ --watch, --verbose) ────────────────────────────────────────────

program
  .command('check <file>')
  .description('Dry-run evaluate tool payload files against Vark security gates')
  .option('-c, --config <file>', 'Path to Vark config file')
  .option('-w, --watch', 'Re-run when matched files change')
  .option('-v, --verbose', 'Explain the blocking gate for each refusal')
  .option('--output-format <format>', 'Output format: text (default) | streaming-json (NDJSON)', 'text')
  .action(async (file: string, options: { config?: string; watch?: boolean; verbose?: boolean; outputFormat?: string }) => {
    let streaming: boolean;
    try {
      streaming = resolveOutputFormat(options.outputFormat) === 'streaming-json';
    } catch (error) {
      console.error(`${red('Error:')} ${error instanceof Error ? error.message : String(error)}`);
      process.exitCode = 1;
      return;
    }

    const runOnce = async (run: number): Promise<void> => {
      if (options.watch && run > 1 && !streaming) console.log(`\n  ── run #${run} ──`);
      const started = Date.now();
      try {
        let config: Record<string, unknown> = {};
        if (options.config) {
          const content = await readFile(options.config, 'utf8');
          config = JSON.parse(content);
        }

        const results = await runCheck(
          file,
          config,
          streaming ? (result) => writeEvent({ type: 'result', command: 'check', ...result }) : undefined,
        );
        if (streaming) {
          const passed = results.filter((r) => r.success).length;
          const blocked = results.length - passed;
          writeEvent({
            type: 'summary',
            command: 'check',
            passed,
            blocked,
            total: results.length,
            ok: blocked === 0,
            elapsedMs: Date.now() - started,
          });
          if (blocked > 0) process.exitCode = 1;
        } else {
          printCheckResults(results, { elapsedMs: Date.now() - started, verbose: options.verbose });
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (streaming) writeEvent({ type: 'error', command: 'check', message });
        else console.error(`${red('Error:')} ${message}`);
        process.exitCode = 1;
      }
    };

    await runOnce(1);
    if (!options.watch) return;

    console.log('  watching for changes (Ctrl+C to exit)…');
    let run = 1;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const watcher = watch(file, { persistent: true }, () => {
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => {
        run += 1;
        void runOnce(run);
      }, 300);
    });
    await new Promise<void>((resolve) => {
      process.on('SIGINT', () => {
        watcher.close();
        process.stdout.write('\n');
        resolve();
      });
    });
  });

// ── scan ─────────────────────────────────────────────────────────────────────

program
  .command('scan <input>')
  .description('Scan text, a file, or stdin through the detection stages (use "-" for stdin)')
  .option('--direction <direction>', 'Text direction: input (default, tool args/prompts) | output (tool results)', 'input')
  .option('--output-format <format>', 'Output format: text (default) | streaming-json (NDJSON)', 'text')
  .action(async (input: string, options: { direction?: string; outputFormat?: string }) => {
    let streaming: boolean;
    try {
      streaming = resolveOutputFormat(options.outputFormat) === 'streaming-json';
    } catch (error) {
      console.error(`${red('Error:')} ${error instanceof Error ? error.message : String(error)}`);
      process.exitCode = 1;
      return;
    }
    if (options.direction !== 'input' && options.direction !== 'output') {
      console.error(
        `${red('Error:')} unknown direction "${options.direction}" — expected "input" or "output"`,
      );
      process.exitCode = 1;
      return;
    }
    const direction = options.direction;
    const started = Date.now();
    try {
      const result = await runScan(input, { direction });
      if (streaming) {
        writeEvent({ type: 'result', command: 'scan', ...result });
        writeEvent({
          type: 'summary',
          command: 'scan',
          triggered: result.triggered,
          ok: !result.triggered,
          elapsedMs: Date.now() - started,
        });
        if (result.triggered) process.exitCode = 1;
      } else {
        printScanResult(result, Date.now() - started);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (streaming) {
        writeEvent({ type: 'error', command: 'scan', message });
        process.exitCode = 1;
        return;
      }
      console.error(`${red('Error:')} ${message}`);
      process.exit(1);
    }
  });

// ── bench ────────────────────────────────────────────────────────────────────

program
  .command('bench')
  .description('Circuit-breaker micro-benchmark with p99 budget assertion')
  .option('-n, --iterations <n>', 'Inspection iterations', '20000')
  .option('--max-p99 <ms>', 'Fail (exit 1) when the headline p99 exceeds this many ms (default 1)')
  .action(async (options: { iterations?: string; maxP99?: string }) => {
    const started = Date.now();
    const iterations = Math.max(1, Number(options.iterations ?? 20000));
    const maxP99 = options.maxP99 === undefined ? undefined : Number(options.maxP99);
    if (maxP99 !== undefined && !Number.isFinite(maxP99)) {
      console.error(`${red('Error:')} --max-p99 must be a number (got "${options.maxP99}")`);
      process.exitCode = 1;
      return;
    }
    try {
      const report = await runBench({ iterations, maxP99 });
      printBenchReport(report, Date.now() - started);
    } catch (error) {
      console.error(`${red('Error:')} ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

// ── audit group ──────────────────────────────────────────────────────────────

const auditCmd = program
  .command('audit')
  .description('Audit log commands');

/** `<log>` argument with `$VARK_AUDIT_PATH` fallback; exits when neither is set. */
function resolveLogPath(log: string | undefined): string {
  const path = log ?? process.env.VARK_AUDIT_PATH;
  if (!path) {
    console.error(`${red('Error:')} pass <log> or set VARK_AUDIT_PATH`);
    process.exit(1);
  }
  return path;
}

auditCmd
  .command('verify [log]')
  .description('Verify the cryptographic integrity of an audit log hash chain (default $VARK_AUDIT_PATH)')
  .action(async (log?: string) => {
    const started = Date.now();
    try {
      const result = await runAuditVerify(resolveLogPath(log));
      printVerifyResult(result, Date.now() - started);
    } catch (error) {
      console.error(`${red('Error:')} ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

auditCmd
  .command('tail [log]')
  .description('Stream audit records, color-coded by decision (default $VARK_AUDIT_PATH)')
  .option('-f, --follow', 'Keep following appended records')
  .option('-n, --lines <n>', 'Number of trailing records to show', '10')
  .option('--alert', 'Loud alert line for security refusals (pairs with --follow)')
  .option('--webhook <url>', 'POST alert entries to this URL (default $VARK_SIEM_WEBHOOK_URL)')
  .action(async (log: string | undefined, options: { follow?: boolean; lines?: string; alert?: boolean; webhook?: string }) => {
    try {
      await runTail(resolveLogPath(log), {
        follow: options.follow,
        lines: Number(options.lines ?? 10),
        alert: options.alert,
        webhook: options.webhook,
      });
    } catch (error) {
      console.error(`${red('Error:')} ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

auditCmd
  .command('export [log]')
  .description('Export an audit trail to JSON, NDJSON, CSV or a styled HTML report (default $VARK_AUDIT_PATH)')
  .option('--format <format>', 'json | ndjson | csv | html', 'json')
  .option('-o, --out <file>', 'Write to file instead of stdout')
  .action(async (log: string | undefined, options: { format?: string; out?: string }) => {
    try {
      const format = (options.format ?? 'json') as ExportFormat;
      if (!['json', 'ndjson', 'csv', 'html'].includes(format)) {
        console.error(`${red('Error:')} --format must be json, ndjson, csv or html`);
        process.exit(1);
      }
      const output = exportAudit(await loadEntries(resolveLogPath(log)), format);
      if (options.out) {
        await writeFile(options.out, output, 'utf8');
        console.log(`  wrote ${output.length} chars → ${options.out}`);
      } else {
        console.log(output);
      }
    } catch (error) {
      console.error(`${red('Error:')} ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

// ── policy group ─────────────────────────────────────────────────────────────

const policyCmd = program
  .command('policy')
  .description('Policy commands');

policyCmd
  .command('test <policy>')
  .description('Execute unit test assertions against a declarative policy file')
  .option('--output-format <format>', 'Output format: text (default) | streaming-json (NDJSON)', 'text')
  .option('--key <publicKeyPem>', 'Pin signature verification to this public key PEM')
  .option('--require-signature', 'Fail unless the policy carries a valid signature bundle')
  .option('--skip-signature', 'Skip automatic verification of an existing <policy>.sig')
  .action(
    async (
      policy: string,
      options: {
        outputFormat?: string;
        key?: string;
        requireSignature?: boolean;
        skipSignature?: boolean;
      },
    ) => {
      let streaming: boolean;
      try {
        streaming = resolveOutputFormat(options.outputFormat) === 'streaming-json';
      } catch (error) {
        console.error(`${red('Error:')} ${error instanceof Error ? error.message : String(error)}`);
        process.exitCode = 1;
        return;
      }
      const started = Date.now();
      try {
        const results = await runPolicyTest(policy, {
          quiet: streaming,
          keyPath: options.key,
          requireSignature: options.requireSignature,
          skipSignature: options.skipSignature,
        });
        if (streaming) {
          for (const result of results.results) {
            writeEvent({ type: 'result', command: 'policy-test', ...result });
          }
          writeEvent({
            type: 'summary',
            command: 'policy-test',
            passed: results.passed,
            failed: results.failed,
            ok: results.failed === 0,
            elapsedMs: Date.now() - started,
          });
          if (results.failed > 0) process.exitCode = 1;
        } else {
          printTestResults(results, Date.now() - started);
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (streaming) {
          writeEvent({ type: 'error', command: 'policy-test', message });
          process.exitCode = 1;
          return;
        }
        console.error(`${red('Error:')} ${message}`);
        process.exit(1);
      }
    },
  );

policyCmd
  .command('lint <policy>')
  .description('Statically validate a policy file (syntax + schema)')
  .action(async (policy: string) => {
    try {
      printLint(await lintPolicy(policy));
    } catch (error) {
      console.error(`${red('Error:')} ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

policyCmd
  .command('init [dir]')
  .description('Scaffold a starter policy file')
  .action(async (dir?: string) => {
    try {
      printInit(await initPolicy(dir ?? '.'));
    } catch (error) {
      console.error(`${red('Error:')} ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

policyCmd
  .command('keygen [out]')
  .description('Generate an Ed25519 key pair for policy signing (writes PEM files)')
  .action(async (out?: string) => {
    try {
      printPolicyKeygen(await generatePolicyKeyFiles({ out }));
    } catch (error) {
      console.error(`${red('Error:')} ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

policyCmd
  .command('sign <policy>')
  .description('Sign the exact bytes of a policy file (writes <policy>.sig)')
  .requiredOption('--key <privateKeyPem>', 'Path to the PKCS#8 Ed25519 private key PEM (see policy keygen)')
  .option('--out <sig>', 'Signature bundle output path (default <policy>.sig)')
  .action(async (policy: string, options: { key: string; out?: string }) => {
    try {
      printPolicySign(
        await signPolicyFile(policy, { keyPath: options.key, outPath: options.out }),
      );
    } catch (error) {
      console.error(`${red('Error:')} ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

policyCmd
  .command('verify <policy>')
  .description('Verify a policy signature bundle (tamper + drift detection)')
  .option('--key <publicKeyPem>', 'Pin verification to this public key PEM')
  .option('--sig <path>', 'Signature bundle path (default <policy>.sig)')
  .action(async (policy: string, options: { key?: string; sig?: string }) => {
    const started = Date.now();
    try {
      const outcome = await verifyPolicyFile(policy, {
        keyPath: options.key,
        sigPath: options.sig,
      });
      printPolicyVerify(outcome, Date.now() - started); // sets exitCode 1 when !ok
    } catch (error) {
      console.error(`${red('Error:')} ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

policyCmd
  .command('diff <a> <b>')
  .description('Structural diff of two policy files — exit 1 on drift, exit 2 on error')
  .action(async (a: string, b: string) => {
    const started = Date.now();
    try {
      const { entries, a: aLabel, b: bLabel } = await diffPolicyFiles(a, b);
      printPolicyDiff(entries, aLabel, bLabel, Date.now() - started);
      if (entries.length > 0) process.exitCode = 1; // drift
    } catch (error) {
      // Exit 2 so CI can tell drift (1) from unreadable input (2).
      console.error(`${red('Error:')} ${error instanceof Error ? error.message : String(error)}`);
      process.exit(2);
    }
  });

// ── analyzers: canary, pii, entropy, compress ────────────────────────────────

program
  .command('canary')
  .description('Honeytoken trap demo: seed, echo, detect, lock')
  .action(() => {
    printCanaryDemo(runCanaryDemo());
  });

program
  .command('pii <input>')
  .description('Scan text or a file for PII and preview anonymization')
  .action(async (input: string) => {
    const started = Date.now();
    try {
      const result = await runPiiScan(input);
      printPiiResult(input, result, Date.now() - started);
    } catch (error) {
      console.error(`${red('Error:')} ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

program
  .command('entropy <input>')
  .description('Entropy + system-context reflection report for a file or text')
  .option('--context <text...>', 'System context strings to compare against')
  .action(async (input: string, options: { context?: string[] }) => {
    const started = Date.now();
    try {
      const result = await runEntropyScan(input, options.context ?? []);
      printEntropyResult(input, result, Date.now() - started);
    } catch (error) {
      console.error(`${red('Error:')} ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

program
  .command('compress <schema>')
  .description('Preview Compact Tool Protocol compression for a JSON Schema file')
  .option('--name <name>', 'Tool name', 'tool')
  .option('--desc <text>', 'Tool description', '')
  .action(async (schema: string, options: { name?: string; desc?: string }) => {
    try {
      printCompressResult(await runCompress(schema, options.name ?? 'tool', options.desc ?? ''));
    } catch (error) {
      console.error(`${red('Error:')} ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

// ── ops: session, explain, doctor ────────────────────────────────────────────

const sessionCmd = program
  .command('session')
  .description('Session commands');

sessionCmd
  .command('stats <log>')
  .description('Per-session call/block table derived from an audit log')
  .option('--output-format <format>', 'Output format: text (default) | streaming-json (NDJSON)', 'text')
  .action(async (log: string, options: { outputFormat?: string }) => {
    let streaming: boolean;
    try {
      streaming = resolveOutputFormat(options.outputFormat) === 'streaming-json';
    } catch (error) {
      console.error(`${red('Error:')} ${error instanceof Error ? error.message : String(error)}`);
      process.exitCode = 1;
      return;
    }
    const started = Date.now();
    try {
      const rows = await runSessionStats(log);
      if (streaming) {
        for (const row of rows) writeEvent({ type: 'result', command: 'session-stats', ...row });
        writeEvent({
          type: 'summary',
          command: 'session-stats',
          sessions: rows.length,
          ok: true,
          elapsedMs: Date.now() - started,
        });
      } else {
        printSessionStats(rows);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (streaming) {
        writeEvent({ type: 'error', command: 'session-stats', message });
        process.exitCode = 1;
        return;
      }
      console.error(`${red('Error:')} ${message}`);
      process.exit(1);
    }
  });

program
  .command('explain <gate>')
  .description('Explain a refusal gate: when it fires, why, and how to fix it')
  .action((gate: string) => {
    printGateExplanation(gate);
  });

program
  .command('doctor')
  .description('Environment + install readiness check')
  .action(async () => {
    try {
      const checks = await runDoctor();
      printDoctor(checks);
    } catch (error) {
      console.error(`${red('Error:')} ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

// Global error handler
program.exitOverride((err) => {
  if (err.code === 'commander.helpDisplayed') {
    process.exit(0);
  }
  if (err.code === 'commander.version') {
    process.exit(0);
  }
  console.error(`${red('Error:')} ${err.message}`);
  process.exit(1);
});

program.parseAsync(process.argv).catch((error) => {
  console.error(`${red('Error:')} ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
