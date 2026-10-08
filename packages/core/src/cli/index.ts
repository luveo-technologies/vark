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
import { runPolicyTest, printTestResults } from './commands/policy.js';
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
  .action(async (file: string, options: { config?: string; watch?: boolean; verbose?: boolean }) => {
    const runOnce = async (run: number): Promise<void> => {
      if (options.watch && run > 1) console.log(`\n  ── run #${run} ──`);
      const started = Date.now();
      try {
        let config: Record<string, unknown> = {};
        if (options.config) {
          const content = await readFile(options.config, 'utf8');
          config = JSON.parse(content);
        }

        const results = await runCheck(file, config);
        printCheckResults(results, { elapsedMs: Date.now() - started, verbose: options.verbose });
      } catch (error) {
        console.error(`${red('Error:')} ${error instanceof Error ? error.message : String(error)}`);
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
  .action(async (input: string) => {
    const started = Date.now();
    try {
      const result = await runScan(input);
      printScanResult(result, Date.now() - started);
    } catch (error) {
      console.error(`${red('Error:')} ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

// ── bench ────────────────────────────────────────────────────────────────────

program
  .command('bench')
  .description('Circuit-breaker micro-benchmark with p99 budget assertion')
  .option('-n, --iterations <n>', 'Inspection iterations', '20000')
  .action(async (options: { iterations?: string }) => {
    const started = Date.now();
    const iterations = Math.max(1, Number(options.iterations ?? 20000));
    try {
      const report = runBench({ iterations });
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

auditCmd
  .command('verify <log>')
  .description('Verify the cryptographic integrity of an audit log hash chain')
  .action(async (log: string) => {
    const started = Date.now();
    try {
      const result = await runAuditVerify(log);
      printVerifyResult(result, Date.now() - started);
    } catch (error) {
      console.error(`${red('Error:')} ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

auditCmd
  .command('tail <log>')
  .description('Stream audit records, color-coded by decision')
  .option('-f, --follow', 'Keep following appended records')
  .option('-n, --lines <n>', 'Number of trailing records to show', '10')
  .action(async (log: string, options: { follow?: boolean; lines?: string }) => {
    try {
      await runTail(log, { follow: options.follow, lines: Number(options.lines ?? 10) });
    } catch (error) {
      console.error(`${red('Error:')} ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

auditCmd
  .command('export <log>')
  .description('Export an audit trail to JSON, CSV or a styled HTML report')
  .option('--format <format>', 'json | csv | html', 'json')
  .option('-o, --out <file>', 'Write to file instead of stdout')
  .action(async (log: string, options: { format?: string; out?: string }) => {
    try {
      const format = (options.format ?? 'json') as ExportFormat;
      if (!['json', 'csv', 'html'].includes(format)) {
        console.error(`${red('Error:')} --format must be json, csv or html`);
        process.exit(1);
      }
      const output = exportAudit(await loadEntries(log), format);
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
  .action(async (policy: string) => {
    const started = Date.now();
    try {
      const results = await runPolicyTest(policy);
      printTestResults(results, Date.now() - started);
    } catch (error) {
      console.error(`${red('Error:')} ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

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
  .action(async (log: string) => {
    try {
      printSessionStats(await runSessionStats(log));
    } catch (error) {
      console.error(`${red('Error:')} ${error instanceof Error ? error.message : String(error)}`);
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
