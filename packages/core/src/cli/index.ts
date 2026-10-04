#!/usr/bin/env node
/**
 * Vark CLI - Zero-trust security runtime for AI agent tool calls
 *
 * @packageDocumentation
 */

import { program } from 'commander';
import { runCheck, printCheckResults } from './commands/check.js';
import { runAuditVerify, printVerifyResult } from './commands/audit.js';
import { runPolicyTest, printTestResults } from './commands/policy.js';
import { spinner } from './ux.js';
import { readFile } from 'node:fs/promises';
import pkg from 'picocolors';
const { red } = pkg;

let version = '0.1.0';
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

program
  .command('check <file>')
  .description('Dry-run evaluate tool payload files against Vark security gates')
  .option('-c, --config <file>', 'Path to Vark config file')
  .action(async (file: string, options: { config?: string }) => {
    const started = Date.now();
    const spin = spinner('Evaluating payloads against the 8 gates…');
    try {
      let config: Record<string, unknown> = {};
      if (options.config) {
        // Load config from file
        const content = await readFile(options.config, 'utf8');
        config = JSON.parse(content);
      }

      const results = await runCheck(file, config);
      spin.stop();
      printCheckResults(results, Date.now() - started);

      // Exit code is set by printCheckResults
    } catch (error) {
      spin.fail('Evaluation failed');
      console.error(`${red('Error:')} ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

const auditCmd = program
  .command('audit')
  .description('Audit log commands');

auditCmd
  .command('verify <log>')
  .description('Verify the cryptographic integrity of an audit log hash chain')
  .action(async (log: string) => {
    const started = Date.now();
    const spin = spinner('Recomputing hash chain…');
    try {
      const result = await runAuditVerify(log);
      spin.stop();
      printVerifyResult(result, Date.now() - started);
    } catch (error) {
      spin.fail('Verification failed');
      console.error(`${red('Error:')} ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

const policyCmd = program
  .command('policy')
  .description('Policy commands');

policyCmd
  .command('test <policy>')
  .description('Execute unit test assertions against a declarative policy file')
  .action(async (policy: string) => {
    const started = Date.now();
    const spin = spinner('Running policy assertions…');
    try {
      const results = await runPolicyTest(policy);
      spin.stop();
      printTestResults(results, Date.now() - started);
    } catch (error) {
      spin.fail('Policy run failed');
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