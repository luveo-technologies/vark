/**
 * `vark session|explain|doctor` + `vark policy lint|init` — operator tooling.
 *
 * - `session stats`: per-session call/block tables derived from an audit log.
 * - `session replay`: call-by-call timeline of a session (or whole log).
 * - `explain`: gate explainer with why-it-fires and remediation hints.
 * - `doctor`: environment + install readiness check.
 * - `policy lint` / `policy init`: validate or scaffold a policy file.
 */

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import type { AuditEntry } from '../../types.js';
import { loadEntries } from './audit.js';
import { printBanner, printSummaryLine, table, decisionChip } from '../ux.js';
import pkg from 'picocolors';
const { green, red, yellow, dim, bold, cyan } = pkg;

// ── session stats ───────────────────────────────────────────────────────────

export interface SessionRow {
  id: string;
  calls: number;
  blocked: number;
}

export function sessionStats(entries: AuditEntry[]): SessionRow[] {
  const map = new Map<string, { calls: number; blocked: number }>();
  for (const entry of entries) {
    const row = map.get(entry.sessionId) ?? { calls: 0, blocked: 0 };
    row.calls += 1;
    if (entry.blockedBy) row.blocked += 1;
    map.set(entry.sessionId, row);
  }
  return [...map.entries()]
    .map(([id, stats]) => ({ id, ...stats }))
    .sort((a, b) => b.calls - a.calls);
}

export async function runSessionStats(logPath: string): Promise<SessionRow[]> {
  return sessionStats(await loadEntries(logPath));
}

// ── session replay ─────────────────────────────────────────────────────────

export interface ReplayOptions {
  /** Only replay records for this session id. */
  session?: string;
  /** First seq to include (inclusive). */
  from?: number;
  /** Last seq to include (inclusive). */
  to?: number;
  /** Replay at most this many records (after the other filters). */
  limit?: number;
}

export interface ReplaySession {
  sessionId: string;
  entries: AuditEntry[];
  allowed: number;
  refused: number;
  byDecision: Record<string, number>;
  redactions: { input: number; output: number; injection: number };
  executionMs: number;
  firstAt: string;
  lastAt: string;
}

export interface ReplayReport {
  /** Sessions in first-appearance order, each chronologically ordered. */
  sessions: ReplaySession[];
  /** Records after filtering — what gets replayed. */
  matched: number;
  /** Records in the log before filtering. */
  total: number;
}

/**
 * Reconstruct a call-by-call timeline from an audit log. Grouping is by
 * session (first-appearance order); `matched`/`total` let callers report
 * "replayed X of Y" when filters trimmed the view.
 */
export async function runSessionReplay(logPath: string, opts: ReplayOptions = {}): Promise<ReplayReport> {
  const all = await loadEntries(logPath);
  let entries = all;
  if (opts.session !== undefined) entries = entries.filter((e) => e.sessionId === opts.session);
  if (opts.from !== undefined) entries = entries.filter((e) => e.seq >= opts.from!);
  if (opts.to !== undefined) entries = entries.filter((e) => e.seq <= opts.to!);
  if (opts.limit !== undefined) entries = entries.slice(0, Math.max(0, opts.limit));

  const sessions: ReplaySession[] = [];
  const byId = new Map<string, ReplaySession>();
  for (const entry of entries) {
    let session = byId.get(entry.sessionId);
    if (!session) {
      session = {
        sessionId: entry.sessionId,
        entries: [],
        allowed: 0,
        refused: 0,
        byDecision: {},
        redactions: { input: 0, output: 0, injection: 0 },
        executionMs: 0,
        firstAt: entry.timestamp,
        lastAt: entry.timestamp,
      };
      byId.set(entry.sessionId, session);
      sessions.push(session);
    }
    session.entries.push(entry);
    if (entry.decision === 'ALLOWED') session.allowed += 1;
    else session.refused += 1;
    session.byDecision[entry.decision] = (session.byDecision[entry.decision] ?? 0) + 1;
    session.redactions.input += entry.inputRedactions;
    session.redactions.output += entry.outputRedactions;
    session.redactions.injection += entry.injectionSanitized;
    session.executionMs += entry.executionTimeMs;
    session.lastAt = entry.timestamp;
  }
  return { sessions, matched: entries.length, total: all.length };
}

function formatOffset(ms: number): string {
  return ms < 1_000 ? `+${ms}ms` : `+${(ms / 1_000).toFixed(1)}s`;
}

function formatReplayLine(entry: AuditEntry, offsetMs: number): string {
  const time = entry.timestamp.slice(11, 23);
  const redactions: string[] = [];
  if (entry.inputRedactions > 0) redactions.push(`in:${entry.inputRedactions}`);
  if (entry.outputRedactions > 0) redactions.push(`out:${entry.outputRedactions}`);
  if (entry.injectionSanitized > 0) redactions.push(`inj:${entry.injectionSanitized}`);

  const parts = [
    dim(time),
    dim(formatOffset(offsetMs)),
    dim(`#${entry.seq}`),
    decisionChip(entry.decision),
    bold(entry.tool),
    dim(`${Math.round(entry.executionTimeMs)}ms`),
  ];
  if (redactions.length > 0) parts.push(yellow(`[${redactions.join(' ')}]`));
  // Refusals already show their gate via the chip; findings matter on the
  // allowed path (DLP redactions, BREAK_GLASS overrides, injection flags).
  if (entry.decision === 'ALLOWED' && entry.findings.length > 0) {
    parts.push(yellow(`[${entry.findings.join(' ')}]`));
  }
  const input = JSON.stringify(entry.sanitizedInputs);
  if (input !== undefined) parts.push(dim(input.length > 72 ? `${input.slice(0, 72)}…` : input));
  if (entry.reason) {
    parts.push(entry.blockedBy ? red(`— ${entry.reason.slice(0, 90)}`) : dim(`— ${entry.reason.slice(0, 90)}`));
  }
  return parts.join('  ');
}

export function printSessionReplay(
  report: ReplayReport,
  opts: { logPath: string; elapsedMs?: number },
): void {
  printBanner(`session replay  ·  ${opts.logPath}`);

  if (report.matched === 0) {
    console.log(
      `  ${yellow('⚠')} no records to replay${report.total === 0 ? ' (empty log)' : ` (${report.total} in log, none matched the filters)`}`,
    );
    printSummaryLine([yellow('✘ NOTHING REPLAYED'), dim('check --session / --from / --to filters')], opts.elapsedMs);
    process.exitCode = 1;
    return;
  }

  for (const session of report.sessions) {
    const start = Date.parse(session.firstAt);
    console.log('');
    console.log(
      `  ${bold(`session ${session.sessionId}`)}  ·  ${session.entries.length} call${session.entries.length === 1 ? '' : 's'}  ·  ` +
        `${green(`${session.allowed} allowed`)} / ${red(`${session.refused} refused`)}  ·  ` +
        `${session.firstAt.slice(11, 19)} → ${session.lastAt.slice(11, 19)}  ·  ${Math.round(session.executionMs)}ms total`,
    );
    for (const entry of session.entries) {
      console.log(`    ${formatReplayLine(entry, Date.parse(entry.timestamp) - start)}`);
    }
    const redactions = session.redactions.input + session.redactions.output + session.redactions.injection;
    const breakdown = Object.entries(session.byDecision)
      .map(([decision, count]) => `${decision}×${count}`)
      .join('  ');
    const redactionNote =
      redactions > 0
        ? `  ·  redactions: in ${session.redactions.input} / out ${session.redactions.output} / inj ${session.redactions.injection}`
        : '';
    if (Object.keys(session.byDecision).length > 1 || redactions > 0) {
      console.log(`    ${dim(`${breakdown}${redactionNote}`)}`);
    }
  }

  const filtersNote = report.matched < report.total ? dim(`of ${report.total} in log`) : '';
  printSummaryLine(
    [
      green(`✔ REPLAYED ${report.matched} record${report.matched === 1 ? '' : 's'}`),
      dim(`${report.sessions.length} session${report.sessions.length === 1 ? '' : 's'}`),
      ...(filtersNote ? [filtersNote] : []),
    ],
    opts.elapsedMs,
  );
}

// ── explain ─────────────────────────────────────────────────────────────────

interface GateDoc {
  gate: string;
  when: string;
  why: string;
  fix: string;
}

const GATE_DOCS: GateDoc[] = [
  {
    gate: 'LOOP_BLOCKED',
    when: 'Same tool + identical args more than maxIdenticalCalls (default 3).',
    why: 'Stops runaway agents before they burn downstream budget or exfiltrate in a loop.',
    fix: 'Vary the arguments, raise maxIdenticalCalls for polling tools, or resetSession() when the task changes.',
  },
  {
    gate: 'VELOCITY_EXCEEDED',
    when: 'More than maxCallsPerMinute calls (default 30) inside the sliding window; the session is halted.',
    why: 'A flooding agent is indistinguishable from a compromised one — halt first, investigate after.',
    fix: 'Raise maxCallsPerMinute/windowMs for bursty workloads, or resetSession() after manual review.',
  },
  {
    gate: 'BUDGET_EXCEEDED',
    when: 'Lifetime maxTotalCalls or maxSessionTokens exhausted; the session is halted.',
    why: 'Hard budgets bound blast radius and spend per agent session.',
    fix: 'Raise the budgets for long-running agents, or resetSession() to start a fresh budget window.',
  },
  {
    gate: 'CAPABILITY_VIOLATION',
    when: 'A path-shaped arg falls outside filesystem.allow, or a URL violates the network policy.',
    why: 'Authorization runs before detection so policy gaps report precisely.',
    fix: 'Widen the grant glob (e.g. ./workspace/**), add the host to allowedHosts, or fix the agent prompt.',
  },
  {
    gate: 'CIRCUIT_BREAKER',
    when: 'Shell metacharacters (; && | $() backticks eval rm -rf curl|sh) or traversal paths (../ /etc/passwd .env).',
    why: 'Sub-millisecond signature firewall over the raw payload.',
    fix: 'Pass arguments as argv arrays, never shell strings; add customRules for domain-specific denylists.',
  },
  {
    gate: 'DLP_REDACTED',
    when: 'API keys, JWTs, Bearer tokens, private keys or .env pairs found in args (gate 4) or output (gate 6).',
    why: 'Credentials must never reach run(), the model context, or the logs.',
    fix: 'Use mode:block to refuse instead of redact; add custom patterns for internal secret formats.',
  },
  {
    gate: 'INDIRECT_INJECTION',
    when: 'Untrusted text carries instruction overrides, jailbreaks, or exfiltration payloads.',
    why: 'Tool output re-enters the prompt — it is attacker-controlled input.',
    fix: 'Use mode:block for untrusted sources; add customRules paired with block mode.',
  },
  {
    gate: 'TIMEOUT',
    when: 'run() exceeded maxExecutionMs (default 10s).',
    why: 'Wall-clock bound via Promise.race; the timer is always cleared.',
    fix: 'Raise maxExecutionMs per tool, or break the work into smaller calls.',
  },
  {
    gate: 'DESCRIPTOR_PIN_VIOLATION',
    when: 'An MCP tool descriptor changed after wrapTools() pinned its hash.',
    why: 'Servers can mutate name/description/schema mid-session (rug pull); the pinned hash no longer matches.',
    fix: 'Re-wrap the tools to accept the new descriptor, or investigate the server.',
  },
  {
    gate: 'SESSION_FROZEN',
    when: 'The session was frozen (e.g. injection block with freezeOnInjectionBlock, or runtime.freezeSession()).',
    why: 'A frozen session is administratively locked until reset.',
    fix: 'Review the audit trail, then resetSession() to unfreeze.',
  },
  {
    gate: 'HITL_DENIED',
    when: 'A high-risk tool mapped in hitl.tools was denied approval or timed out waiting for it.',
    why: 'Fail-closed: undecided approvals deny rather than execute.',
    fix: 'Approve via the HitlGate, raise hitl.timeoutMs, or remove the tool mapping.',
  },
  {
    gate: 'ISOLATION_UNAVAILABLE',
    when: "isolation:'wasm' was requested but isolated-vm is not installed (or its bootstrap failed) and isolationConfig.allowFallback is false.",
    why: 'Fail-closed on dependency loss: no true isolate boundary, no execution — a silent fallback would claim isolation that does not exist.',
    fix: 'Install isolated-vm, or set isolationConfig.allowFallback: true to accept advisory execution with the warning stated.',
  },
  {
    gate: 'AUDIT_UNAVAILABLE',
    when: 'The audit sink failed to persist a record and audit.failClosed is set.',
    why: 'Fail-closed: actions without a durable, hash-chained record are unauditable — refuse until the trail writes again.',
    fix: 'Restore the sink (disk space, path permissions, SIEM endpoint); this refusal record probes the sink, so the next call succeeds once writes work.',
  },
  {
    gate: 'EXECUTION_ERROR',
    when: 'run() threw, the tool is unknown, or schema validation failed.',
    why: 'Failures resolve — never throw — so the agent loop survives.',
    fix: 'Check the error message; for schema failures compare args against the tool schema.',
  },
];

export function explainGate(gate: string): GateDoc | undefined {
  return GATE_DOCS.find((doc) => doc.gate === gate.toUpperCase());
}

export function printGateExplanation(gate: string): void {
  const doc = explainGate(gate);
  if (!doc) {
    console.log(`${yellow('Unknown gate:')} ${gate}`);
    console.log(dim(`  known gates: ${GATE_DOCS.map((d) => d.gate).join(', ')}`));
    process.exitCode = 1;
    return;
  }
  printBanner(`explain  ·  ${doc.gate}`);
  console.log(`  ${bold('fires when:')}  ${doc.when}`);
  console.log(`  ${bold('why:')}         ${doc.why}`);
  console.log(`  ${bold('fix:')}         ${doc.fix}`);
}

// ── doctor ──────────────────────────────────────────────────────────────────

export interface DoctorCheck {
  name: string;
  ok: boolean;
  detail: string;
}

export async function runDoctor(): Promise<DoctorCheck[]> {
  const checks: DoctorCheck[] = [];

  // Node version
  const major = Number(process.versions.node.split('.')[0]);
  checks.push({
    name: 'node >= 20',
    ok: major >= 20,
    detail: process.versions.node,
  });

  // ESM
  checks.push({ name: 'esm', ok: true, detail: 'type: module' });

  // commander + picocolors resolvable
  for (const dep of ['commander', 'picocolors']) {
    try {
      await import(dep);
      checks.push({ name: `dep: ${dep}`, ok: true, detail: 'resolvable' });
    } catch {
      checks.push({ name: `dep: ${dep}`, ok: false, detail: 'MISSING — reinstall' });
    }
  }

  // isolated-vm (optional true isolation) — indirect specifier so
  // TypeScript does not try to resolve the optional dependency
  try {
    const moduleName = 'isolated-vm';
    await import(moduleName);
    checks.push({ name: 'isolated-vm', ok: true, detail: 'true heap isolation available' });
  } catch {
    checks.push({
      name: 'isolated-vm',
      ok: true,
      detail: 'not installed — wasm mode falls back to process (advisory)',
    });
  }

  return checks;
}

export function printDoctor(checks: DoctorCheck[]): void {
  printBanner('doctor  ·  readiness check');
  const failed = checks.filter((c) => !c.ok);
  console.log(
    table(
      [
        ['check', 'status', 'detail'],
        ...checks.map((c) => [c.name, c.ok ? green('ok') : red('FAIL'), dim(c.detail)]),
      ],
      { head: true },
    )
      .split('\n')
      .map((line) => `  ${line}`)
      .join('\n'),
  );
  printSummaryLine(
    failed.length === 0 ? [green(`✔ ready (${checks.length} checks)`)] : [red(`✘ ${failed.length} failing`)],
  );
  if (failed.length > 0) process.exitCode = 1;
}

// ── policy lint / init ──────────────────────────────────────────────────────

export interface LintResult {
  valid: boolean;
  errors: string[];
  testCount: number;
  toolCount: number;
}

export async function lintPolicy(policyPath: string): Promise<LintResult> {
  const errors: string[] = [];
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(await readFile(resolve(policyPath), 'utf8')) as Record<string, unknown>;
  } catch (error) {
    return {
      valid: false,
      errors: [`invalid JSON: ${error instanceof Error ? error.message : String(error)}`],
      testCount: 0,
      toolCount: 0,
    };
  }

  const tools = parsed['tools'];
  const tests = parsed['tests'];
  const toolCount = Array.isArray(tools) ? tools.length : 0;
  const testCount = Array.isArray(tests) ? tests.length : 0;

  if (tools !== undefined && !Array.isArray(tools)) errors.push('"tools" must be an array');
  if (tests !== undefined && !Array.isArray(tests)) errors.push('"tests" must be an array');

  if (Array.isArray(tools)) {
    tools.forEach((tool, i) => {
      const t = tool as Record<string, unknown>;
      if (typeof t['name'] !== 'string') errors.push(`tools[${i}].name must be a string`);
      if (typeof t['description'] !== 'string') errors.push(`tools[${i}].description must be a string`);
      if (typeof t['schema'] !== 'object' || t['schema'] === null) errors.push(`tools[${i}].schema must be an object`);
    });
  }
  if (Array.isArray(tests)) {
    const toolNames = new Set(
      Array.isArray(tools) ? (tools as Array<Record<string, unknown>>).map((t) => t['name']) : [],
    );
    tests.forEach((test, i) => {
      const t = test as Record<string, unknown>;
      if (typeof t['name'] !== 'string') errors.push(`tests[${i}].name must be a string`);
      if (typeof t['tool'] !== 'string') errors.push(`tests[${i}].tool must be a string`);
      if (typeof t['shouldAllow'] !== 'boolean') errors.push(`tests[${i}].shouldAllow must be a boolean`);
      if (toolNames.size > 0 && typeof t['tool'] === 'string' && !toolNames.has(t['tool'])) {
        errors.push(`tests[${i}].tool "${t['tool']}" has no matching tool definition`);
      }
    });
  }

  return { valid: errors.length === 0, errors, testCount, toolCount };
}

export function printLint(result: LintResult): void {
  printBanner('policy lint  ·  static validation');
  if (result.valid) {
    printSummaryLine([
      green('✔ syntax valid'),
      dim(`${result.toolCount} tools · ${result.testCount} tests`),
    ]);
  } else {
    for (const error of result.errors) console.log(`  ${red('✘')} ${error}`);
    printSummaryLine([red(`✘ ${result.errors.length} problem(s)`)]);
    process.exitCode = 1;
  }
}

const STARTER_POLICY = {
  config: {
    circuitBreaker: { blockShellInjection: true, blockPathTraversal: true },
    defaultCapabilities: { maxExecutionMs: 5000 },
  },
  tools: [
    {
      name: 'read_file',
      description: 'Read a UTF-8 text file.',
      schema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] },
      run: 'return args;',
    },
  ],
  tests: [
    { name: 'allows a workspace path', tool: 'read_file', args: { path: './a.json' }, shouldAllow: true },
    { name: 'blocks a missing required arg', tool: 'read_file', args: {}, shouldAllow: false },
  ],
};

export async function initPolicy(dir: string): Promise<string> {
  const target = resolve(dir);
  await mkdir(target, { recursive: true });
  const path = join(target, 'policy.vark.json');
  await writeFile(path, JSON.stringify(STARTER_POLICY, null, 2), 'utf8');
  return path;
}

export function printInit(path: string): void {
  printBanner('policy init  ·  scaffold');
  console.log(`  ${green('●')} wrote starter policy → ${cyan(path)}`);
  console.log(dim('  next: vark policy lint <file>  ·  vark policy test <file>'));
}
