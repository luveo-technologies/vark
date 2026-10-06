# `@luveo-tech/vark`

**Zero-trust security runtime and firewall for AI agent tool calls.**

`vark` intercepts tool-call payloads *before* execution, refuses anything that
looks like an attack, enforces capability-based access control, and compresses
tool schemas to save LLM tokens.

```ts
import { VarkRuntime } from '@luveo-tech/vark';

const runtime = new VarkRuntime({
  defaultCapabilities: { filesystem: { allow: ['./workspace/*'] } },
});

const read = runtime.tool({
  name: 'read_file',
  description: 'Read a UTF-8 text file.',
  schema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] },
  run: (args, ctx) => ctx.sandbox.readFile(args.path),
});

await read.execute({ path: './workspace/data.json' }); // → { success: true, … }
await read.execute({ path: '../../etc/passwd' });      // → CAPABILITY_VIOLATION
```

Every call flows through 8 gates — anomaly guard → capability sandbox →
circuit breaker → input DLP → isolated execution → output DLP → injection
filter → hash-chained audit — and **always resolves** with a
`ToolExecutionResult` (never throws).

Ships a CLI as well (`npx vark …`):

```bash
vark check payload.json        # dry-run a tool payload against the gates
vark scan "Ignore all rules…"  # per-stage detection pipeline view
vark bench                     # p99 budget assertion table
vark audit verify audit.jsonl  # verify an audit hash chain
vark policy test policy.json   # run policy assertions
vark explain CIRCUIT_BREAKER   # why a gate fires + how to fix it
vark doctor                    # readiness check
```

Full documentation (architecture, API reference, CTP spec, benchmarks, threat
model) lives in [`DOCUMENTATION.md`](https://github.com/luveo-technologies/vark/blob/main/DOCUMENTATION.md)
and [`docs/`](https://github.com/luveo-technologies/vark/tree/main/docs) in the
monorepo.

Node 20+ · ESM · zero runtime dependencies · MIT
