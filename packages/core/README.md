# `@saturn/vark`

**Zero-trust security runtime and firewall for AI agent tool calls.**

`vark` intercepts tool-call payloads *before* execution, refuses anything that
looks like an attack, enforces capability-based access control, and compresses
tool schemas to save LLM tokens.

```ts
import { VarkRuntime } from '@saturn/vark';

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

Ships a CLI as well:

```bash
npx vark check payload.json        # dry-run a tool payload against the gates
npx vark audit verify audit.jsonl  # verify an audit hash chain
npx vark policy test policy.json   # run policy assertions
```

Full documentation (architecture, API reference, CTP spec, benchmarks, threat
model) lives in [`DOCUMENTATION.md`](https://github.com/saturn-security/vark/blob/main/DOCUMENTATION.md)
and [`docs/`](https://github.com/saturn-security/vark/tree/main/docs) in the
monorepo.

Node 20+ · ESM · zero runtime dependencies · MIT
