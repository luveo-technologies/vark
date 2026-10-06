# `@luveo-tech/vark-mcp`

**Zero-rewrite bridge that wraps Anthropic Model Context Protocol (MCP) tools
with [`@luveo-tech/vark`](https://www.npmjs.com/package/@luveo-tech/vark) protection.**

Raw MCP descriptors are left byte-identical; vark adds a guard pipeline, an
`execute()` hook, and a CTP signature:

```ts
import { VarkRuntime } from '@luveo-tech/vark';
import { VarkMCPAdapter } from '@luveo-tech/vark-mcp';

const runtime = new VarkRuntime();
const adapter = new VarkMCPAdapter({
  runtime, // share the host runtime: same anomaly window, same audit chain
  executor: async (tool, args) => client.callTool(tool.name, args),
});

const tools = adapter.wrapTools(mcpTools, {
  network: { allowedHosts: ['docs.example.com', '*.docs.example.com'] },
});

await tools[0].execute({ url: 'https://evil.example.net' }); // → CAPABILITY_VIOLATION
tools[0].check({ url: 'https://docs.example.com' });         // dry run, no server call
tools[0].compact;                                            // CTP signature
```

Full documentation in the
[monorepo](https://github.com/luveo-technologies/vark).

Node 20+ · ESM · MIT
