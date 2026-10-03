# Integration Guides

## LangChain Integration

```ts
import { VarkRuntime } from '@saturn/vark';
import { DynamicTool } from 'langchain/tools';

const runtime = new VarkRuntime({
  defaultCapabilities: { filesystem: { allow: ['./workspace/*'] } },
});

// Wrap a LangChain tool
const varkTool = new DynamicTool({
  name: 'read_file',
  description: 'Read a file from the workspace',
  func: async (input) => {
    const result = await runtime.execute('read_file', { path: input });
    if (!result.success) throw new Error(result.error);
    return result.data;
  },
});

// Use in a LangChain agent
const agent = await initializeAgentExecutor([varkTool], llm, 'chat-conversational-react-description');
```

## LlamaIndex Integration

```ts
import { VarkRuntime } from '@saturn/vark';
import { Tool } from 'llamaindex';

const runtime = new VarkRuntime();

const varkTool = new Tool({
  name: 'read_file',
  description: 'Read a file',
  parameters: {
    type: 'object',
    properties: { path: { type: 'string' } },
    required: ['path'],
  },
  fn: async ({ path }) => {
    const result = await runtime.execute('read_file', { path });
    return result.success ? result.data : `Error: ${result.error}`;
  },
});
```

## Saturn AI Integration

```ts
import { VarkRuntime } from '@saturn/vark';

const runtime = new VarkRuntime({
  isolation: 'wasm',
  isolationConfig: { memoryLimitMb: 64 },
  dlp: { mode: 'block' },
  anomaly: { maxIdenticalCalls: 3, maxCallsPerMinute: 30 },
});

// Register tools with Saturn AI
const tools = runtime.list().map(tool => ({
  name: tool.definition.name,
  description: tool.definition.description,
  parameters: tool.definition.schema,
  execute: (args) => tool.execute(args),
}));
```

## Custom Agent Loop

```ts
import { VarkRuntime } from '@saturn/vark';

const runtime = new VarkRuntime({
  circuitBreaker: { blockShellInjection: true, blockPathTraversal: true },
  defaultCapabilities: { maxExecutionMs: 5_000 },
  audit: { sink: (entry) => appendFileSync('audit.jsonl', JSON.stringify(entry) + '\n') },
});

// Register tools
runtime.tool({
  name: 'read_file',
  description: 'Read a UTF-8 file',
  schema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] },
  capabilities: { filesystem: { allow: ['./workspace/*'] } },
  run: (args, ctx) => ctx.sandbox.readFile(args.path),
});

// Agent loop
async function agentLoop(userMessage: string) {
  const llmResponse = await llm.complete(userMessage);

  for (const toolCall of llmResponse.toolCalls) {
    const result = await runtime.execute(toolCall.name, toolCall.args, {
      sessionId: 'agent-session-1',
    });

    if (result.success) {
      console.log(`✅ ${toolCall.name}:`, result.data);
    } else {
      console.error(`❌ ${toolCall.name}: ${result.blockedBy} — ${result.error}`);
    }
  }
}
```

## Anthropic MCP Integration

```ts
import { VarkRuntime } from '@saturn/vark';
import { VarkMCPAdapter } from '@saturn/vark-mcp';

const runtime = new VarkRuntime();

const adapter = new VarkMCPAdapter({
  runtime,
  executor: async (tool, args) => mcpClient.callTool(tool.name, args),
});

const tools = adapter.wrapTools(mcpTools, {
  network: { allowedHosts: ['docs.example.com', '*.docs.example.com'] },
});

// Execute with full guard pipeline
const result = await tools[0].execute({ url: 'https://docs.example.com/intro' });
```

## Express.js Middleware

```ts
import express from 'express';
import { VarkRuntime } from '@saturn/vark';

const app = express();
const runtime = new VarkRuntime();

// Middleware to guard all tool calls
app.use('/api/tools', async (req, res, next) => {
  const { tool, args, sessionId } = req.body;
  const result = await runtime.execute(tool, args, { sessionId });

  if (!result.success) {
    return res.status(403).json({ error: result.error, blockedBy: result.blockedBy });
  }

  req.varkResult = result;
  next();
});
```

## Next.js API Route

```ts
// app/api/tools/route.ts
import { VarkRuntime } from '@saturn/vark';

const runtime = new VarkRuntime({
  defaultCapabilities: { network: false },
});

export async function POST(request: Request) {
  const { tool, args } = await request.json();
  const result = await runtime.execute(tool, args);

  if (!result.success) {
    return Response.json({ error: result.error }, { status: 403 });
  }

  return Response.json({ data: result.data });
}
```
