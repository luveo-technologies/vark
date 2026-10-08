/**
 * `@luveo-tech/vark-mcp` — zero-rewrite bridge between Anthropic Model Context
 * Protocol tool descriptors and the vark guard pipeline.
 */

export { VarkMCPAdapter, wrapMCPTools, hashDescriptor } from './bridge.js';
export type {
  MCPExecutor,
  MCPToolLike,
  VarkMCPAdapterOptions,
  WrappedMCPTool,
} from './bridge.js';
export type { ExecutionOptions } from './bridge.js';
