/**
 * Anthropic MCP bridge — zero-rewrite protection for Model Context Protocol
 * tools.
 *
 * MCP exposes *schema-only* tool descriptors (`{ name, description,
 * inputSchema }`); the actual call is a `tools/call` request against the MCP
 * server. The adapter keeps those descriptors byte-identical and adds three
 * things around them:
 *
 *  - a vark guard pipeline (capabilities + circuit breaker + timeout),
 *  - an `execute()` hook that performs the server call,
 *  - a CTP signature so the descriptor can be sent to the model in far fewer
 *    tokens than the original JSON Schema.
 *
 * ```ts
 * const adapter = new VarkMCPAdapter({ executor: async (tool, args) => client.callTool(tool.name, args) });
 * const tools = adapter.wrapTools(mcpTools, { network: { allowedHosts: ['api.example.com'] } });
 * await tools[0].execute({ url: 'https://evil.com' }); // → CAPABILITY_VIOLATION
 * ```
 */

import { VarkRuntime } from '@luveo-tech/vark';
import { createHash } from 'node:crypto';
import type {
  CapabilityConfig,
  CompressionReport,
  ExecutionOptions,
  ExecutionContext,
  GuardResult,
  InspectionResult,
  ToolExecutionResult,
  VarkConfig,
} from '@luveo-tech/vark';
import { VarkError, stableStringify, DEFAULT_SESSION } from '@luveo-tech/vark';

/** Shape of a raw MCP (or OpenAI-style function) tool descriptor. */
export interface MCPToolLike {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
  /** OpenAI-style alias for `inputSchema`. */
  schema?: Record<string, unknown>;
  [key: string]: unknown;
}

/** Performs the real `tools/call` round trip against the MCP server. */
export type MCPExecutor = (
  tool: MCPToolLike,
  args: Record<string, unknown>,
  context: ExecutionContext,
) => Promise<unknown>;

/** A raw MCP tool after vark has wrapped it. */
export interface WrappedMCPTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  /**
   * SHA-256 pin of `{ name, description, inputSchema }` taken at wrap time.
   * Every `check()`/`execute()` recomputes it — a mismatch means the
   * descriptor was mutated after wrapping (MCP rug pull) and the call is
   * refused with `DESCRIPTOR_PIN_VIOLATION`.
   */
  descriptorHash: string;
  /** Effective grants (defaults merged with the per-wrap defaults). */
  capabilities: CapabilityConfig;
  /** CTP signature for this tool. */
  compact: string;
  /** CTP signature plus token accounting. */
  compression: CompressionReport;
  /** Dry run: guards only, no server call. */
  check: (args?: unknown, options?: ExecutionOptions) => GuardResult;
  /** Guarded execution — runs the payload through vark, then the MCP server. */
  execute: (args?: unknown, options?: ExecutionOptions) => Promise<ToolExecutionResult>;
}

/** Canonical descriptor fingerprint for rug-pull detection. */
export function hashDescriptor(tool: Pick<MCPToolLike, 'name' | 'description' | 'inputSchema' | 'schema'>): string {
  const canonical = stableStringify({
    name: tool.name,
    description: tool.description ?? '',
    inputSchema: tool.inputSchema ?? tool.schema ?? {},
  });
  return createHash('sha256').update(canonical).digest('hex');
}

/**
 * Recompute the live descriptor hash and compare it to the wrap-time pin.
 * Returns a refusal when the server (or anyone holding the original object)
 * mutated the descriptor after wrapping.
 */
function checkDescriptorPin(
  entry: WrappedMCPTool,
  live: MCPToolLike,
): GuardResult | undefined {
  if (hashDescriptor(live) === entry.descriptorHash) return undefined;
  return {
    safe: false,
    blockedBy: 'DESCRIPTOR_PIN_VIOLATION',
    reason:
      `MCP descriptor for "${entry.name}" changed since wrap ` +
      `(pinned ${entry.descriptorHash.slice(0, 12)}…) — possible rug pull, refusing`,
  };
}

export interface VarkMCPAdapterOptions {
  config?: VarkConfig;
  executor?: MCPExecutor;
  /**
   * Reuse an existing runtime. This is how you keep the MCP tools inside the
   * host's anomaly-guard window and audit trail (shared sessions, one chain).
   * When provided, `config` is ignored.
   */
  runtime?: VarkRuntime;
}

function normalizeTool(raw: unknown): MCPToolLike {
  if (!raw || typeof raw !== 'object') throw new TypeError('MCP tool descriptor must be an object');
  const tool = raw as MCPToolLike;
  const name = typeof tool.name === 'string' ? tool.name.trim() : '';
  if (!name) throw new TypeError('MCP tool descriptor is missing "name"');
  return tool;
}

export class VarkMCPAdapter {
  /** The underlying runtime — exposed so hosts can register bespoke tools too. */
  readonly runtime: VarkRuntime;

  readonly #executor?: MCPExecutor;
  readonly #tools = new Map<string, WrappedMCPTool>();

  constructor(options: VarkMCPAdapterOptions = {}) {
    this.runtime = options.runtime ?? new VarkRuntime(options.config ?? {});
    this.#executor = options.executor;
  }

  /**
   * Wrap raw Anthropic MCP tools with vark protection.
   *
   * @param mcpTools          raw `{ name, description, inputSchema }` descriptors
   * @param defaultCapabilities grants applied to every wrapped tool
   * @param executor          per-call override for the MCP server round trip
   */
  wrapTools(
    mcpTools: unknown[],
    defaultCapabilities?: CapabilityConfig,
    executor?: MCPExecutor,
  ): WrappedMCPTool[] {
    const dispatch = executor ?? this.#executor;
    const wrapped: WrappedMCPTool[] = [];

    for (const raw of Array.isArray(mcpTools) ? mcpTools : []) {
      const tool = normalizeTool(raw);
      if (this.#tools.has(tool.name)) {
        throw new Error(`MCP tool "${tool.name}" is already wrapped`);
      }

      const inputSchema = tool.inputSchema ?? tool.schema ?? {};
      const capabilities: CapabilityConfig = { ...(defaultCapabilities ?? {}) };

      const guard = this.runtime.tool<Record<string, unknown>, unknown>({
        name: tool.name,
        description: tool.description ?? '',
        schema: inputSchema,
        capabilities,
        run: async (args: Record<string, unknown>, context: ExecutionContext) => {
          if (!dispatch) {
            throw new VarkError(
              'EXECUTION_ERROR',
              `MCP tool "${tool.name}" passed every guard, but no executor is bound to call the server`,
            );
          }
          return dispatch(tool, args, context);
        },
      });

      const entry: WrappedMCPTool = {
        name: tool.name,
        description: tool.description ?? '',
        inputSchema,
        descriptorHash: hashDescriptor(tool),
        capabilities: guard.capabilities,
        compact: guard.compact,
        compression: guard.compression,
        check: (args?: unknown, options?: ExecutionOptions): GuardResult => {
          const pin = checkDescriptorPin(entry, tool);
          if (pin) return pin;
          return this.runtime.check(tool.name, args, options);
        },
        execute: async (args?: unknown, options?: ExecutionOptions) => {
          const pin = checkDescriptorPin(entry, tool);
          if (pin) {
            const sessionId = options?.sessionId ?? this.runtime.session ?? DEFAULT_SESSION;
            const message = pin.reason ?? 'MCP descriptor changed since wrap';
            // Audited here because the guard pipeline is never reached.
            this.runtime.audit.append({
              sessionId,
              tool: tool.name,
              decision: 'DESCRIPTOR_PIN_VIOLATION',
              blockedBy: 'DESCRIPTOR_PIN_VIOLATION',
              reason: message,
              sanitizedInputs: args,
              executionTimeMs: 0,
            });
            return {
              success: false,
              blockedBy: 'DESCRIPTOR_PIN_VIOLATION',
              error: message,
              executionTimeMs: 0,
              sessionId,
            };
          }
          return guard.execute(args, options);
        },
      };

      this.#tools.set(entry.name, entry);
      wrapped.push(entry);
    }

    return wrapped;
  }

  get(name: string): WrappedMCPTool | undefined {
    return this.#tools.get(name);
  }

  list(): WrappedMCPTool[] {
    return [...this.#tools.values()];
  }

  /** Payload-only inspection (circuit breaker) for a raw argument object. */
  inspect(args: unknown): InspectionResult {
    return this.runtime.inspect(args);
  }

  /** Unwrap every tool registered through this adapter. */
  clear(): void {
    for (const name of this.#tools.keys()) this.runtime.unregister(name);
    this.#tools.clear();
  }
}

/** Functional shorthand for `new VarkMCPAdapter(options).wrapTools(...)`. */
export function wrapMCPTools(
  mcpTools: unknown[],
  defaultCapabilities?: CapabilityConfig,
  options: VarkMCPAdapterOptions = {},
): WrappedMCPTool[] {
  return new VarkMCPAdapter(options).wrapTools(mcpTools, defaultCapabilities);
}

export type { CompressionReport, ExecutionOptions, ExecutionContext, GuardResult, InspectionResult };
