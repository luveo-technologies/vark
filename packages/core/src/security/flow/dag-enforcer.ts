/**
 * Stateful DAG Flow Enforcement
 *
 * Enforces tool execution dependency graphs. For example, `execute_payment`
 * is rejected unless preceded by `verify_cart` in the same session.
 * Prevents agents from skipping critical verification steps.
 */

export interface DagNode {
  /** Tool name. */
  tool: string;
  /** Human-readable description. */
  description: string;
  /** Tools that must execute before this one. */
  dependsOn: string[];
  /** Tools that are mutually exclusive with this one (cannot both run). */
  mutuallyExclusiveWith?: string[];
  /** Maximum number of times this tool can run per session. @default Infinity */
  maxExecutions?: number;
}

export interface DagConfig {
  /** DAG nodes defining the execution graph. */
  nodes: DagNode[];
  /** Whether to enforce dependencies strictly. @default true */
  strict?: boolean;
}

export interface DagCheckResult {
  allowed: boolean;
  reason?: string;
  /** Missing dependencies that were required. */
  missingDependencies: string[];
}

/**
 * Per-session DAG execution tracker. Enforces dependency graphs and
 * execution limits.
 */
export class DagFlowEnforcer {
  readonly #config: Required<DagConfig>;
  readonly #nodes = new Map<string, DagNode>();
  readonly #sessionExecutions = new Map<string, Map<string, number>>();
  readonly #sessionOrder = new Map<string, string[]>();

  constructor(config: DagConfig) {
    this.#config = {
      nodes: config.nodes,
      strict: config.strict ?? true,
    };
    for (const node of config.nodes) {
      this.#nodes.set(node.tool, node);
    }
  }

  /** Check if a tool is allowed to execute in the given session. */
  checkExecution(sessionId: string, tool: string): DagCheckResult {
    const node = this.#nodes.get(tool);
    if (!node) {
      return { allowed: true, missingDependencies: [] };
    }

    const executions = this.#getExecutions(sessionId);

    // Check max executions.
    const currentCount = executions.get(tool) ?? 0;
    if (node.maxExecutions !== undefined && currentCount >= node.maxExecutions) {
      return {
        allowed: false,
        reason: `Tool "${tool}" has exceeded max executions (${node.maxExecutions}) in this session`,
        missingDependencies: [],
      };
    }

    // Check dependencies.
    const missingDependencies: string[] = [];
    for (const dep of node.dependsOn) {
      if (!executions.has(dep)) {
        missingDependencies.push(dep);
      }
    }

    if (missingDependencies.length > 0 && this.#config.strict) {
      return {
        allowed: false,
        reason: `Tool "${tool}" requires prior execution of: ${missingDependencies.join(', ')}`,
        missingDependencies,
      };
    }

    // Check mutual exclusivity.
    if (node.mutuallyExclusiveWith) {
      for (const exclusive of node.mutuallyExclusiveWith) {
        if (executions.has(exclusive)) {
          return {
            allowed: false,
            reason: `Tool "${tool}" is mutually exclusive with "${exclusive}" which already executed`,
            missingDependencies: [],
          };
        }
      }
    }

    return { allowed: true, missingDependencies: [] };
  }

  /** Record a tool execution in the session. */
  recordExecution(sessionId: string, tool: string): void {
    const executions = this.#getExecutions(sessionId);
    executions.set(tool, (executions.get(tool) ?? 0) + 1);

    const order = this.#getOrder(sessionId);
    order.push(tool);
  }

  /** Get execution count for a tool in a session. */
  getExecutionCount(sessionId: string, tool: string): number {
    return this.#getExecutions(sessionId).get(tool) ?? 0;
  }

  /** Get execution order for a session. */
  getExecutionOrder(sessionId: string): string[] {
    return [...this.#getOrder(sessionId)];
  }

  /** Reset session state. */
  resetSession(sessionId: string): void {
    this.#sessionExecutions.delete(sessionId);
    this.#sessionOrder.delete(sessionId);
  }

  /** Reset all sessions. */
  resetAll(): void {
    this.#sessionExecutions.clear();
    this.#sessionOrder.clear();
  }

  get sessionCount(): number {
    return this.#sessionExecutions.size;
  }

  #getExecutions(sessionId: string): Map<string, number> {
    let executions = this.#sessionExecutions.get(sessionId);
    if (!executions) {
      executions = new Map();
      this.#sessionExecutions.set(sessionId, executions);
    }
    return executions;
  }

  #getOrder(sessionId: string): string[] {
    let order = this.#sessionOrder.get(sessionId);
    if (!order) {
      order = [];
      this.#sessionOrder.set(sessionId, order);
    }
    return order;
  }
}

/**
 * Common DAG patterns for typical agent workflows.
 */
export const COMMON_DAG_PATTERNS: Record<string, DagNode[]> = {
  payment: [
    { tool: 'verify_cart', description: 'Verify cart contents and pricing', dependsOn: [] },
    { tool: 'check_inventory', description: 'Check item availability', dependsOn: ['verify_cart'] },
    { tool: 'execute_payment', description: 'Process payment', dependsOn: ['verify_cart', 'check_inventory'] },
    { tool: 'send_confirmation', description: 'Send order confirmation', dependsOn: ['execute_payment'] },
  ],
  deployment: [
    { tool: 'run_tests', description: 'Run test suite', dependsOn: [] },
    { tool: 'build_image', description: 'Build container image', dependsOn: ['run_tests'] },
    { tool: 'push_image', description: 'Push image to registry', dependsOn: ['build_image'] },
    { tool: 'deploy', description: 'Deploy to production', dependsOn: ['push_image'], maxExecutions: 1 },
  ],
  data_migration: [
    { tool: 'backup_database', description: 'Create database backup', dependsOn: [] },
    { tool: 'validate_schema', description: 'Validate migration schema', dependsOn: ['backup_database'] },
    { tool: 'run_migration', description: 'Execute migration', dependsOn: ['validate_schema'] },
    { tool: 'verify_migration', description: 'Verify migration results', dependsOn: ['run_migration'] },
  ],
};
