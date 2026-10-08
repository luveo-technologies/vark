/**
 * Compact Tool Protocol (CTP).
 *
 * Tool definitions are the single largest recurring cost in an agent context
 * window: verbose JSON Schemas repeat `type`, `properties`, `required` and
 * long `description` keys on every request. CTP rewrites them as a compact
 * TypeScript signature that an LLM reads in a fraction of the tokens while
 * remaining unambiguous.
 *
 *   { "type":"object", "properties": { "query": {"type":"string"},
 *     "limit": {"type":"integer"} }, "required":["query"] }
 *                      ↓
 *   a single line: an inline description comment followed by
 *   `type search = (query: string, limit?: number) => any;`
 */

export interface CompressionReport {
  /** The CTP signature string. */
  compact: string;
  /** Pretty-printed original tool definition, exactly as displayed. */
  originalJson: string;
  originalTokens: number;
  compactTokens: number;
  savedTokens: number;
  savedPercent: number;
}

type JsonSchemaLike = Record<string, unknown>;

/** Rough public heuristic: ≈4 characters per token. */
export function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

function literal(value: unknown): string {
  if (typeof value === 'string') return JSON.stringify(value);
  if (value === null) return 'null';
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return JSON.stringify(value) ?? 'any';
}

/** Quote a property name only when it is not a valid TypeScript identifier. */
function safeKey(key: string): string {
  return /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(key) ? key : JSON.stringify(key);
}

/** Make a tool name usable as a TS type name (`mcp__fs__read` → `mcp__fs__read`). */
function safeIdentifier(name: string): string {
  const cleaned = name.replace(/[^A-Za-z0-9_$]/g, '_');
  return /^[0-9]/.test(cleaned) ? `_${cleaned}` : cleaned;
}

function isSimpleType(type: string): boolean {
  return !/[\s|&<>[\]{}]/.test(type);
}

function objectType(node: JsonSchemaLike): string {
  const properties = (node.properties ?? {}) as JsonSchemaLike;
  const required = new Set<string>(Array.isArray(node.required) ? node.required : []);
  const entries = Object.entries(properties);

  if (entries.length === 0) {
    if (node.additionalProperties && typeof node.additionalProperties === 'object') {
      const valueType = resolveType(node.additionalProperties) ?? 'any';
      return `Record<string, ${valueType}>`;
    }
    return 'Record<string, any>';
  }

  const body = entries
    .map(([key, sub]) => `${safeKey(key)}${required.has(key) ? '' : '?'}: ${resolveType(sub) ?? 'any'};`)
    .join(' ');
  return `{ ${body} }`;
}

/** Map a JSON Schema node onto its TypeScript equivalent. */
function resolveType(node: unknown): string | undefined {
  if (!node || typeof node !== 'object') return undefined;
  const schema = node as JsonSchemaLike;

  if (schema.const !== undefined) return literal(schema.const);

  if (Array.isArray(schema.enum) && schema.enum.length > 0) {
    const members = schema.enum.map((value: unknown) => literal(value));
    return [...new Set(members)].join(' | ');
  }

  const union: string[] = [];
  for (const key of ['oneOf', 'anyOf'] as const) {
    if (!Array.isArray(schema[key])) continue;
    for (const member of schema[key] as unknown[]) {
      const type = resolveType(member);
      if (type) union.push(type);
    }
  }
  if (union.length > 0) return [...new Set(union)].join(' | ');

  if (Array.isArray(schema.allOf)) {
    const parts = (schema.allOf as unknown[])
      .map((member) => resolveType(member))
      .filter((type): type is string => Boolean(type));
    if (parts.length > 0) return parts.join(' & ');
  }

  if (Array.isArray(schema.type)) {
    const parts = (schema.type as unknown[])
      .map((member) => resolveType({ type: member }))
      .filter((type): type is string => Boolean(type));
    if (parts.length > 0) return [...new Set(parts)].join(' | ');
  }

  if (typeof schema.type === 'string') {
    switch (schema.type) {
      case 'object':
        return objectType(schema);
      case 'array': {
        const inner = resolveType(schema.items) ?? 'any';
        return isSimpleType(inner) ? `${inner}[]` : `Array<${inner}>`;
      }
      case 'string':
        return 'string';
      case 'number':
      case 'integer':
        return 'number';
      case 'boolean':
        return 'boolean';
      case 'null':
        return 'null';
      default:
        return undefined;
    }
  }

  if (schema.properties) return objectType(schema);
  return undefined;
}

function buildSignature(schema: JsonSchemaLike): string {
  const properties = (schema.properties ?? {}) as JsonSchemaLike;
  const required = new Set<string>(Array.isArray(schema.required) ? schema.required : []);

  const params = Object.entries(properties).map(([key, sub]) => {
    const optional = required.has(key) ? '' : '?';
    return `${safeKey(key)}${optional}: ${resolveType(sub) ?? 'any'}`;
  });

  return `(${params.join(', ')})`;
}

function comment(description: string): string {
  const flat = String(description ?? '').replace(/\s*\r?\n+/g, ' ').trim();
  // Keep the block comment closable on one line: neutralize any `*/` in text.
  const safe = flat.replace(/\*\//g, '* /');
  return safe.length > 0 ? safe : 'no description';
}

/**
 * Convert a verbose JSON Schema into a compact TypeScript signature.
 *
 * Single line: an inline `slash-star` description comment followed by the
 * `type` signature, so consumers splitting on `\n` count exactly one entry
 * per tool. The optional `returns` / `x-returns` hint customises the return
 * type; otherwise it is `any`.
 */
export function compressSchema(name: string, description: string, jsonSchema: object): string {
  const schema = (jsonSchema ?? {}) as JsonSchemaLike;
  const returns = resolveType(schema.returns ?? schema['x-returns']) ?? 'any';
  return `/* ${comment(description)} */ type ${safeIdentifier(name)} = ${buildSignature(schema)} => ${returns};`;
}

/**
 * Compress a tool *and* measure the win: original JSON vs CTP signature with
 * token estimates for both.
 */
export function analyzeCompression(
  name: string,
  description: string,
  jsonSchema: object,
): CompressionReport {
  const compact = compressSchema(name, description, jsonSchema);
  const originalJson =
    JSON.stringify({ name, description, inputSchema: jsonSchema }, null, 2) ?? '{}';

  const originalTokens = estimateTokens(originalJson);
  const compactTokens = estimateTokens(compact);
  const savedTokens = originalTokens - compactTokens;

  return {
    compact,
    originalJson,
    originalTokens,
    compactTokens,
    savedTokens,
    savedPercent: originalTokens > 0 ? (savedTokens / originalTokens) * 100 : 0,
  };
}
