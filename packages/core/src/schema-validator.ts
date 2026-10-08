/**
 * Runtime Schema Validation Gate
 *
 * Dependency-free JSON Schema (draft-07 subset) validator. Runs as an
 * explicit gate inside the pipeline — after authorisation, before execution —
 * so malformed or manipulated arguments are rejected with a precise reason
 * instead of reaching the tool body.
 *
 * Supported keywords: type, required, properties, additionalProperties,
 * items, enum, const, minimum, maximum, exclusiveMinimum, exclusiveMaximum,
 * minLength, maxLength, pattern, format (email/uri/date-time/uuid),
 * minItems, maxItems, uniqueItems, oneOf, anyOf, allOf, not, nullable.
 */

export interface SchemaValidationResult {
  valid: boolean;
  /** Human-readable reason for the first failure. */
  reason?: string;
  /** JSON Pointer to the offending value, e.g. `/items/2/price`. */
  path?: string;
}

type JsonSchema = Record<string, unknown>;

const FORMAT_VALIDATORS: Record<string, RegExp> = {
  email: /^[^@\s]+@[^@\s]+\.[^@\s]+$/,
  uri: /^[a-z][a-z0-9+.-]*:\/\/\S+$/i,
  'date-time': /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/,
  uuid: /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
};

function typeOf(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  if (typeof value === 'number') return Number.isInteger(value) ? 'integer' : 'number';
  return typeof value;
}

function matchesType(value: unknown, expected: string): boolean {
  const actual = typeOf(value);
  if (expected === 'number') return actual === 'number' || actual === 'integer';
  return actual === expected;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeOf(a) !== typeOf(b)) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((item, i) => deepEqual(item, b[i]));
  }
  if (isPlainObject(a) && isPlainObject(b)) {
    const keysA = Object.keys(a);
    const keysB = Object.keys(b);
    return keysA.length === keysB.length && keysA.every((k) => deepEqual(a[k], b[k]));
  }
  return false;
}

function validateNode(
  value: unknown,
  schema: JsonSchema,
  path: string,
  trail: Array<string | number>,
): SchemaValidationResult | undefined {
  // ── combinators ──────────────────────────────────────────────────────────
  if (Array.isArray(schema.oneOf)) {
    const matches = schema.oneOf.filter((sub) => validateNode(value, sub as JsonSchema, path, trail) === undefined);
    if (matches.length !== 1) {
      return { valid: false, reason: `value at ${path} must match exactly one schema (matched ${matches.length})`, path };
    }
  }
  if (Array.isArray(schema.anyOf)) {
    if (!schema.anyOf.some((sub) => validateNode(value, sub as JsonSchema, path, trail) === undefined)) {
      return { valid: false, reason: `value at ${path} must match at least one schema`, path };
    }
  }
  if (Array.isArray(schema.allOf)) {
    for (const sub of schema.allOf) {
      const failure = validateNode(value, sub as JsonSchema, path, trail);
      if (failure) return failure;
    }
  }
  if (schema.not !== undefined) {
    if (validateNode(value, schema.not as JsonSchema, path, trail) === undefined) {
      return { valid: false, reason: `value at ${path} must NOT match the given schema`, path };
    }
  }

  // ── type ──────────────────────────────────────────────────────────────────
  const typeDecl = schema.type;
  if (typeDecl !== undefined) {
    const types = Array.isArray(typeDecl) ? typeDecl : [typeDecl];
    const ok = types.some((t) => matchesType(value, String(t)));
    if (!ok) {
      return { valid: false, reason: `expected ${types.join(' or ')} at ${path}, got ${typeOf(value)}`, path };
    }
  }
  if (schema.nullable === true && value === null) return undefined;

  // ── enum / const ──────────────────────────────────────────────────────────
  if (Array.isArray(schema.enum) && !schema.enum.some((allowed) => deepEqual(value, allowed))) {
    return { valid: false, reason: `value at ${path} is not one of the allowed enum values`, path };
  }
  if (schema.const !== undefined && !deepEqual(value, schema.const)) {
    return { valid: false, reason: `value at ${path} must equal the constant`, path };
  }

  // ── string ────────────────────────────────────────────────────────────────
  if (typeof value === 'string') {
    if (schema.minLength !== undefined && value.length < Number(schema.minLength)) {
      return { valid: false, reason: `string at ${path} is shorter than minLength ${schema.minLength}`, path };
    }
    if (schema.maxLength !== undefined && value.length > Number(schema.maxLength)) {
      return { valid: false, reason: `string at ${path} is longer than maxLength ${schema.maxLength}`, path };
    }
    if (schema.pattern !== undefined && !new RegExp(String(schema.pattern)).test(value)) {
      return { valid: false, reason: `string at ${path} does not match pattern ${String(schema.pattern)}`, path };
    }
    const format = schema.format;
    if (typeof format === 'string' && FORMAT_VALIDATORS[format] !== undefined) {
      if (!FORMAT_VALIDATORS[format].test(value)) {
        return { valid: false, reason: `string at ${path} is not a valid ${format}`, path };
      }
    }
  }

  // ── number ────────────────────────────────────────────────────────────────
  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < Number(schema.minimum)) {
      return { valid: false, reason: `number at ${path} is below minimum ${schema.minimum}`, path };
    }
    if (schema.maximum !== undefined && value > Number(schema.maximum)) {
      return { valid: false, reason: `number at ${path} is above maximum ${schema.maximum}`, path };
    }
    if (schema.exclusiveMinimum !== undefined && value <= Number(schema.exclusiveMinimum)) {
      return { valid: false, reason: `number at ${path} must be > ${schema.exclusiveMinimum}`, path };
    }
    if (schema.exclusiveMaximum !== undefined && value >= Number(schema.exclusiveMaximum)) {
      return { valid: false, reason: `number at ${path} must be < ${schema.exclusiveMaximum}`, path };
    }
    if (schema.multipleOf !== undefined && value % Number(schema.multipleOf) !== 0) {
      return { valid: false, reason: `number at ${path} is not a multiple of ${schema.multipleOf}`, path };
    }
  }

  // ── array ─────────────────────────────────────────────────────────────────
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < Number(schema.minItems)) {
      return { valid: false, reason: `array at ${path} has fewer than minItems ${schema.minItems}`, path };
    }
    if (schema.maxItems !== undefined && value.length > Number(schema.maxItems)) {
      return { valid: false, reason: `array at ${path} has more than maxItems ${schema.maxItems}`, path };
    }
    if (schema.uniqueItems === true) {
      const seen: unknown[] = [];
      for (const item of value) {
        if (seen.some((prior) => deepEqual(prior, item))) {
          return { valid: false, reason: `array at ${path} must have unique items`, path };
        }
        seen.push(item);
      }
    }
    if (schema.items !== undefined) {
      const itemSchema = schema.items as JsonSchema;
      for (let i = 0; i < value.length; i += 1) {
        const failure = validateNode(value[i], itemSchema, `${path}/${i}`, [...trail, i]);
        if (failure) return failure;
      }
    }
  }

  // ── object ────────────────────────────────────────────────────────────────
  if (isPlainObject(value)) {
    const required = Array.isArray(schema.required) ? schema.required.map(String) : [];
    for (const key of required) {
      if (!(key in value)) {
        return { valid: false, reason: `missing required property "${key}" at ${path}`, path };
      }
    }

    const properties = isPlainObject(schema.properties) ? schema.properties : {};
    const additional = schema.additionalProperties;

    for (const [key, child] of Object.entries(value)) {
      const childPath = `${path}/${key}`;
      const childTrail = [...trail, key];
      const sub = properties[key] as JsonSchema | undefined;
      if (sub !== undefined) {
        const failure = validateNode(child, sub, childPath, childTrail);
        if (failure) return failure;
      } else if (additional === false) {
        return { valid: false, reason: `additional property "${key}" is not allowed at ${path}`, path };
      } else if (isPlainObject(additional)) {
        const failure = validateNode(child, additional, childPath, childTrail);
        if (failure) return failure;
      }
    }
  }

  return undefined;
}

/**
 * Validate `value` against a JSON Schema. Returns `{ valid: true }` or the
 * first failure with a JSON-pointer path.
 */
export function validateSchema(value: unknown, schema: JsonSchema): SchemaValidationResult {
  if (schema === undefined) return { valid: true };
  const failure = validateNode(value, schema, '', []);
  return failure ?? { valid: true };
}

/** Coerce common JSON-Schema type mismatches (e.g. `"42"` → `42`). */
export function coerceValue(value: unknown, schema: JsonSchema): { value: unknown; coerced: boolean } {
  if (!isPlainObject(schema)) return { value, coerced: false };
  const type = schema.type;

  if (type === 'integer' || type === 'number') {
    if (typeof value === 'string' && value.trim() !== '' && !Number.isNaN(Number(value))) {
      const num = Number(value);
      return { value: type === 'integer' ? Math.trunc(num) : num, coerced: true };
    }
  }
  if (type === 'boolean') {
    if (value === 'true') return { value: true, coerced: true };
    if (value === 'false') return { value: false, coerced: true };
  }
  if (type === 'array' && !Array.isArray(value)) {
    return { value: [value], coerced: true };
  }
  return { value, coerced: false };
}

/**
 * Recursively coerce a value against a schema: object properties and array
 * items are coerced with their subschemas, so `{ n: '42' }` against
 * `{ properties: { n: { type: 'integer' } } }` becomes `{ n: 42 }`.
 *
 * Copy-on-write: containers are only cloned when at least one descendant
 * was coerced; otherwise the original references are returned untouched.
 */
export function coerceValueDeep(value: unknown, schema: JsonSchema): { value: unknown; coerced: boolean } {
  if (!isPlainObject(schema)) return { value, coerced: false };

  if ((schema.type === 'object' || schema.properties !== undefined) && isPlainObject(value)) {
    const properties =
      isPlainObject(schema.properties) ? (schema.properties as Record<string, JsonSchema>) : {};
    let changed = false;
    const out: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) {
      const sub = properties[key];
      if (sub !== undefined) {
        const coerced = coerceValueDeep(child, sub);
        out[key] = coerced.value;
        if (coerced.coerced) changed = true;
      } else {
        out[key] = child;
      }
    }
    return changed ? { value: out, coerced: true } : { value, coerced: false };
  }

  if (schema.type === 'array' && Array.isArray(value) && isPlainObject(schema.items)) {
    const itemSchema = schema.items as JsonSchema;
    let changed = false;
    const out = value.map((item) => {
      const coerced = coerceValueDeep(item, itemSchema);
      if (coerced.coerced) changed = true;
      return coerced.value;
    });
    return changed ? { value: out, coerced: true } : { value, coerced: false };
  }

  return coerceValue(value, schema);
}
