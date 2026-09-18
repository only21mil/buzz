/**
 * Shared argument checks for browser PAL command handlers. Every relay-backed
 * command receives an untyped invoke body; these helpers narrow it with the
 * same error messages the desktop commands return.
 */
export type ObjectBody = Record<string, unknown>;

export function objectBody(body: unknown, command: string): ObjectBody {
  if (
    !body ||
    typeof body !== "object" ||
    Array.isArray(body) ||
    body instanceof ArrayBuffer ||
    body instanceof Uint8Array
  ) {
    throw new TypeError(`${command} requires an object body`);
  }
  return body as ObjectBody;
}

export function optionalString(
  body: ObjectBody,
  field: string,
): string | undefined {
  const value = body[field];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") {
    throw new TypeError(`${field} must be a string`);
  }
  return value;
}

export function requiredString(body: ObjectBody, field: string): string {
  const value = optionalString(body, field);
  if (value === undefined) throw new TypeError(`${field} must be a string`);
  return value;
}

export function optionalNumber(
  body: ObjectBody,
  field: string,
): number | undefined {
  const value = body[field];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new TypeError(`${field} must be an integer`);
  }
  return value;
}
