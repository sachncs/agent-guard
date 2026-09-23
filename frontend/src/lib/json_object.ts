export type JsonObject = Record<string, unknown>;

export type JsonObjectParseResult =
  | { ok: true; value: JsonObject }
  | { ok: false; error: string };

/** Parse optional JSON context as an object and give the caller a safe field error. */
export function parseJsonObject(input: string, fieldName: string): JsonObjectParseResult {
  const text = input.trim();
  if (!text) return { ok: true, value: {} };

  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return { ok: false, error: `${fieldName} must contain valid JSON.` };
  }

  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return { ok: false, error: `${fieldName} must be a JSON object.` };
  }

  return { ok: true, value: value as JsonObject };
}
