import "server-only";

import { z } from "zod";
import { BoundedJsonResponseError, readBoundedJson } from "./bounded_json";

/** Inbound console JSON cap, including simulator args and session facts. */
export const MAX_API_REQUEST_BYTES = 256 * 1024;
export const API_REQUEST_BODY_TIMEOUT_MS = 5_000;

/** Read a bounded JSON request, validate it, and return a safe client error. */
export async function parseJsonBody<S extends z.ZodType>(
  request: Request,
  schema: S,
  timeoutMs = API_REQUEST_BODY_TIMEOUT_MS,
): Promise<
  | { ok: true; data: z.infer<S> }
  | { ok: false; status: 400 | 408 | 413; error: string }
> {
  let raw: unknown;
  try {
    raw = await readBoundedJson(
      request,
      MAX_API_REQUEST_BYTES,
      "console request",
      timeoutMs,
    );
  } catch (error) {
    if (
      error instanceof BoundedJsonResponseError &&
      error.message.includes("exceeded the size limit")
    ) {
      return {
        ok: false,
        status: 413,
        error: `request body exceeds the ${MAX_API_REQUEST_BYTES}-byte limit`,
      };
    }
    if (error instanceof BoundedJsonResponseError && error.message.includes("timed out")) {
      return { ok: false, status: 408, error: "request body read timed out" };
    }
    return { ok: false, status: 400, error: "request body must be valid JSON" };
  }

  const parsed = schema.safeParse(raw);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const where = issue?.path?.length ? `${issue.path.join(".")}: ` : "";
    return {
      ok: false,
      status: 400,
      error: `${where}${issue?.message ?? "validation failed"}`,
    };
  }
  return { ok: true, data: parsed.data };
}
