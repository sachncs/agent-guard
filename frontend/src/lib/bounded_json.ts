import "server-only";

export type BoundedJsonFailureKind =
  | "size_limit"
  | "timeout"
  | "empty"
  | "read"
  | "utf8"
  | "json";

/** A bounded JSON stream violated the caller's transport contract. */
export class BoundedJsonResponseError extends Error {
  constructor(
    readonly kind: BoundedJsonFailureKind,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "BoundedJsonResponseError";
  }
}

/** Read, bound, UTF-8 decode, and parse an upstream JSON response. */
export async function readBoundedJson(
  response: Pick<Response, "headers" | "body">,
  maxBytes: number,
  source: string,
  timeoutMs?: number,
): Promise<unknown> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    throw new RangeError("maxBytes must be a positive safe integer");
  }
  if (timeoutMs !== undefined && (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1)) {
    throw new RangeError("timeoutMs must be a positive safe integer");
  }
  const declaredLength = response.headers.get("content-length");
  if (
    declaredLength &&
    /^\d+$/.test(declaredLength) &&
    Number(declaredLength) > maxBytes
  ) {
    await response.body?.cancel().catch(() => undefined);
    throw new BoundedJsonResponseError("size_limit", `${source} response exceeded the size limit`);
  }
  if (!response.body) throw new BoundedJsonResponseError("empty", `${source} returned an empty response`);

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const readBody = async () => {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        await reader.cancel().catch(() => undefined);
        throw new BoundedJsonResponseError("size_limit", `${source} response exceeded the size limit`);
      }
      chunks.push(value);
    }
  };
  try {
    if (timeoutMs === undefined) {
      await readBody();
    } else {
      const timeout = new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          void reader.cancel().catch(() => undefined);
          reject(new BoundedJsonResponseError("timeout", `${source} response body timed out`));
        }, timeoutMs);
      });
      await Promise.race([readBody(), timeout]);
    }
  } catch (error) {
    if (error instanceof BoundedJsonResponseError) throw error;
    throw new BoundedJsonResponseError("read", `${source} response body could not be read`, { cause: error });
  } finally {
    if (timer) clearTimeout(timer);
    reader.releaseLock();
  }

  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    throw new BoundedJsonResponseError("utf8", `${source} returned invalid UTF-8`, { cause: error });
  }
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new BoundedJsonResponseError("json", `${source} returned invalid JSON`, { cause: error });
  }
}
