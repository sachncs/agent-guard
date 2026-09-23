import "server-only";

/** A remote JSON response violated the caller's transport contract. */
export class BoundedJsonResponseError extends Error {}

/** Read, bound, UTF-8 decode, and parse an upstream JSON response. */
export async function readBoundedJson(
  response: Response,
  maxBytes: number,
  source: string,
): Promise<unknown> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    throw new RangeError("maxBytes must be a positive safe integer");
  }
  const declaredLength = response.headers.get("content-length");
  if (
    declaredLength &&
    /^\d+$/.test(declaredLength) &&
    Number(declaredLength) > maxBytes
  ) {
    await response.body?.cancel().catch(() => undefined);
    throw new BoundedJsonResponseError(`${source} response exceeded the size limit`);
  }
  if (!response.body) throw new BoundedJsonResponseError(`${source} returned an empty response`);

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        await reader.cancel().catch(() => undefined);
        throw new BoundedJsonResponseError(`${source} response exceeded the size limit`);
      }
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof BoundedJsonResponseError) throw error;
    throw new BoundedJsonResponseError(`${source} response body could not be read`, { cause: error });
  } finally {
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
    throw new BoundedJsonResponseError(`${source} returned invalid UTF-8`, { cause: error });
  }
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new BoundedJsonResponseError(`${source} returned invalid JSON`, { cause: error });
  }
}
