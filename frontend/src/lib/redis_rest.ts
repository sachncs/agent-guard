import "server-only";
import { BoundedJsonResponseError, readBoundedJson } from "./bounded_json.ts";

/** Bound Redis REST replies before buffering or parsing JSON. */
export const MAX_REDIS_RESPONSE_BYTES = 256 * 1024;

class RedisRestError extends Error {}

/** Shared HTTP adapter for Redis-compatible REST command endpoints. */
export class RedisRestClient {
  constructor(
    private readonly url: string,
    private readonly token: string,
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly timeoutMs = 3_000,
  ) {}

  async command(command: string[]): Promise<unknown> {
    let response: Response;
    try {
      response = await this.fetchImpl(this.url, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(command),
        signal: AbortSignal.timeout(this.timeoutMs),
        redirect: "error",
        cache: "no-store",
      });
    } catch (error) {
      throw new RedisRestError("Redis-compatible store request failed", { cause: error });
    }
    if (!response.ok) {
      await response.body?.cancel().catch(() => undefined);
      throw new RedisRestError(`Redis-compatible store returned HTTP ${response.status}`);
    }

    let payload: unknown;
    try {
      payload = await readBoundedJson(response, MAX_REDIS_RESPONSE_BYTES, "Redis-compatible store");
    } catch (error) {
      if (error instanceof BoundedJsonResponseError) throw new RedisRestError(error.message, { cause: error });
      throw new RedisRestError("Redis-compatible store returned invalid JSON", { cause: error });
    }
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      throw new RedisRestError("Redis-compatible store returned an invalid response");
    }
    if (Object.hasOwn(payload, "error")) {
      throw new RedisRestError("Redis-compatible store rejected the command");
    }
    if (!Object.hasOwn(payload, "result")) {
      throw new RedisRestError("Redis-compatible store response is missing its result");
    }
    return (payload as { result: unknown }).result;
  }

  async healthCheck(): Promise<void> {
    if (await this.command(["PING"]) !== "PONG") {
      throw new RedisRestError("Redis-compatible store health check failed");
    }
  }
}
