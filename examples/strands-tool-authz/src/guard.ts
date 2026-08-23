/**
 * agentguard guard for Strands Agents (TypeScript).
 *
 * Wraps Strands tools so that every invocation is authorized against an
 * agentguard PDP (`agentguard serve`, OpenID AuthZEN wire format) before
 * the tool callback runs.
 *
 * Semantics are fail-closed: if the PDP cannot be reached, returns a
 * malformed response, or no principal can be resolved, the call is denied
 * and the model receives the denial as tool-result feedback.
 */

import { tool } from "@strands-agents/sdk";
import type { JSONValue, ToolContext } from "@strands-agents/sdk";
import type { z } from "zod";

/** AuthZEN entity reference: `{ "type": "User", "id": "alice" }`. */
export interface AuthZenEntity {
  type: string;
  id: string;
}

export interface AgentGuardOptions {
  /**
   * Base URL of the agentguard AuthZEN PDP (no trailing slash).
   * Defaults to AGENTGUARD_URL, then http://127.0.0.1:8443.
   */
  pdpUrl?: string;
  /** Bearer token when the PDP runs with `AGENTGUARD_AUTH=apikey:<path>`. */
  bearerToken?: string;
  /**
   * Resolves the requesting principal for each evaluation. May return
   * undefined to deny everything for the current request (fail-closed),
   * e.g. when no user is attached to the session.
   */
  principal: AuthZenEntity | (() => AuthZenEntity | undefined);
  /** Resource the tools act upon. Defaults to Resource::"agent". */
  resource?: AuthZenEntity;
}

export class ToolDeniedError extends Error {
  constructor(
    public readonly toolName: string,
    public readonly reason?: string
  ) {
    super(
      `agentguard DENY ${toolName}${reason ? `: ${reason}` : " (no matching permit policy)"}`
    );
    this.name = "ToolDeniedError";
  }
}

export class AgentGuard {
  private readonly pdpUrl: string;
  private readonly bearerToken?: string;
  private readonly principal: AgentGuardOptions["principal"];
  private readonly resource: AuthZenEntity;

  constructor(options: AgentGuardOptions) {
    this.pdpUrl = (
      options.pdpUrl ??
      process.env.AGENTGUARD_URL ??
      "http://127.0.0.1:8443"
    ).replace(/\/$/, "");
    this.bearerToken = options.bearerToken ?? process.env.AGENTGUARD_BEARER;
    this.principal = options.principal;
    this.resource = options.resource ?? { type: "Resource", id: "agent" };
  }

  /** Evaluate one tool call. Throws ToolDeniedError on deny / failure. */
  async authorize(toolName: string, args: unknown): Promise<void> {
    const principal =
      typeof this.principal === "function" ? this.principal() : this.principal;

    if (!principal) {
      throw new ToolDeniedError(toolName, "no principal could be resolved");
    }

    let res: Response;
    try {
      res = await fetch(`${this.pdpUrl}/access/v1/evaluation`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(this.bearerToken && { Authorization: `Bearer ${this.bearerToken}` }),
        },
        body: JSON.stringify({
          subject: principal,
          action: { type: "Action", id: `ToolCall::${toolName}` },
          resource: this.resource,
          context: { args: args ?? {}, session: {} },
        }),
        signal: AbortSignal.timeout(5_000),
      });
    } catch (e) {
      throw new ToolDeniedError(
        toolName,
        `PDP unreachable (${e instanceof Error ? e.message : e})`
      );
    }

    if (!res.ok) {
      throw new ToolDeniedError(toolName, `PDP returned HTTP ${res.status}`);
    }

    const body = (await res.json()) as { decision?: boolean; reason?: string };
    if (body.decision !== true) {
      throw new ToolDeniedError(toolName, body.reason);
    }
  }
}

/** Mirrors the SDK's `ToolConfig` (not re-exported from the package index). */
interface ToolConfigLike<TInput extends z.ZodType | undefined, TReturn extends JSONValue> {
  name: string;
  description: string;
  inputSchema?: TInput;
  // Note: async-generator (streaming) callbacks are not supported by the guard.
  callback: (
    input: TInput extends z.ZodType ? z.infer<TInput> : undefined,
    context?: ToolContext
  ) => Promise<TReturn> | TReturn;
}

/**
 * Wrap a Strands tool config so its callback only runs after the PDP
 * allows it. Denied calls surface to the model as an error tool result,
 * so the agent can react instead of crashing.
 */
export function guarded<TInput extends z.ZodType | undefined, TReturn extends JSONValue>(
  guard: AgentGuard,
  config: ToolConfigLike<TInput, TReturn>
) {
  const callback = config.callback;
  return tool({
    ...config,
    async callback(
      input: TInput extends z.ZodType ? z.infer<TInput> : undefined,
      context?: ToolContext
    ): Promise<TReturn> {
      await guard.authorize(config.name, input);
      return callback(input, context);
    },
  });
}
