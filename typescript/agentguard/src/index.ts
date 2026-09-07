/**
 * agentguard — Cedar-powered authorization for AI agents (TypeScript SDK).
 *
 * Wraps the `agentguard` CLI binary. Mirrors the Python SDK surface.
 */

/** Who is performing the action: an end user, an agent, or a subagent. */
export type Principal =
  | { type: "user"; uid: string; attrs?: Record<string, unknown> }
  | { type: "agent"; uid: string; parent_uid?: string; attrs?: Record<string, unknown> };

/** What is being performed: a tool invocation, optionally scoped to an operation. */
export interface AgentAction {
  tool: string;
  operation?: string;
}

/** What the action targets, identified by Cedar entity type and uid. */
export interface Resource {
  entity_type: string;
  uid: string;
  attrs?: Record<string, unknown>;
}

/** Call-specific data (tool arguments, session state) evaluated by Cedar policies. */
export interface AgentContext {
  args?: Record<string, unknown>;
  session?: Record<string, unknown>;
}

/** Identity-assurance requirements that must be satisfied before access. */
export interface StepUp {
  acr_values: string;
  amr_values: string;
}

/** Result of an authorization evaluation against the agentguard PDP. */
export interface Decision {
  effect: "allow" | "deny";
  policies: string[];
  reasons: string[];
  request: Record<string, unknown>;
  raw: Record<string, unknown>;
  trace_id?: string;
  span_id?: string;
  tenant_id?: string;
  step_up?: StepUp;
}

/** Base class for all errors raised by this SDK. */
export class AgentguardError extends Error {}
/** Thrown by {@link Client.check} when the PDP denies the request. */
export class AuthorizationDenied extends AgentguardError {
  /** The full denial decision, including matched policies and reasons. */
  readonly decision: Decision;
  constructor(decision: Decision) {
    super(`authorization denied: ${decision.reasons.join("; ") || "no matching policy"}`);
    this.decision = decision;
  }
}
/** Thrown when a decision allows only after additional identity assurance. */
export class StepUpRequired extends AgentguardError {
  /** The required authentication context (acr/amr values). */
  readonly stepUp: StepUp;
  /** The conditional decision that triggered the step-up requirement. */
  readonly decision: Decision;
  constructor(stepUp: StepUp, decision: Decision) {
    super(
      `step-up required: acr_values=${JSON.stringify(stepUp.acr_values)} ` +
        `amr_values=${JSON.stringify(stepUp.amr_values)}`
    );
    this.stepUp = stepUp;
    this.decision = decision;
  }
}
/** Thrown when the agentguard CLI binary cannot be found or spawned. */
export class CLIUnavailable extends AgentguardError {}

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { freshTraceContext, parseTraceparent, type TraceContext } from "./trace.js";

export { freshTraceContext, parseTraceparent, type TraceContext };

function findCli(explicit?: string): string {
  if (explicit && existsSync(explicit)) return explicit;
  const envBin = process.env.AGENTGUARD_BIN;
  if (envBin && existsSync(envBin)) return envBin;
  const cargoBin = join(homedir(), ".cargo", "bin", "agentguard");
  if (existsSync(cargoBin)) return cargoBin;
  throw new CLIUnavailable(
    "agentguard CLI not found. Install with: cargo install --path crates/agentguard-cli"
  );
}

/** Options for constructing a {@link Client}. */
export interface ClientOptions {
  /** Path to the agentguard store directory (defaults to `.agentguard`). */
  store?: string;
  /** Path to the JSONL audit log (defaults to `.audit/decisions.jsonl`). */
  auditLog?: string;
  /** Explicit path to the `agentguard` binary, bypassing discovery. */
  cliBin?: string;
  /** Bearer token forwarded to the CLI as AGENTGUARD_BEARER. */
  bearerToken?: string;
  /** W3C traceparent header forwarded to the CLI as AGENTGUARD_TRACEPARENT. */
  traceparent?: string;
}

/**
 * Synchronous client that shells out to the `agentguard` CLI binary.
 *
 * Every method spawns a short-lived process; construct one client and reuse
 * it rather than creating one per call.
 */
export class Client {
  private store: string;
  private auditLog: string;
  private cli: string;
  private bearerToken?: string;
  private traceparent?: string;

  constructor(opts: ClientOptions = {}) {
    this.store = opts.store ?? ".agentguard";
    this.auditLog = opts.auditLog ?? ".audit/decisions.jsonl";
    this.cli = findCli(opts.cliBin);
    this.bearerToken = opts.bearerToken;
    this.traceparent = opts.traceparent;
  }

  private run(args: string[], stdin?: string): string {
    const env: NodeJS.ProcessEnv = { ...process.env };
    if (this.bearerToken) env.AGENTGUARD_BEARER = this.bearerToken;
    if (this.traceparent) env.AGENTGUARD_TRACEPARENT = this.traceparent;
    const res = spawnSync(
      this.cli,
      ["--store", this.store, "--audit", this.auditLog, ...args],
      { input: stdin, encoding: "utf-8", timeout: 30_000, env }
    );
    if (res.error) throw new CLIUnavailable(`agentguard CLI failed to spawn: ${res.error}`);
    if (res.status !== 0 && res.status !== 2) {
      throw new AgentguardError(
        `agentguard CLI failed (status ${res.status}): ${res.stderr.trim() || res.stdout.trim()}`
      );
    }
    return res.stdout;
  }

  /**
   * Evaluate an authorization request against the PDP.
   *
   * @returns The decision. With `check: true`, throws
   * {@link StepUpRequired} or {@link AuthorizationDenied} instead of
   * returning a deny decision (unless `onStepUp` is `"return"`).
   */
  authorize(
    principal: Principal,
    action: AgentAction,
    resource: Resource,
    context: AgentContext = {},
    opts: { audit?: boolean; check?: boolean; onStepUp?: "raise" | "return" } = {}
  ): Decision {
    const req: Record<string, unknown> = {
      principal: {
        type: principal.type,
        uid: principal.uid,
        ...(principal.type === "agent" && "parent_uid" in principal
          ? { parent_uid: principal.parent_uid }
          : {}),
        attrs: principal.attrs ?? {},
      },
      action,
      resource: { ...resource, attrs: resource.attrs ?? {} },
      context: { args: context.args ?? {}, session: context.session ?? {} },
    };
    if (this.traceparent) {
      try {
        const tp = parseTraceparent(this.traceparent);
        req.trace = { trace_id: tp.traceId, span_id: tp.spanId, flags: tp.flags };
      } catch {
        // ignore malformed traceparent
      }
    }
    const stdin = JSON.stringify(req);
    const audit = opts.audit ?? true;
    const args = ["--output", "json", "authorize", "-"];
    if (!audit) args.push("--no-audit");
    const out = this.run(args, stdin);
    const data = JSON.parse(out);
    const stepUp = data.step_up
      ? { acr_values: data.step_up.acr_values, amr_values: data.step_up.amr_values }
      : undefined;
    const decision: Decision = {
      effect: data.effect,
      policies: data.policies ?? [],
      reasons: data.reasons ?? [],
      request: data.request ?? {},
      raw: data,
      trace_id: data.trace_id,
      span_id: data.span_id,
      tenant_id: data.tenant_id,
      step_up: stepUp,
    };
    if (opts.check && decision.effect === "deny") {
      if (stepUp && (opts.onStepUp ?? "raise") === "raise") {
        throw new StepUpRequired(stepUp, decision);
      }
      throw new AuthorizationDenied(decision);
    }
    return decision;
  }

  /** Like {@link Client.authorize} with `check: true`: throws on deny. */
  check(
    principal: Principal,
    action: AgentAction,
    resource: Resource,
    context: AgentContext = {}
  ): Decision {
    return this.authorize(principal, action, resource, context, { check: true });
  }

  /**
   * Mint a delegation token letting principal `to` act as `from` for the
   * listed actions and resources.
   *
   * @returns The path of the written token file.
   */
  delegate(
    from: string,
    to: string,
    actions: string[],
    resources: string[],
    ttlSeconds = 900,
    opts: { keyFile?: string; outFile?: string } = {}
  ): string {
    const args = [
      "delegate",
      "--from", from,
      "--to", to,
      "--actions", ...actions,
      "--resources", ...resources,
      "--ttl", String(ttlSeconds),
    ];
    if (opts.keyFile) args.push("--key-file", opts.keyFile);
    if (opts.outFile) args.push("--out", opts.outFile);
    return this.run(args).trim();
  }

  /** Verify a delegation token against a trusted keys file. */
  verify(token: string, keysFile: string): Record<string, unknown> {
    const out = this.run(["--output", "json", "verify", token, "--keys", keysFile]);
    return JSON.parse(out);
  }

  /** Read the most recent audit-log entries, newest last. */
  logTail(n = 20, filter?: { principal?: string; action?: string }): unknown[] {
    const args = ["log", "tail", "--n", String(n)];
    if (filter?.principal) args.push("--principal", filter.principal);
    if (filter?.action) args.push("--action", filter.action);
    const out = this.run(["--output", "json", ...args]);
    return JSON.parse(out);
  }
}

/** Shorthand constructors for {@link Principal} values. */
export const Principal = {
  user: (uid: string, attrs: Record<string, unknown> = {}): Principal => ({
    type: "user",
    uid,
    attrs,
  }),
  agent: (uid: string, attrs: Record<string, unknown> = {}): Principal => ({
    type: "agent",
    uid,
    attrs,
  }),
  subagent: (uid: string, parent: string, attrs: Record<string, unknown> = {}): Principal => ({
    type: "agent",
    uid,
    parent_uid: parent,
    attrs,
  }),
};

/** Shorthand constructors for {@link AgentAction} values. */
export const Action = {
  tool: (name: string): AgentAction => ({ tool: name }),
  toolOp: (name: string, op: string): AgentAction => ({ tool: name, operation: op }),
};