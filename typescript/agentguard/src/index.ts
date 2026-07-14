/**
 * agentguard — Cedar-powered authorization for AI agents (TypeScript SDK).
 *
 * Wraps the `agentguard` CLI binary. Mirrors the Python SDK surface.
 */

export type Principal =
  | { type: "user"; uid: string; attrs?: Record<string, unknown> }
  | { type: "agent"; uid: string; parent_uid?: string; attrs?: Record<string, unknown> };

export interface AgentAction {
  tool: string;
  operation?: string;
}

export interface Resource {
  entity_type: string;
  uid: string;
  attrs?: Record<string, unknown>;
}

export interface AgentContext {
  args?: Record<string, unknown>;
  session?: Record<string, unknown>;
}

export interface Decision {
  effect: "allow" | "deny";
  policies: string[];
  reasons: string[];
  request: Record<string, unknown>;
  raw: Record<string, unknown>;
}

export class AgentguardError extends Error {}
export class AuthorizationDenied extends AgentguardError {
  constructor(public decision: Decision) {
    super(`authorization denied: ${decision.reasons.join("; ") || "no matching policy"}`);
  }
}
export class CLIUnavailable extends AgentguardError {}

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

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

export interface ClientOptions {
  store?: string;
  auditLog?: string;
  cliBin?: string;
}

export class Client {
  private store: string;
  private auditLog: string;
  private cli: string;

  constructor(opts: ClientOptions = {}) {
    this.store = opts.store ?? ".agentguard";
    this.auditLog = opts.auditLog ?? ".audit/decisions.jsonl";
    this.cli = findCli(opts.cliBin);
  }

  private run(args: string[], stdin?: string): string {
    const res = spawnSync(
      this.cli,
      ["--store", this.store, "--audit", this.auditLog, ...args],
      { input: stdin, encoding: "utf-8", timeout: 30_000 }
    );
    if (res.error) throw new CLIUnavailable(`agentguard CLI failed to spawn: ${res.error}`);
    if (res.status !== 0 && res.status !== 2) {
      throw new AgentguardError(
        `agentguard CLI failed (status ${res.status}): ${res.stderr.trim() || res.stdout.trim()}`
      );
    }
    return res.stdout;
  }

  authorize(
    principal: Principal,
    action: AgentAction,
    resource: Resource,
    context: AgentContext = {},
    opts: { audit?: boolean; check?: boolean } = {}
  ): Decision {
    const req = {
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
    const stdin = JSON.stringify(req);
    const audit = opts.audit ?? true;
    const args = ["--output", "json", "authorize", "-"];
    if (!audit) args.push("--no-audit");
    const out = this.run(args, stdin);
    const data = JSON.parse(out);
    const decision: Decision = {
      effect: data.effect,
      policies: data.policies ?? [],
      reasons: data.reasons ?? [],
      request: data.request ?? {},
      raw: data,
    };
    if (opts.check && decision.effect === "deny") throw new AuthorizationDenied(decision);
    return decision;
  }

  check(
    principal: Principal,
    action: AgentAction,
    resource: Resource,
    context: AgentContext = {}
  ): Decision {
    return this.authorize(principal, action, resource, context, { check: true });
  }

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

  verify(token: string, keysFile: string): Record<string, unknown> {
    const out = this.run(["--output", "json", "verify", token, "--keys", keysFile]);
    return JSON.parse(out);
  }

  logTail(n = 20, filter?: { principal?: string; action?: string }): unknown[] {
    const args = ["log", "tail", "--n", String(n)];
    if (filter?.principal) args.push("--principal", filter.principal);
    if (filter?.action) args.push("--action", filter.action);
    const out = this.run(["--output", "json", ...args]);
    return JSON.parse(out);
  }
}

// Convenience constructors
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

export const Action = {
  tool: (name: string): AgentAction => ({ tool: name }),
  toolOp: (name: string, op: string): AgentAction => ({ tool: name, operation: op }),
};