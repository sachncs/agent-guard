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

import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from "node:child_process";
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
  /** Default private signing-key file for delegation minting. */
  delegationKeyFile?: string;
  /** Maximum time allowed for an asynchronous CLI operation (defaults to 30 seconds). */
  timeoutMs?: number;
  /** Maximum concurrent asynchronous CLI children for this client (defaults to 8). */
  maxConcurrentCliProcesses?: number;
}

/** Options shared by synchronous and asynchronous authorization methods. */
export interface AuthorizationOptions {
  /** Skip writing the decision to the local audit log. Defaults to false. */
  audit?: boolean;
  /** Throw on deny; a step-up denial follows `onStepUp`. */
  check?: boolean;
  /** Raise `StepUpRequired` (default) or return the step-up denial decision. */
  onStepUp?: "raise" | "return";
}

const DEFAULT_CLI_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_CONCURRENT_CLI_PROCESSES = 8;
const MAX_CLI_OUTPUT_BYTES = 8 * 1024 * 1024;

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
  private delegationKeyFile?: string;
  private timeoutMs: number;
  private maxConcurrentCliProcesses: number;
  private activeAsyncProcesses = 0;

  constructor(opts: ClientOptions = {}) {
    this.store = opts.store ?? ".agentguard";
    this.auditLog = opts.auditLog ?? ".audit/decisions.jsonl";
    this.cli = findCli(opts.cliBin);
    this.bearerToken = opts.bearerToken;
    this.traceparent = opts.traceparent;
    this.delegationKeyFile = opts.delegationKeyFile;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_CLI_TIMEOUT_MS;
    if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 1) {
      throw new RangeError("timeoutMs must be a positive safe integer");
    }
    this.maxConcurrentCliProcesses = opts.maxConcurrentCliProcesses ??
      DEFAULT_MAX_CONCURRENT_CLI_PROCESSES;
    if (!Number.isSafeInteger(this.maxConcurrentCliProcesses) || this.maxConcurrentCliProcesses < 1) {
      throw new RangeError("maxConcurrentCliProcesses must be a positive safe integer");
    }
  }

  private commandEnv(): NodeJS.ProcessEnv {
    const env: NodeJS.ProcessEnv = { ...process.env };
    if (this.bearerToken) env.AGENTGUARD_BEARER = this.bearerToken;
    if (this.traceparent) env.AGENTGUARD_TRACEPARENT = this.traceparent;
    return env;
  }

  private run(args: string[], stdin?: string): string {
    const res = spawnSync(
      this.cli,
      ["--store", this.store, "--audit", this.auditLog, ...args],
      { input: stdin, encoding: "utf-8", timeout: 30_000, env: this.commandEnv() }
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
   * Run a CLI operation without blocking the Node.js event loop. Prefer these
   * variants in web servers and other concurrent Node applications.
   */
  private runAsync(args: string[], stdin?: string): Promise<string> {
    if (this.activeAsyncProcesses >= this.maxConcurrentCliProcesses) {
      return Promise.reject(new CLIUnavailable(
        `agentguard CLI concurrency limit reached (${this.maxConcurrentCliProcesses})`
      ));
    }
    this.activeAsyncProcesses += 1;
    return new Promise((resolve, reject) => {
      let child: ChildProcessWithoutNullStreams;
      try {
        child = spawn(
          this.cli,
          ["--store", this.store, "--audit", this.auditLog, ...args],
          { env: this.commandEnv(), stdio: "pipe" }
        );
      } catch (error) {
        this.activeAsyncProcesses -= 1;
        reject(new CLIUnavailable(`agentguard CLI failed to spawn: ${error}`));
        return;
      }

      const stdoutChunks: Buffer[] = [];
      const stderrChunks: Buffer[] = [];
      let outputBytes = 0;
      let settled = false;
      let timer: ReturnType<typeof setTimeout>;
      const finish = (action: () => void) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.activeAsyncProcesses -= 1;
        action();
      };
      timer = setTimeout(() => {
        child.kill("SIGKILL");
        finish(() => reject(new CLIUnavailable(
          `agentguard CLI timed out after ${this.timeoutMs} ms`
        )));
      }, this.timeoutMs);
      const collect = (chunk: Buffer, stream: "stdout" | "stderr") => {
        outputBytes += chunk.byteLength;
        if (outputBytes > MAX_CLI_OUTPUT_BYTES) {
          child.kill("SIGKILL");
          finish(() => reject(new AgentguardError(
            `agentguard CLI output exceeded ${MAX_CLI_OUTPUT_BYTES} bytes`
          )));
          return;
        }
        if (stream === "stdout") stdoutChunks.push(chunk);
        else stderrChunks.push(chunk);
      };
      child.stdout.on("data", (chunk: Buffer) => collect(chunk, "stdout"));
      child.stderr.on("data", (chunk: Buffer) => collect(chunk, "stderr"));
      // The child can exit (or close stdin) before the request has been
      // delivered. Writable EPIPE is otherwise an unhandled stream error and
      // can crash the host process. Fail closed: a response from a process
      // that did not receive its request is not an authorization result.
      child.stdin.once("error", (error) => finish(() => reject(
        new CLIUnavailable(`agentguard CLI failed to receive request: ${error.message}`)
      )));
      child.once("error", (error) => finish(() => reject(
        new CLIUnavailable(`agentguard CLI failed to spawn: ${error.message}`)
      )));
      child.once("close", (code, signal) => finish(() => {
        const stdout = Buffer.concat(stdoutChunks).toString("utf8");
        if (code === 0 || code === 2) {
          resolve(stdout);
        } else {
          const stderr = Buffer.concat(stderrChunks).toString("utf8");
          reject(new AgentguardError(
            `agentguard CLI failed (${signal ? `signal ${signal}` : `status ${code}`}): ` +
              (stderr.trim() || stdout.trim())
          ));
        }
      }));
      child.stdin.end(stdin);
    });
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
    opts: AuthorizationOptions = {},
  ): Decision {
    const out = this.run(
      this.authorizationArgs(opts),
      this.authorizationInput(principal, action, resource, context),
    );
    return this.finishAuthorization(this.parseDecision(out), opts);
  }

  /**
   * Evaluate an authorization request without blocking the Node.js event loop.
   * Use this method in web servers and other concurrent Node.js applications.
   *
   * @returns The decision. With `check: true`, throws
   * {@link StepUpRequired} or {@link AuthorizationDenied} instead of
   * returning a deny decision (unless `onStepUp` is `"return"`).
   */
  async authorizeAsync(
    principal: Principal,
    action: AgentAction,
    resource: Resource,
    context: AgentContext = {},
    opts: AuthorizationOptions = {},
  ): Promise<Decision> {
    const out = await this.runAsync(
      this.authorizationArgs(opts),
      this.authorizationInput(principal, action, resource, context),
    );
    return this.finishAuthorization(this.parseDecision(out), opts);
  }

  private authorizationInput(
    principal: Principal,
    action: AgentAction,
    resource: Resource,
    context: AgentContext,
  ): string {
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
    return JSON.stringify(req);
  }

  private authorizationArgs(opts: Pick<AuthorizationOptions, "audit">): string[] {
    const audit = opts.audit ?? true;
    const args = ["--output", "json", "authorize", "-"];
    if (!audit) args.push("--no-audit");
    return args;
  }

  private parseDecision(out: string): Decision {
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
    return decision;
  }

  private finishAuthorization(
    decision: Decision,
    opts: Pick<AuthorizationOptions, "check" | "onStepUp">,
  ): Decision {
    if (opts.check && decision.effect === "deny") {
      if (decision.step_up) {
        if ((opts.onStepUp ?? "raise") === "raise") {
          throw new StepUpRequired(decision.step_up, decision);
        }
        return decision;
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

  /** Like {@link Client.authorizeAsync} with `check: true`: throws on deny. */
  checkAsync(
    principal: Principal,
    action: AgentAction,
    resource: Resource,
    context: AgentContext = {},
  ): Promise<Decision> {
    return this.authorizeAsync(principal, action, resource, context, { check: true });
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
    const keyFile = opts.keyFile ?? this.delegationKeyFile;
    if (keyFile) args.push("--key-file", keyFile);
    if (opts.outFile) args.push("--out", opts.outFile);
    return this.run(args).trim();
  }

  /** Asynchronous, non-blocking version of {@link Client.delegate}. */
  async delegateAsync(
    from: string,
    to: string,
    actions: string[],
    resources: string[],
    ttlSeconds = 900,
    opts: { keyFile?: string; outFile?: string } = {}
  ): Promise<string> {
    const args = [
      "delegate",
      "--from", from,
      "--to", to,
      "--actions", ...actions,
      "--resources", ...resources,
      "--ttl", String(ttlSeconds),
    ];
    const keyFile = opts.keyFile ?? this.delegationKeyFile;
    if (keyFile) args.push("--key-file", keyFile);
    if (opts.outFile) args.push("--out", opts.outFile);
    return (await this.runAsync(args)).trim();
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

  /** Asynchronous, non-blocking version of {@link Client.logTail}. */
  async logTailAsync(
    n = 20,
    filter?: { principal?: string; action?: string }
  ): Promise<unknown[]> {
    const args = ["--output", "json", "log", "tail", "--n", String(n)];
    if (filter?.principal) args.push("--principal", filter.principal);
    if (filter?.action) args.push("--action", filter.action);
    return JSON.parse(await this.runAsync(args));
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
