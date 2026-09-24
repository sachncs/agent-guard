import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  AgentguardError,
  AuthorizationDenied,
  CLIUnavailable,
  Client,
  StepUpRequired,
} from "../index.js";
import { freshTraceContext, parseTraceparent } from "../trace.js";

const FAKE = `#!/bin/sh
case "\$FAKE_AGENTGUARD_MODE" in
  deny)
    cat >/dev/null
    echo '{"effect":"deny","policies":[],"reasons":["no matching policy"],"request":{}}' ;;
  stepup)
    cat >/dev/null
    echo '{"effect":"deny","policies":[],"reasons":[],"step_up":{"acr_values":"mfa","amr_values":"otp"},"request":{}}' ;;
  envdump)
    printf '{"effect":"allow","policies":["p-env"],"reasons":["bearer=%s trace=%s"],"request":{}}' "\$AGENTGUARD_BEARER" "\$AGENTGUARD_TRACEPARENT" ;;
  argsdump)
    printf '%s' "\$*" ;;
  asyncdelay)
    sleep 0.18
    case "\$*" in
      *"log tail"*) echo '[{"id":"async-1"}]' ;;
      *delegate*) echo 'fake.jwt.token' ;;
      *) echo '{}' ;;
    esac ;;
  asyncauthorize)
    read -r request
    sleep 0.18
    printf '{"effect":"allow","policies":["p-async"],"reasons":[],"request":%s}' "$request" ;;
  hang)
    exec sleep 5 ;;
  closestdin)
    exec 0<&-
    sleep 0.05
    echo '{"effect":"allow","policies":["p-ignored"],"reasons":[],"request":{}}' ;;
  fail)
    echo 'boom' >&2
    exit 3 ;;
  *)
    echo '{"effect":"allow","policies":["p1"],"reasons":["explicit permit"],"request":{"principal":{"uid":"alice"}},"trace_id":"tr-1"}' ;;
esac
`;

let fakeCli: string;

before(() => {
  const dir = mkdtempSync(join(tmpdir(), "agentguard-test-"));
  fakeCli = join(dir, "agentguard");
  writeFileSync(fakeCli, FAKE);
  chmodSync(fakeCli, 0o755);
});

describe("trace", () => {
  it("parses a valid traceparent", () => {
    const tp = parseTraceparent(
      "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    );
    assert.equal(tp.traceId, "4bf92f3577b34da6a3ce929d0e0e4736");
    assert.equal(tp.spanId, "00f067aa0ba902b7");
    assert.equal(tp.flags, 1);
  });

  it("rejects malformed traceparents", () => {
    for (const bad of [
      "",
      "00-xyz-00f067aa0ba902b7-01",
      "00-4bf92f3577b34da6a3ce929d0e0e4736-short-01",
      "99-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-zz",
    ]) {
      assert.throws(() => parseTraceparent(bad));
    }
  });

  it("generates contexts that round-trip", () => {
    const ctx = freshTraceContext();
    assert.match(ctx.traceId, /^[0-9a-f]{32}$/);
    assert.match(ctx.spanId, /^[0-9a-f]{16}$/);
    const parsed = parseTraceparent(`00-${ctx.traceId}-${ctx.spanId}-01`);
    assert.deepEqual(parsed, ctx);
  });
});

describe("Client", () => {
  it("returns allow decisions from authorize()", () => {
    const client = new Client({ cliBin: fakeCli });
    const d = client.authorize(
      { type: "user", uid: "alice" },
      { tool: "web_search" },
      { entity_type: "Document", uid: "doc-1" }
    );
    assert.equal(d.effect, "allow");
    assert.deepEqual(d.policies, ["p1"]);
    assert.equal(d.trace_id, "tr-1");
    assert.equal(
      (d.request as { principal?: { uid?: string } }).principal?.uid,
      "alice"
    );
  });

  it("check() raises AuthorizationDenied on deny", () => {
    process.env.FAKE_AGENTGUARD_MODE = "deny";
    try {
      const client = new Client({ cliBin: fakeCli });
      assert.throws(
        () =>
          client.check(
            { type: "user", uid: "alice" },
            { tool: "send_email" },
            { entity_type: "Resource", uid: "agent" }
          ),
        (e: unknown) => {
          assert.ok(e instanceof AuthorizationDenied);
          assert.ok(e.message.includes("no matching policy"));
          assert.equal(e.decision.effect, "deny");
          return true;
        }
      );
    } finally {
      delete process.env.FAKE_AGENTGUARD_MODE;
    }
  });

  it("check() raises StepUpRequired when the CLI demands step-up", () => {
    process.env.FAKE_AGENTGUARD_MODE = "stepup";
    try {
      const client = new Client({ cliBin: fakeCli });
      assert.throws(
        () =>
          client.check(
            { type: "user", uid: "alice" },
            { tool: "send_email" },
            { entity_type: "Resource", uid: "agent" }
          ),
        (e: unknown) => {
          assert.ok(e instanceof StepUpRequired);
          assert.equal(e.stepUp.acr_values, "mfa");
          assert.equal(e.stepUp.amr_values, "otp");
          return true;
        }
      );
      const decision = client.authorize(
        { type: "user", uid: "alice" },
        { tool: "send_email" },
        { entity_type: "Resource", uid: "agent" },
        {},
        { check: true, onStepUp: "return" },
      );
      assert.equal(decision.effect, "deny");
      assert.equal(decision.step_up?.acr_values, "mfa");
    } finally {
      delete process.env.FAKE_AGENTGUARD_MODE;
    }
  });

  it("maps nonzero CLI exit codes to AgentguardError", () => {
    process.env.FAKE_AGENTGUARD_MODE = "fail";
    try {
      const client = new Client({ cliBin: fakeCli });
      assert.throws(
        () =>
          client.authorize(
            { type: "user", uid: "alice" },
            { tool: "web_search" },
            { entity_type: "Resource", uid: "agent" }
          ),
        (e: unknown) => {
          assert.ok(e instanceof AgentguardError);
          assert.ok(!(e instanceof CLIUnavailable));
          assert.ok(e.message.includes("boom"));
          return true;
        }
      );
    } finally {
      delete process.env.FAKE_AGENTGUARD_MODE;
    }
  });

  it("raises CLIUnavailable when the configured binary cannot spawn", () => {
    const dir = mkdtempSync(join(tmpdir(), "agentguard-test-"));
    const notExecutable = join(dir, "not-agentguard");
    writeFileSync(notExecutable, "", { mode: 0o644 });
    const client = new Client({ cliBin: notExecutable }); // path exists -> accepted
    assert.throws(
      () =>
        client.authorize(
          { type: "user", uid: "alice" },
          { tool: "web_search" },
          { entity_type: "Resource", uid: "agent" }
        ),
      (e: unknown) => e instanceof CLIUnavailable
    );
  });

  it("propagates bearer token and traceparent through the environment", () => {
    process.env.FAKE_AGENTGUARD_MODE = "envdump";
    try {
      const ctx = freshTraceContext();
      const tp = `00-${ctx.traceId}-${ctx.spanId}-01`;
      const client = new Client({
        cliBin: fakeCli,
        bearerToken: "secret-token",
        traceparent: tp,
      });
      const d = client.authorize(
        { type: "user", uid: "alice" },
        { tool: "web_search" },
        { entity_type: "Resource", uid: "agent" }
      );
      assert.deepEqual(d.reasons, [
        `bearer=secret-token trace=${tp}`,
      ]);
    } finally {
      delete process.env.FAKE_AGENTGUARD_MODE;
    }
  });

  it("uses the configured delegation key file by default", () => {
    process.env.FAKE_AGENTGUARD_MODE = "argsdump";
    try {
      const client = new Client({
        cliBin: fakeCli,
        delegationKeyFile: "/run/secrets/delegation.key",
      });
      const args = client.delegate(
        'Agent::"research"',
        'Agent::"summarizer"',
        ["ToolCall::repo_read"],
        ["Repository::demo"],
        300
      );
      assert.match(args, /delegate.*--key-file \/run\/secrets\/delegation\.key/);
    } finally {
      delete process.env.FAKE_AGENTGUARD_MODE;
    }
  });

  it("runs async log requests without blocking the event loop", async () => {
    process.env.FAKE_AGENTGUARD_MODE = "asyncdelay";
    const client = new Client({ cliBin: fakeCli, timeoutMs: 2_000 });
    let ticks = 0;
    const interval = setInterval(() => ticks += 1, 30);
    try {
      const records = await client.logTailAsync(5);
      assert.deepEqual(records, [{ id: "async-1" }]);
      assert.ok(ticks >= 3, `event loop should continue ticking during CLI work (ticks=${ticks})`);
    } finally {
      clearInterval(interval);
      delete process.env.FAKE_AGENTGUARD_MODE;
    }
  });

  it("authorizes asynchronously, forwards the request, and keeps the event loop responsive", async () => {
    process.env.FAKE_AGENTGUARD_MODE = "asyncauthorize";
    const client = new Client({ cliBin: fakeCli, timeoutMs: 2_000 });
    let ticks = 0;
    const interval = setInterval(() => ticks += 1, 30);
    try {
      const decision = await client.authorizeAsync(
        { type: "agent", uid: "alice", attrs: { team: "security" } },
        { tool: "repo_read" },
        { entity_type: "Repository", uid: "demo" },
        { args: { repo: "demo" }, session: { mfa: true } },
        { audit: false },
      );
      assert.equal(decision.effect, "allow");
      assert.equal(decision.policies[0], "p-async");
      assert.deepEqual(decision.request, {
        principal: { type: "agent", uid: "alice", attrs: { team: "security" } },
        action: { tool: "repo_read" },
        resource: { entity_type: "Repository", uid: "demo", attrs: {} },
        context: { args: { repo: "demo" }, session: { mfa: true } },
      });
      assert.ok(ticks >= 3, `event loop should continue ticking during authorization (ticks=${ticks})`);
    } finally {
      clearInterval(interval);
      delete process.env.FAKE_AGENTGUARD_MODE;
    }
  });

  it("applies checkAsync deny and step-up behavior consistently", async () => {
    const client = new Client({ cliBin: fakeCli });
    const input = [
      { type: "user", uid: "alice" } as const,
      { tool: "repo_read" },
      { entity_type: "Repository", uid: "demo" },
    ] as const;
    process.env.FAKE_AGENTGUARD_MODE = "deny";
    try {
      await assert.rejects(client.checkAsync(...input), AuthorizationDenied);
    } finally {
      delete process.env.FAKE_AGENTGUARD_MODE;
    }

    process.env.FAKE_AGENTGUARD_MODE = "stepup";
    try {
      await assert.rejects(client.checkAsync(...input), StepUpRequired);
      const decision = await client.authorizeAsync(
        ...input,
        {},
        { check: true, onStepUp: "return" },
      );
      assert.equal(decision.effect, "deny");
      assert.equal(decision.step_up?.acr_values, "mfa");
    } finally {
      delete process.env.FAKE_AGENTGUARD_MODE;
    }
  });

  it("supports asynchronous delegation with a configured signing key", async () => {
    process.env.FAKE_AGENTGUARD_MODE = "asyncdelay";
    try {
      const client = new Client({ cliBin: fakeCli, delegationKeyFile: "/run/secrets/delegation.key" });
      assert.equal(
        await client.delegateAsync(
          'Agent::"research"',
          'Agent::"summarizer"',
          ["ToolCall::repo_read"],
          ["Repository::demo"],
          300,
        ),
        "fake.jwt.token",
      );
    } finally {
      delete process.env.FAKE_AGENTGUARD_MODE;
    }
  });

  it("terminates an asynchronous CLI that exceeds its timeout", async () => {
    process.env.FAKE_AGENTGUARD_MODE = "hang";
    try {
      const client = new Client({ cliBin: fakeCli, timeoutMs: 25 });
      await assert.rejects(client.logTailAsync(), (error: unknown) => {
        assert.ok(error instanceof CLIUnavailable);
        assert.match(error.message, /timed out after 25 ms/);
        return true;
      });
    } finally {
      delete process.env.FAKE_AGENTGUARD_MODE;
    }
  });

  it("fails closed when the CLI closes stdin before receiving the request", async () => {
    process.env.FAKE_AGENTGUARD_MODE = "closestdin";
    try {
      const client = new Client({ cliBin: fakeCli });
      await assert.rejects(
        client.authorizeAsync(
          { type: "user", uid: "alice" },
          { tool: "repo_read" },
          { entity_type: "Repository", uid: "demo" },
          { args: { payload: "x".repeat(1024 * 1024) } },
        ),
        (error: unknown) => {
          assert.ok(error instanceof CLIUnavailable);
          assert.match(error.message, /failed to receive request/);
          return true;
        },
      );
    } finally {
      delete process.env.FAKE_AGENTGUARD_MODE;
    }
  });

  it("bounds concurrent asynchronous CLI processes", async () => {
    process.env.FAKE_AGENTGUARD_MODE = "asyncdelay";
    try {
      const client = new Client({ cliBin: fakeCli, maxConcurrentCliProcesses: 1 });
      const first = client.logTailAsync();
      await assert.rejects(client.logTailAsync(), (error: unknown) => {
        assert.ok(error instanceof CLIUnavailable);
        assert.match(error.message, /concurrency limit reached/);
        return true;
      });
      assert.deepEqual(await first, [{ id: "async-1" }]);
      assert.deepEqual(await client.logTailAsync(), [{ id: "async-1" }]);
    } finally {
      delete process.env.FAKE_AGENTGUARD_MODE;
    }
  });

  it("rejects invalid asynchronous CLI timeouts", () => {
    assert.throws(() => new Client({ cliBin: fakeCli, timeoutMs: 0 }), RangeError);
    assert.throws(() => new Client({ cliBin: fakeCli, timeoutMs: Number.POSITIVE_INFINITY }), RangeError);
    assert.throws(() => new Client({ cliBin: fakeCli, maxConcurrentCliProcesses: 0 }), RangeError);
  });
});
