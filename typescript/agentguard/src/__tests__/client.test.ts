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
    echo '{"effect":"deny","policies":[],"reasons":["no matching policy"],"request":{}}' ;;
  stepup)
    echo '{"effect":"deny","policies":[],"reasons":[],"step_up":{"acr_values":"mfa","amr_values":"otp"},"request":{}}' ;;
  envdump)
    printf '{"effect":"allow","policies":["p-env"],"reasons":["bearer=%s trace=%s"],"request":{}}' "\$AGENTGUARD_BEARER" "\$AGENTGUARD_TRACEPARENT" ;;
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
});
