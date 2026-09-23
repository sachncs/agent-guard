import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import { AgentguardError, CLIUnavailable } from "agentguard";
import { toApiErrorResponse } from "./api_error.ts";

const originalConsoleError = console.error;

afterEach(() => {
  console.error = originalConsoleError;
});

describe("toApiErrorResponse", () => {
  it("does not return CLI stderr or filesystem paths to the caller", async () => {
    const internal = new AgentguardError("failed to read /etc/agentguard/private-keys.json: secret-value");
    const logged: unknown[][] = [];
    console.error = (...args: unknown[]) => logged.push(args);

    const response = toApiErrorResponse(internal);
    const body = (await response.json()) as { error: string; kind: string; reference: string };

    assert.equal(response.status, 422);
    assert.equal(body.kind, "cli_error");
    assert.equal(body.error, "AgentGuard could not complete this operation.");
    assert.doesNotMatch(JSON.stringify(body), /private-keys|secret-value/);
    assert.match(body.reference, /^[0-9a-f-]{36}$/);
    assert.equal(logged.length, 1);
    assert.equal(logged[0]?.[1] && typeof logged[0][1], "object");
  });

  it("maps unavailable, malformed JSON, and unknown errors to safe messages", async () => {
    console.error = () => {};
    const errors: Array<[unknown, number, string]> = [
      [new CLIUnavailable("spawn failed at /private/path"), 503, "cli_unavailable"],
      [new SyntaxError("unexpected input: credential"), 400, "invalid_request"],
      [new Error("secret credential in dependency response"), 500, "unknown"],
    ];

    for (const [error, expectedStatus, expectedKind] of errors) {
      const response = toApiErrorResponse(error);
      const body = (await response.json()) as { error: string; kind: string };
      assert.equal(response.status, expectedStatus);
      assert.equal(body.kind, expectedKind);
      assert.doesNotMatch(body.error, /private|credential|dependency/);
    }
  });
});
