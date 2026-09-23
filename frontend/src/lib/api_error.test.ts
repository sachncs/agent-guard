import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import { AgentguardError, CLIUnavailable } from "agentguard";
import {
  identityProviderUnavailableResponse,
  pdpUnavailableResponse,
  toApiErrorResponse,
} from "./api_error.ts";

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

  it("sanitizes PDP failures while preserving the service-unavailable contract", async () => {
    console.error = () => {};
    const response = pdpUnavailableResponse(
      new Error("PDP unreachable: private-host /internal/policies/secret.cedar")
    );
    const body = (await response.json()) as {
      error: string;
      kind: string;
      reference: string;
    };

    assert.equal(response.status, 503);
    assert.equal(body.kind, "pdp_unavailable");
    assert.equal(body.error, "The authorization service is temporarily unavailable.");
    assert.match(body.reference, /^[0-9a-f-]{36}$/);
    assert.doesNotMatch(JSON.stringify(body), /private-host|secret\.cedar/);
  });

  it("sanitizes identity-provider failures returned by the public login route", async () => {
    console.error = () => {};
    const response = identityProviderUnavailableResponse(
      new Error("issuer response exposed /private/tenant/client-secret")
    );
    const body = (await response.json()) as {
      error: string;
      kind: string;
      reference: string;
    };

    assert.equal(response.status, 502);
    assert.equal(body.kind, "idp_error");
    assert.equal(body.error, "The identity provider is temporarily unavailable. Try again shortly.");
    assert.match(body.reference, /^[0-9a-f-]{36}$/);
    assert.doesNotMatch(JSON.stringify(body), /private|client-secret/);
  });
});
