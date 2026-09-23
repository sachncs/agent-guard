import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { validateOidcEndpoint } from "./endpoint_url.ts";

describe("OIDC endpoint transport validation", () => {
  it("requires HTTPS in production", () => {
    assert.equal(validateOidcEndpoint("https://idp.example", true), undefined);
    assert.match(validateOidcEndpoint("http://idp.example", true) ?? "", /HTTPS/);
  });

  it("permits only loopback HTTP outside production", () => {
    assert.equal(validateOidcEndpoint("http://127.0.0.1:3172", false), undefined);
    assert.equal(validateOidcEndpoint("http://[::1]:3172", false), undefined);
    assert.match(validateOidcEndpoint("http://idp.example", false) ?? "", /loopback/);
  });

  it("rejects malformed URLs and embedded credentials", () => {
    assert.match(validateOidcEndpoint("not a URL", true) ?? "", /absolute URL/);
    assert.match(validateOidcEndpoint("https://user:secret@idp.example", true) ?? "", /URL credentials/);
  });
});
