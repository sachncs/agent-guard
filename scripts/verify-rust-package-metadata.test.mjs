import assert from "node:assert/strict";
import test from "node:test";
import { findRustPackageMetadataIssues } from "./verify-rust-package-metadata.mjs";

const workspaceRoot = "/repo";
const packageMetadata = {
  id: "agentguard-core 0.2.0 (path+file:///repo/crates/agentguard-core)",
  name: "agentguard-core",
  manifest_path: `${workspaceRoot}/crates/agentguard-core/Cargo.toml`,
  authors: ["AgentGuard maintainers"],
  repository: "https://github.com/sachncs/agent-guard",
  rust_version: "1.89",
};

test("accepts complete OSS metadata on workspace crates", () => {
  assert.deepEqual(
    findRustPackageMetadataIssues({
      workspace_root: workspaceRoot,
      workspace_members: [packageMetadata.id],
      packages: [packageMetadata],
    }),
    [],
  );
});

test("rejects missing package identity and compatibility metadata", () => {
  assert.deepEqual(
    findRustPackageMetadataIssues({
      workspace_root: workspaceRoot,
      workspace_members: [packageMetadata.id],
      packages: [{ ...packageMetadata, authors: [], repository: null, rust_version: null }],
    }),
    [
      "agentguard-core: authors metadata is missing",
      "agentguard-core: repository metadata is missing",
      "agentguard-core: rust-version metadata is missing",
    ],
  );
});

test("ignores packages outside the workspace", () => {
  assert.deepEqual(
    findRustPackageMetadataIssues({
      workspace_root: workspaceRoot,
      workspace_members: [],
      packages: [{ ...packageMetadata, authors: [], repository: null, rust_version: null }],
    }),
    ["Cargo workspace contains no crate/example packages"],
  );
});
