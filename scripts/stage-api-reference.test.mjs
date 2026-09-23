import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { requiredCrates, stageApiReference } from "./stage-api-reference.mjs";

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), "agentguard-api-reference-test-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

function createInputs(root, omit) {
  const rustdocSource = join(root, "rustdoc");
  const typescriptSource = join(root, "typescript");
  mkdirSync(typescriptSource, { recursive: true });
  for (const crate of requiredCrates) {
    mkdirSync(join(rustdocSource, crate), { recursive: true });
    writeFileSync(join(rustdocSource, crate, "index.html"), `<h1>${crate}</h1>`);
  }
  for (const declaration of ["index.d.ts", "trace.d.ts"]) {
    writeFileSync(join(typescriptSource, declaration), `export type ${declaration};`);
  }

  const files = {
    cliHelp: join(root, "agentguard-cli-help.txt"),
    serverHelp: join(root, "agentguard-server-help.txt"),
    protobufSource: join(root, "agentguard.proto"),
    protobufDescriptor: join(root, "agentguard.pb"),
  };
  for (const [key, path] of Object.entries(files)) {
    if (key !== omit) writeFileSync(path, `artifact:${key}`);
  }
  return {
    rustdocSource,
    typescriptSource,
    destination: join(root, "dist", "reference", "generated"),
    ...files,
  };
}

test("stages Rust, TypeScript, CLI, and protobuf reference artifacts", (t) => {
  const root = fixture(t);
  const inputs = createInputs(root);
  const result = stageApiReference(inputs);

  assert.equal(result, inputs.destination);
  assert.equal(readFileSync(join(result, "rustdoc", "agentguard_core", "index.html"), "utf8"), "<h1>agentguard_core</h1>");
  assert.equal(readFileSync(join(result, "typescript", "index.d.ts"), "utf8"), "export type index.d.ts;");
  assert.equal(readFileSync(join(result, "typescript", "trace.d.ts"), "utf8"), "export type trace.d.ts;");
  assert.equal(readFileSync(join(result, "cli", "agentguard-help.txt"), "utf8"), "artifact:cliHelp");
  assert.equal(readFileSync(join(result, "cli", "agentguard-server-help.txt"), "utf8"), "artifact:serverHelp");
  assert.equal(readFileSync(join(result, "protobuf", "agentguard.proto"), "utf8"), "artifact:protobufSource");
  assert.equal(readFileSync(join(result, "protobuf", "agentguard.pb"), "utf8"), "artifact:protobufDescriptor");
  const index = readFileSync(join(result, "index.html"), "utf8");
  for (const link of [
    "rustdoc/agentguard_core/index.html",
    "typescript/index.d.ts",
    "cli/agentguard-help.txt",
    "protobuf/agentguard.proto",
    "protobuf/agentguard.pb",
  ]) assert.ok(index.includes(link), `generated index should link ${link}`);
});

test("validates the complete artifact set before replacing the published reference", (t) => {
  const root = fixture(t);
  const inputs = createInputs(root, "protobufDescriptor");
  mkdirSync(inputs.destination, { recursive: true });
  writeFileSync(join(inputs.destination, "preserve.txt"), "previous reference remains intact");

  assert.throws(() => stageApiReference(inputs), /reference is incomplete.*protobuf descriptor/);
  assert.equal(readFileSync(join(inputs.destination, "preserve.txt"), "utf8"), "previous reference remains intact");
});
