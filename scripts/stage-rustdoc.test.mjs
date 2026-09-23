import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { requiredCrates, stageRustdoc } from "./stage-rustdoc.mjs";

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), "agentguard-rustdoc-test-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

test("stages the complete generated crate API tree", (t) => {
  const root = fixture(t);
  const source = join(root, "doc");
  const destination = join(root, "dist", "reference", "rustdoc");

  for (const crate of requiredCrates) {
    const directory = join(source, crate);
    mkdirSync(directory, { recursive: true });
    writeFileSync(join(directory, "index.html"), `<h1>${crate}</h1>`);
  }
  mkdirSync(join(source, "static.files"));
  writeFileSync(join(source, "static.files", "main.css"), "body {}");

  assert.equal(stageRustdoc(source, destination), destination);
  assert.equal(readFileSync(join(destination, "agentguard_core", "index.html"), "utf8"), "<h1>agentguard_core</h1>");
  assert.equal(readFileSync(join(destination, "static.files", "main.css"), "utf8"), "body {}");
});

test("refuses incomplete input before replacing an existing reference", (t) => {
  const root = fixture(t);
  const source = join(root, "incomplete-doc");
  const destination = join(root, "dist", "reference", "rustdoc");
  mkdirSync(join(source, "agentguard_core"), { recursive: true });
  writeFileSync(join(source, "agentguard_core", "index.html"), "partial");
  mkdirSync(destination, { recursive: true });
  writeFileSync(join(destination, "preserve.txt"), "previous complete reference");

  assert.throws(() => stageRustdoc(source, destination), /reference is incomplete/);
  assert.equal(readFileSync(join(destination, "preserve.txt"), "utf8"), "previous complete reference");
});
