import { cpSync, mkdirSync, rmSync, statSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const requiredCrates = ["agentguard_core", "agentguard_server", "agentguard", "agentguard_auth", "agentguard_policy", "agentguard_telemetry"];

export function stageRustdoc(sourcePath, destinationPath) {
  const source = resolve(sourcePath);
  const destination = resolve(destinationPath);

  for (const crate of requiredCrates) {
    const entry = resolve(source, crate, "index.html");
    if (!statSync(entry, { throwIfNoEntry: false })?.isFile()) {
      throw new Error(`generated Rust API reference is incomplete: missing ${entry}`);
    }
  }

  rmSync(destination, { recursive: true, force: true });
  mkdirSync(dirname(destination), { recursive: true });
  cpSync(source, destination, { recursive: true, dereference: true });
  return destination;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  // Keep the destructive replacement scoped to this generated build output;
  // callers cannot redirect it to an arbitrary filesystem path.
  const destination = stageRustdoc("target/doc", "site/dist/reference/rustdoc");
  console.log(`staged Rust API reference (${requiredCrates.length} crates) at ${destination}`);
}
