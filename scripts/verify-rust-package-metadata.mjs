#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { relative, sep } from "node:path";
import { pathToFileURL } from "node:url";

export function findRustPackageMetadataIssues(metadata) {
  const workspaceMembers = new Set(metadata.workspace_members ?? []);
  const packages = (metadata.packages ?? []).filter((pkg) => {
    if (!workspaceMembers.has(pkg.id)) return false;
    const manifest = relative(metadata.workspace_root, pkg.manifest_path).split(sep);
    return manifest[0] === "crates" || manifest[0] === "examples";
  });
  const issues = [];

  if (packages.length === 0) issues.push("Cargo workspace contains no crate/example packages");
  for (const pkg of packages) {
    if (!Array.isArray(pkg.authors) || pkg.authors.length === 0) {
      issues.push(`${pkg.name}: authors metadata is missing`);
    }
    if (typeof pkg.repository !== "string" || pkg.repository.length === 0) {
      issues.push(`${pkg.name}: repository metadata is missing`);
    }
    if (typeof pkg.rust_version !== "string" || pkg.rust_version.length === 0) {
      issues.push(`${pkg.name}: rust-version metadata is missing`);
    }
  }
  return issues;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const output = execFileSync(
    "cargo",
    ["metadata", "--locked", "--no-deps", "--format-version", "1"],
    { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] },
  );
  const issues = findRustPackageMetadataIssues(JSON.parse(output));
  if (issues.length > 0) {
    console.error(issues.join("\n"));
    process.exitCode = 1;
  } else {
    console.log("Rust workspace package metadata is complete");
  }
}
