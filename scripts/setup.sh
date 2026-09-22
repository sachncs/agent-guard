#!/usr/bin/env bash
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

command -v rustup >/dev/null || { echo "rustup is required" >&2; exit 1; }
command -v cargo >/dev/null || { echo "cargo is required" >&2; exit 1; }
command -v node >/dev/null || { echo "Node.js 20.9+ is required" >&2; exit 1; }
command -v corepack >/dev/null || { echo "corepack is required for pnpm" >&2; exit 1; }
command -v protoc >/dev/null || {
  echo "protoc is required; install protobuf-compiler or set PROTOC" >&2
  exit 1
}

rustup toolchain install 1.89.0 --profile minimal
corepack prepare pnpm@11.22.0 --activate
pnpm install --frozen-lockfile

# The Astro workspace has its own lockfile and explicitly needs native build
# approvals for sharp/esbuild in a clean checkout.
(
  cd site
  pnpm config set dangerouslyAllowAllBuilds true
  pnpm install --frozen-lockfile
)

echo "AgentGuard development environment is ready."
echo "Run: cargo test --workspace"
echo "Run: pnpm check:public"
echo "Run: pnpm --filter frontend test"
