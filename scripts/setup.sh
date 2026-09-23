#!/usr/bin/env bash
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

command -v rustup >/dev/null || { echo "rustup is required" >&2; exit 1; }
command -v cargo >/dev/null || { echo "cargo is required" >&2; exit 1; }
command -v node >/dev/null || { echo "Node.js 20.9+ is required" >&2; exit 1; }
node scripts/check-node-version.mjs || exit 1
if [[ -n "${PROTOC:-}" ]]; then
  [[ -x "$PROTOC" ]] || command -v "$PROTOC" >/dev/null || {
    echo "PROTOC must point to an executable" >&2
    exit 1
  }
elif ! command -v protoc >/dev/null; then
  echo "protoc is required for all-feature SPIFFE tests; install protobuf-compiler or set PROTOC" >&2
  exit 1
fi

rustup toolchain install 1.89.0 --profile minimal --component rustfmt --component clippy
pnpm_command=(pnpm)
if command -v corepack >/dev/null; then
  corepack prepare pnpm@11.22.0 --activate
elif ! command -v pnpm >/dev/null || [[ "$(pnpm --version)" != "11.22.0" ]]; then
  command -v npm >/dev/null || {
    echo "pnpm 11.22.0, Corepack, or npm is required" >&2
    exit 1
  }
  pnpm_command=(npm exec --yes --package=pnpm@11.22.0 -- pnpm)
fi
"${pnpm_command[@]}" --version | grep -Fxq "11.22.0" || {
  echo "failed to activate pinned pnpm 11.22.0" >&2
  exit 1
}
CI=true "${pnpm_command[@]}" install --frozen-lockfile

# The Astro workspace has its own lockfile and explicitly allowlists the
# esbuild/sharp install scripts it needs in site/pnpm-workspace.yaml.
(
  cd site
  CI=true "${pnpm_command[@]}" install --frozen-lockfile
)

echo "AgentGuard development environment is ready."
echo "Run: cargo test --workspace"
echo "Run: pnpm check:public"
echo "Run: pnpm --filter frontend test"
