# agentguard console

Admin console for [agentguard](../README.md) — Cedar-powered authorization
for AI agents. Built with **Next.js 16**, **React 19**, **Tailwind CSS v4**
and **shadcn/ui**; talks to the `agentguard` TypeScript SDK (workspace
package) server-side only.

## Pages

| Route | What it does |
|---|---|
| `/` | **Dashboard** — hash-chained audit log tail with principal/action filters, allow/deny stats, auto-refresh |
| `/simulator` | **Policy Simulator** — submit a principal/action/resource/context request and inspect the Allow/Deny decision, matched policies, reasons and step-up hints |
| `/delegation` | **Delegation** — issue scoped JWS delegation tokens (RFC 8693) and verify existing ones |

## Prerequisites

1. The `agentguard` CLI on your `PATH` (`~/.cargo/bin/agentguard` is
   auto-detected):

   ```bash
   cargo install --path crates/agentguard-cli
   ```

2. An initialized store at the repo root:

   ```bash
   agentguard init --name acme
   ```

## Run

From the repository root:

```bash
pnpm install
pnpm --filter frontend dev
```

Open <http://localhost:3000>.

> The SDK spawns the CLI binary per request and reads `.agentguard/`
> relative to the working directory — start the dev server from the repo
> root unless you override the paths below.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `AGENTGUARD_STORE` | `.agentguard` | Cedar schema + policy directory |
| `AGENTGUARD_AUDIT` | `.audit/decisions.jsonl` | Audit log destination |
| `AGENTGUARD_BEARER` | *(unset)* | Bearer token when talking to an AuthZEN PDP |

## Architecture note

The TypeScript SDK wraps the Rust CLI via `child_process`, so it can never
run in the browser: every page is a client component that calls route
handlers under `src/app/api/*`, which own the single server-side
`Client` instance.
