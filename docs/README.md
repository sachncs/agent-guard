# AgentGuard documentation

The canonical, browsable user journey is the [AgentGuard documentation site](https://sachncs.github.io/agent-guard/).
This directory contains the versioned operational guides that ship with the
repository and are reviewed with the implementation.

## Start here

1. [Getting started](getting-started.md) — install the CLI, create a policy,
   evaluate an allow/deny pair, and verify the audit record.
2. [Architecture](architecture.md) — understand the clean boundaries between
   adapters, the PDP, the Cedar engine, identity, and evidence.
3. [Policy authoring](policy-authoring.md) — write, validate, simulate, review,
   reload, and roll back policy bundles.
4. [Production deployment](production.md) — the supported Docker-on-Kubernetes
   topology and its explicit operating contract.

## Operate the supported topology

- [Kubernetes operations](kubernetes.md)
- [Console deployment](console.md)
- [Backups and retention](backups.md)
- [Upgrades and rollback](upgrades.md)
- [Incident response](incident-response.md)
- [Troubleshooting](troubleshooting.md)
- [Operations runbook](operations/runbook.md)

## Integrate and reference

- [HTTP, SDK, CLI, and Rust surfaces](reference.md)
- [Configuration](../README.md#configuration)
- [Identity and delegation](identity.md)
- [Compatibility and deprecation policy](compatibility.md)

## Project and OSS policy

- [OSS governance](oss-governance.md)
- [Brand system](branding.md)
- [Release checklist](../RELEASE.md)
- [Security response](../SECURITY.md)
- [Support policy](../SUPPORT.md)

Public claims must map to shipped behavior, tests, or an explicit operator
responsibility. If a guide and the implementation disagree, open an issue with
the exact command, version, and observed behavior; do not silently rely on a
stale example.
