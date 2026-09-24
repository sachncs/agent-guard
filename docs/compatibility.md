# Compatibility policy

## Current support matrix

| Surface | Supported baseline |
| --- | --- |
| Rust libraries, CLI, and server | Rust 1.89 MSRV; CI tests 1.89.0. Stable Rust is recommended for deployments. |
| Full repository install/build and documentation site | Node.js 22.12 or newer; CI uses Node 22.19.0. Astro 7 requires Node 22.12+. |
| TypeScript SDK and console | Node.js 20.9 or newer, as declared by their package engines. |
| JavaScript package manager | pnpm 11.22.x; use the version pinned by the root `packageManager` field. |
| Container runtime | Docker-compatible OCI runtime. CI builds the release images from the checked-in Dockerfiles. |
| Kubernetes | Supported reference manifests target Kubernetes 1.28 or newer; the CI smoke cluster uses Kind with Kubernetes 1.31.4. Review cluster-specific admission and storage behavior before rollout. |
| Kubernetes packaging | Kustomize v5-compatible base plus a production overlay template. Operators must supply registry names/digests and environment-specific network/ingress policy before deployment. |
| Production topology | One PDP replica and one console replica. Console sessions and rate limits require a shared Redis-compatible store. Audit storage is operator-provided persistent storage. |
| License | Apache-2.0 |
| Distribution | Rust crates are source-distributed and are not published to crates.io. Semantic-version releases publish `linux/amd64` PDP and console images to GHCR; verify registry visibility before release announcement. |

The matrix is intentionally narrower than the set of platforms that may happen
to work. CI coverage is not a promise that every operating system, architecture,
Kubernetes distribution, proxy, identity provider, or Redis service has been
tested. The release gate currently exercises the documented Rust toolchain,
Node/pnpm versions, container build, frontend flows, and a disposable Kind
cluster. Validate any materially different environment before relying on it.

### Deployment boundaries

- The documented production deployment is Docker images on Kubernetes, with
  TLS terminated by a trusted ingress or service mesh. Do not expose the PDP's
  plaintext listener directly to an untrusted network.
- The checked-in Kustomize base contains sample image tags and policy material.
  Start from `deploy/overlays/production/kustomization.yaml.example` and
  build an operator-owned overlay with immutable image digests, reviewed
  policies, secret references, ingress/network controls, and storage settings.
- The supplied audit volume and append path are single-writer. Do not scale
  the PDP horizontally against one shared audit file. A coordinated,
  distributed audit backend is not part of the supported contract.
- Embedded Rust and CLI-backed SDK integrations are supported library/client
  use cases, but they do not inherit the standalone server's file watcher,
  readiness endpoint, or automatic audit behavior. The embedding application
  owns configuration, lifecycle, enforcement, and evidence durability.
- The gRPC interface is repository-defined and plaintext by default. Use it
  only on a protected network or provide transport security in the embedding
  environment; it is not a standardized AuthZEN gRPC protocol.

See [production deployment](production.md), [Kubernetes operations](kubernetes.md),
and the [security model](security.md) for the operator responsibilities and
failure behavior behind these boundaries.

The HTTP interface follows the repository's AuthZEN request model. The gRPC
interface is repository-defined and is not presented as a standardized AuthZEN
gRPC protocol.

## Versioning

AgentGuard is pre-1.0. Until a v1.0 stability contract is published, minor
releases may contain breaking changes to Rust APIs, CLI behavior, configuration,
HTTP request/response details, and TypeScript SDK APIs. Do not infer a
compatibility guarantee from a matching major version of `0.x` packages. Pin
the exact release in production and review the changelog and migration notes
before upgrading.

For every intentional breaking change, maintainers should publish the affected
surface, migration steps, and a changelog entry in the same change. Where
practical, provide a deprecation warning or a transition release; security,
correctness, and data-integrity fixes may require a direct change. Generated
references describe the checked-out revision and can change independently of
the latest published package.

After 1.0, the project intends to use Semantic Versioning for released crates,
the TypeScript SDK, CLI contracts, configuration keys, and documented HTTP
contracts. A breaking change to one of those stable surfaces requires a major
release and migration guidance. Experimental or explicitly unstable surfaces
will be labeled as such in their API documentation rather than silently
treated as stable.

## Deprecations and support lifecycle

- Deprecations must identify the replacement and the release in which removal
  is planned. Before 1.0, the transition period is best-effort; after 1.0,
  maintainers will normally keep a deprecated surface for at least one minor
  release and document its removal in the next major release.
- Only the latest published release receives security fixes. Maintainers do
  not promise backports to older releases; operators should upgrade promptly
  after reviewing the migration notes.
- There is no enterprise support SLA. Maintainer availability is best-effort;
  see [support policy](../SUPPORT.md) and [security reporting](../SECURITY.md).
- Report compatibility regressions with the exact AgentGuard version, runtime,
  deployment mode, configuration (with secrets removed), and a minimal
  reproduction. Do not include credentials or sensitive policy data in public
  issues.
