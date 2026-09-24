# Release checklist

- [ ] Update workspace, crate, SDK, console, and site versions together.
- [ ] Run Rust format, clippy, tests, doctests, and build.
- [ ] Run `cargo deny check` and `pnpm audit:dependencies` against the release lockfiles.
- [ ] Run TypeScript install, lint, typecheck, tests, frontend build, and e2e.
- [ ] Run Astro check and site build.
- [ ] Verify README and docs links and inspect public branding assets.
- [ ] Build both Docker images and run health/readiness smoke tests.
- [ ] Apply the Kubernetes manifests in a disposable cluster and verify an
      allow, deny, audit append, graceful shutdown, and rollback.
- [ ] Run `./scripts/k8s-smoke.sh` (or confirm the CI `Kubernetes PDP smoke`
      job) against the release source. The release workflow builds, publishes,
      and records `linux/amd64` image digests after this gate passes; verify
      both GHCR packages are public and pin those digests before promotion.
- [ ] Run `pnpm check && pnpm build` from the repository root so the SDK,
      console, examples, and canonical documentation site are checked together.
- [ ] Review SECURITY.md, CHANGELOG.md, compatibility policy, and migration
      notes.
- [ ] Tag the release and publish release notes only after all checks pass.

## Automated path

Push a semantic-version tag such as `v0.3.0` after the checklist is reviewed.
The `release.yml` workflow validates the tag, tests that exact revision, builds
and publishes both `linux/amd64` images to GHCR, then attaches the registry
digests to the GitHub release. SemVer build metadata `+` is mapped to `_` in
Docker tags. Verify both packages are public before announcement so anonymous
cluster pulls work. New releases are assembled as drafts with the digest asset
before publication. An interrupted draft can be resumed; rerunning a complete
release is a no-op, and an incomplete already-published release is rejected
rather than rebuilding and replacing version tags. A manual dispatch can
publish only an existing tested tag; it does not test the dispatch branch as a
substitute. Pin the attached digests in the production overlay. Operators
using another registry can follow
[Kubernetes operations](docs/kubernetes.md#build-and-publish). Never deploy
mutable `latest` tags.
