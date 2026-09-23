# Release checklist

- [ ] Update workspace, crate, SDK, console, and site versions together.
- [ ] Run Rust format, clippy, tests, doctests, build, and dependency audits.
- [ ] Run TypeScript install, lint, typecheck, tests, frontend build, and e2e.
- [ ] Run Astro check and site build.
- [ ] Verify README and docs links and inspect public branding assets.
- [ ] Build both Docker images and run health/readiness smoke tests.
- [ ] Apply the Kubernetes manifests in a disposable cluster and verify an
      allow, deny, audit append, graceful shutdown, and rollback.
- [ ] Run `./scripts/k8s-smoke.sh` (or confirm the CI `Kubernetes PDP smoke`
      job) against the exact release image artifacts; record published digests
      and ensure the production overlay pins those digests before promotion.
- [ ] Run `pnpm check && pnpm build` from the repository root so the SDK,
      console, examples, and canonical documentation site are checked together.
- [ ] Review SECURITY.md, CHANGELOG.md, compatibility policy, and migration
      notes.
- [ ] Tag the release and publish release notes only after all checks pass.

## Automated path

Push a semantic-version tag such as `v0.3.0` after the checklist is reviewed.
The `release.yml` workflow validates that the tag exists before starting the
release gate, checks out that exact tag in every CI job, and publishes the same
tag only after the gate succeeds. A manual dispatch can validate and publish an
existing tag by supplying its exact value; the workflow does not test the
dispatch branch as a substitute. CI builds and scans the Docker images as test
artifacts but does not publish container images to a registry. Build and push
both release images to the operator-selected registry using the procedure in
[Kubernetes operations](docs/kubernetes.md#build-and-publish), then record the
registry-reported image digests in the deployment change. The GitHub release
workflow publishes source release notes only; it does not build, sign, or
publish OCI images. Never deploy mutable `latest` tags.
