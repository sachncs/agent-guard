# Release checklist

- [ ] Update workspace, crate, SDK, console, and site versions together.
- [ ] Run Rust format, clippy, tests, doctests, build, and dependency audits.
- [ ] Run TypeScript install, lint, typecheck, tests, frontend build, and e2e.
- [ ] Run Astro check and site build.
- [ ] Verify README and docs links and inspect public branding assets.
- [ ] Build both Docker images and run health/readiness smoke tests.
- [ ] Apply the Kubernetes manifests in a disposable cluster and verify an
      allow, deny, audit append, graceful shutdown, and rollback.
- [ ] Review SECURITY.md, CHANGELOG.md, compatibility policy, and migration
      notes.
- [ ] Tag the release and publish release notes only after all checks pass.
