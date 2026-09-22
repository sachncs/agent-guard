# Open-source governance

AgentGuard is Apache-2.0 licensed and maintained as a public repository. The
maintainer owns release decisions and the default code-owner paths; review is
still expected for security, policy, deployment, and public documentation
changes.

## Contribution path

Start with [CONTRIBUTING.md](../CONTRIBUTING.md), run the clean-checkout setup,
and open a pull request using the repository template. Changes that alter a
public API, configuration key, deployment contract, or security behavior must
include tests, documentation, and a changelog entry. Keep generated or
vendored artifacts out of commits unless the release instructions require
them.

## Support and security

Usage questions belong in Discussions or a question issue. Vulnerabilities
must use the private reporting path in [SECURITY.md](../SECURITY.md). Only the
latest release receives security fixes; compatibility and deprecation policy
are documented in [compatibility](compatibility.md).

## Release gate

The release workflow runs the same clean-checkout checks as CI before creating
a GitHub release. A release candidate must also have reviewed policy changes,
backup/rollback evidence, and a current incident-response owner. Never label a
release production-ready while an item in the documented current limitations
would invalidate the supported deployment contract.
