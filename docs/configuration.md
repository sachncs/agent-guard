# Configuration reference

Configuration is component-specific: environment variables are not universal
switches. This guide documents which process reads each setting and where its
default applies. The standalone server binary, embedded Rust library, CLI,
TypeScript subprocess, and optional console have distinct configuration
boundaries.

For the supported production deployment, use the
[Docker-on-Kubernetes contract](production.md). Keep credentials in a secret
manager or Kubernetes Secret; do not put them in image layers, source control,
or browser-visible variables.

## Standalone server

| Setting | Default | Purpose and constraints |
| --- | --- | --- |
| `AGENTGUARD_LISTEN` / `--listen` | `tcp://127.0.0.1:8443` | TCP or `tls://` listener URL. |
| `AGENTGUARD_STORE` / `--store` | `.agentguard` | Policy directory containing schema and Cedar policies. |
| `AGENTGUARD_AUDIT` / `--audit` | `.audit/decisions.jsonl` | Decision-log destination. The configured destination must be a regular file. |
| `AGENTGUARD_CHAIN_SECRET` | unset | Path to the HMAC chain secret. Unset means JSONL without cryptographic chaining. |
| `AGENTGUARD_AUTH` / `--auth` | `disabled` | Binary accepts `disabled`, `apikey` with a separate key-file, or the complete `apikey:<path>` environment form. Non-loopback production listeners require authentication. |
| `AGENTGUARD_AUTH_KEY_FILE` / `--auth-key-file` | unset | JSON API-key store for `--auth apikey`; unnecessary when the environment value includes the path. |
| `AGENTGUARD_GRPC_LISTEN` / `--grpc-listen` | unset | Optional loopback socket address for the repository-defined gRPC service. Protect the network boundary; the listener is plaintext. |
| `AGENTGUARD_ALLOW_LOOPBACK_BYPASS` | `false` | Explicit bypass for auth-disabled public HTTP binds. Do not expose such a listener to untrusted clients. |
| `RUST_LOG` | `info,agentguard=debug` | `tracing-subscriber` filter used by the server binary. |

### Authentication parsing: binary and library

The standalone binary accepts `--auth apikey` with a separate
`--auth-key-file`, or `AGENTGUARD_AUTH=apikey:<path>` as one complete
environment value. `ServerConfig::from_env` in the library accepts the same
`apikey:<path>` environment form. The binary and library intentionally have
separate configuration surfaces: check `agentguard-server --help` for the
binary and configure `ServerConfig` / `AuthConfig` explicitly when embedding.

## CLI and TypeScript subprocess

| Setting | Default | Purpose and constraints |
| --- | --- | --- |
| `--store` / `AGENTGUARD_STORE` | `.agentguard` | Local schema and policy directory. |
| `--audit` / `AGENTGUARD_AUDIT` | `.audit/decisions.jsonl` | CLI decision log. |
| `--secret-file` / `AGENTGUARD_CHAIN_SECRET` | unset | HMAC audit-chain secret file. |
| `--output` | `pretty` | Use `json` for automation. |
| `AGENTGUARD_BIN` | unset | Explicit TypeScript SDK CLI path; `ClientOptions.cliBin` takes precedence. |
| `AGENTGUARD_TRACEPARENT` | unset | W3C trace context forwarded to CLI requests by the SDK. |
| `AGENTGUARD_BEARER` | unset | Forwarded by the SDK. The local CLI does not validate it or send it to a PDP. |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | unset | Provider credential for the optional `gen` command; not used for ordinary authorization. |

The TypeScript SDK's synchronous methods block the calling thread. Use its
bounded asynchronous methods in concurrent server handlers; see the
[API reference](https://sachncs.github.io/agent-guard/docs/api/).

## Cache, audit rotation, and optional library integrations

| Setting | Default | Purpose and constraints |
| --- | --- | --- |
| `AGENTGUARD_CACHE_TTL` | `60s` | Standalone allow-cache TTL. Malformed values fail startup. Embedded builders receive `CacheConfig` explicitly. |
| `AGENTGUARD_DENY_CACHE_TTL` | `5s` | Standalone deny-cache TTL. Malformed values fail startup. |
| `AGENTGUARD_CACHE_CAPACITY` | `10000` | Positive standalone cache capacity. Malformed or zero values fail startup. |
| `AGENTGUARD_AUDIT_MAX_BYTES` | unset | Standalone audit rotation threshold in bytes. Unset disables rotation; a configured value must be a positive integer. Embedded builders receive `RotationConfig` explicitly. |
| `AGENTGUARD_JWKS_REFRESH` | `30s` | Read by `JwtConfig::with_jwks_refresh_from_env`; the embedding application owns validator and refresher wiring. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTel exporter default | Read by `OtlpSink::from_env` when the `otlp` feature is enabled. Setting an endpoint alone does not activate export in the standalone server. |
| `OTEL_SERVICE_NAME` | `agentguard` | Resource `service.name` used by `OtlpSink`. |

## Optional admin console

The console is a separately deployed Next.js process. Authentication is
mandatory; there is no open mode. Its production sessions and rate limits use
Redis-compatible shared stores. In-memory implementations are for development
and tests only.

| Setting | Default / requirement | Purpose and constraints |
| --- | --- | --- |
| `AGENTGUARD_OIDC_ISSUER` | required | OIDC issuer. Production requires HTTPS for the issuer and discovered authorization, token, and JWKS endpoints. Loopback HTTP is development-only. |
| `AGENTGUARD_OIDC_CLIENT_ID` | required | Confidential OIDC client identifier. |
| `AGENTGUARD_OIDC_CLIENT_SECRET` | required | Confidential client secret; provide through a secret manager. |
| `AGENTGUARD_SESSION_SECRET` | required, at least 32 characters | Signs console session and OIDC state cookies. |
| `AGENTGUARD_SESSION_TTL_SECONDS` | `28800` | Console session lifetime, integer from 300 to 28800 seconds; OIDC role changes take effect on next login. |
| `AGENTGUARD_SESSION_STORE` | memory in development; `redis` in production | Shared session backend. Production refuses memory fallback. |
| `AGENTGUARD_SESSION_REDIS_URL` / `AGENTGUARD_SESSION_REDIS_TOKEN` | required for Redis | Redis-compatible REST endpoint and credential. Production requires HTTPS; provide credentials separately. |
| `AGENTGUARD_SESSION_REDIS_PREFIX` | `agentguard:session:` | Optional 1–128 character key namespace. Use a distinct prefix for each environment sharing a database. |
| `AGENTGUARD_RATE_LIMIT_STORE` | memory in development; `redis` in production | Shared rate-limit backend. Production refuses memory fallback. |
| `AGENTGUARD_RATE_LIMIT_REDIS_URL` / `AGENTGUARD_RATE_LIMIT_REDIS_TOKEN` | required for Redis | Redis-compatible REST endpoint and credential. Production requires HTTPS; provide credentials separately. |
| `AGENTGUARD_RATE_LIMIT_REDIS_PREFIX` | `agentguard:ratelimit:` | Optional 1–128 character key namespace. Use a distinct prefix for each environment sharing a database. |
| `AGENTGUARD_ADMIN_CLAIM` | `groups` | ID-token claim used to resolve the console role. |
| `AGENTGUARD_ADMIN_VALUES` | empty | Comma-separated claim values granting admin. Empty means every signed-in user is a viewer. |
| `AGENTGUARD_PDP_URL` | `http://127.0.0.1:8443` in development; required in production | PDP base URL. Production requires HTTPS unless the internal transport exception is enabled. |
| `AGENTGUARD_PDP_ALLOW_INSECURE_INTERNAL` | `0` | Set to `1` only for an isolated private cluster hop or a service mesh that provides mTLS. Production HTTP targets remain restricted to loopback, private IPs, or cluster-local DNS. |
| `AGENTGUARD_PDP_BEARER` | unset | Server-side bearer credential sent to the PDP; never expose it to browser code. |
| `AGENTGUARD_STORE` | `.agentguard` | Policy store used by CLI-backed console routes. |
| `AGENTGUARD_AUDIT` | `.audit/decisions.jsonl` | Audit source used by CLI-backed routes. |
| `AGENTGUARD_DELEGATION_KEY_FILE` | unset | Persistent Ed25519 key required for delegation issuance; the route fails closed when it is unavailable. |
| `AGENTGUARD_TRUST_PROXY_HEADERS` | `0` in development; `1` required in production | Trust only a reverse proxy that removes and replaces forwarded address, host, and scheme headers with validated values. |
| `AGENTGUARD_INSECURE_COOKIE` | unset | Set to `1` only for local plain-HTTP development; never use in production. |

The deployment proxy must terminate TLS and set the external scheme correctly.
Read the [console deployment guide](console.md) for readiness checks, role
mapping, session behavior, CSRF protections, and failure semantics.

## Verify and source references

Inspect the selected command's `--help` output and validate a deployment
configuration before release. The
[compatibility policy](compatibility.md) defines supported runtimes, and the
[production guide](production.md) defines the supported deployment contract.
The implementation sources are the [server binary flags](../crates/agentguard-server/src/main.rs),
[library configuration](../crates/agentguard-server/src/listener.rs),
[cache implementation](../crates/agentguard-core/src/decision/cache.rs), and
[console environment contract](../frontend/README.md).
