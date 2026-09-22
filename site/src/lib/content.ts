export const site = {
  name: "AgentGuard",
  title: "AgentGuard — Cedar-powered authorization for AI agents",
  description:
    "Per-tool-call authorization, tamper-evident audit, and scoped delegation for AI agents. Cedar policies, AuthZEN-compatible HTTP PDP, JWS-signed tokens, OTel-native observability.",
  url: "https://sachncs.github.io/agent-guard",
  repo: "https://github.com/sachncs/agent-guard",
  version: "0.2.0",
  license: "Apache-2.0",
};

export const nav = [
  { label: "Product", href: "#product" },
  { label: "How it works", href: "#how" },
  { label: "Standards", href: "#standards" },
  { label: "Adoption", href: "#adoption" },
  { label: "Docs", href: "https://github.com/sachncs/agent-guard#readme" },
];

export const pillars = [
  {
    title: "Per-call authorization",
    body: "Every tool call is an explicit Cedar decision — principal, action, resource, context. Allow runs the tool, deny raises AuthorizationDenied back to the model.",
    icon: "shield-check",
  },
  {
    title: "Tamper-evident audit",
    body: "Every decision is appended to a hash-chained log. Verify the chain end-to-end, export to CEF, LEEF, ECS, or JSONL for your SIEM.",
    icon: "fingerprint",
  },
  {
    title: "Scoped delegation",
    body: "A parent agent gives a sub-agent a scoped subset of permissions, time-boxed, sender-constrained (DPoP), and revocable.",
    icon: "git-branch",
  },
  {
    title: "Schema-validated Cedar",
    body: "Security teams write Cedar policies, not imperative code. Validated at authoring time against a typed schema of entities, actions, and context shapes.",
    icon: "file-check",
  },
  {
    title: "Standards-native authn",
    body: "JWT, OIDC, API keys, DPoP, SPIFFE — RFC 8725 BCP crypto, RFC 8693 token exchange, no proprietary protocols.",
    icon: "key-round",
  },
  {
    title: "Hot reload + blast radius",
    body: "Push policies without downtime. See what would break before you push, roll back instantly, observe decisions as OTel spans.",
    icon: "refresh-cw",
  },
];

export const standards = [
  { name: "Cedar", version: "4.x", href: "https://www.cedarpolicy.com" },
  { name: "OpenID AuthZEN", version: "WG", href: "https://openid.github.io/authzen/" },
  { name: "JWT", version: "RFC 7519", href: "https://datatracker.ietf.org/doc/html/rfc7519" },
  { name: "JWT BCP", version: "RFC 8725", href: "https://datatracker.ietf.org/doc/html/rfc8725" },
  { name: "DPoP", version: "RFC 9449", href: "https://datatracker.ietf.org/doc/html/rfc9449" },
  { name: "Token Exchange", version: "RFC 8693", href: "https://datatracker.ietf.org/doc/html/rfc8693" },
  { name: "W3C Trace Context", version: "W3C", href: "https://www.w3.org/TR/trace-context/" },
  { name: "SPIFFE", version: "X.509-SVID", href: "https://spiffe.io" },
];

export const integrations = [
  {
    name: "Strands Agents",
    body: "TypeScript SDK + BeforeToolCallEvent hook guards every tool invocation through the AuthZEN PDP.",
    href: "https://github.com/sachncs/agent-guard/tree/master/examples/strands-tool-authz",
  },
  {
    name: "LangChain / Custom Loops",
    body: "Spawn the CLI in-process from any Node.js agent. DPoP-bound bearer tokens, JWS-signed delegation.",
    href: "https://github.com/sachncs/agent-guard/tree/master/typescript/agentguard",
  },
  {
    name: "Axum / Tower",
    body: "Mount the AuthZEN PDP router inside your existing Rust service via agentguard_server::build_router.",
    href: "https://github.com/sachncs/agent-guard/tree/master/examples/rust-embedder",
  },
  {
    name: "Admin console",
    body: "Next.js 16 dashboard with OIDC sign-in, policy simulator, delegation console, audit browser.",
    href: "https://github.com/sachncs/agent-guard/tree/master/frontend",
  },
];

export const adoption = [
  {
    title: "Self-host",
    body: "Open-source under Apache-2.0. Drop the CLI into your agent, ship a sidecar, or embed the Cedar engine in-process. Files in .agentguard/ are the source of truth.",
    cta: "cargo install --path crates/agentguard-cli",
    href: "https://github.com/sachncs/agent-guard",
  },
  {
    title: "Run as a sidecar",
    body: "agentguard serve speaks OpenID AuthZEN over HTTP and gRPC. Use it with any language, any gateway, any federation tool that speaks AuthZEN.",
    cta: "agentguard serve --listen tcp://0.0.0.0:8443",
    href: "https://github.com/sachncs/agent-guard#quick-start",
  },
  {
    title: "Embedded in-process",
    body: "Mount the agentguard-server router inside your existing axum app. The same Cedar engine, the same audit chain — without an extra hop on the data path.",
    cta: "use agentguard_server::build_router",
    href: "https://github.com/sachncs/agent-guard/tree/master/examples/rust-embedder",
  },
];
