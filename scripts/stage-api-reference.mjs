import { cpSync, mkdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const requiredCrates = ["agentguard_core", "agentguard_server", "agentguard", "agentguard_auth", "agentguard_policy", "agentguard_telemetry"];
const declarationFiles = ["index.d.ts", "trace.d.ts"];
const referenceFiles = [
  ["target/api-reference/agentguard-cli-help.txt", "CLI help"],
  ["target/api-reference/agentguard-server-help.txt", "server CLI help"],
  ["crates/agentguard-server/proto/agentguard.proto", "protobuf source"],
  ["target/api-reference/agentguard.pb", "protobuf descriptor"],
];

function requireFile(path, label) {
  if (!statSync(path, { throwIfNoEntry: false })?.isFile()) {
    throw new Error(`generated API reference is incomplete: missing ${label} (${path})`);
  }
}

function page() {
  const items = [
    ["Rust: core authorization", "rustdoc/agentguard_core/index.html"],
    ["Rust: standalone server", "rustdoc/agentguard_server/index.html"],
    ["Rust: CLI library", "rustdoc/agentguard/index.html"],
    ["Rust: identity", "rustdoc/agentguard_auth/index.html"],
    ["Rust: policy operations", "rustdoc/agentguard_policy/index.html"],
    ["Rust: telemetry", "rustdoc/agentguard_telemetry/index.html"],
    ["TypeScript: public API declarations", "typescript/index.d.ts"],
    ["TypeScript: trace declarations", "typescript/trace.d.ts"],
    ["CLI: agentguard --help", "cli/agentguard-help.txt"],
    ["CLI: agentguard-server --help", "cli/agentguard-server-help.txt"],
    ["Protobuf: source contract", "protobuf/agentguard.proto"],
    ["Protobuf: compiled descriptor set", "protobuf/agentguard.pb"],
  ];
  const links = items.map(([label, href]) => `      <li><a href="${href}">${label}</a></li>`).join("\n");
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark"><title>Generated API reference · AgentGuard</title>
<style>body{max-width:56rem;margin:4rem auto;padding:0 1.5rem;font:1rem/1.7 system-ui,sans-serif;background:#101716;color:#eef3f0}a{color:#79dfbf}li{margin:.55rem 0}code{font-size:.92em}</style></head>
<body><main><p><a href="../../docs/reference/">← API and reference guide</a></p>
<h1>Generated API reference</h1>
<p>Generated from the same source revision as this documentation deployment. Rustdoc links are browsable; TypeScript declarations, CLI help, protobuf source, and the descriptor set are versioned downloads.</p>
<ul>
${links}
</ul>
<p>HTTP, configuration, and integration contracts are documented in the <a href="../../docs/api/">HTTP, SDK, and CLI guide</a> and <a href="../../docs/configuration/">configuration reference</a>.</p>
</main></body></html>
`;
}

export function stageApiReference({
  rustdocSource,
  typescriptSource,
  destination,
  cliHelp,
  serverHelp,
  protobufSource,
  protobufDescriptor,
}) {
  const rustdoc = resolve(rustdocSource);
  const typescript = resolve(typescriptSource);
  const output = resolve(destination);

  for (const crate of requiredCrates) requireFile(resolve(rustdoc, crate, "index.html"), `${crate} Rustdoc`);
  for (const declaration of declarationFiles) requireFile(resolve(typescript, declaration), `TypeScript ${declaration}`);
  for (const [path, label] of [
    [cliHelp, "CLI help"],
    [serverHelp, "server CLI help"],
    [protobufSource, "protobuf source"],
    [protobufDescriptor, "protobuf descriptor"],
  ]) requireFile(resolve(path), label);

  // Validate every input before replacing this exact generated output path.
  rmSync(output, { recursive: true, force: true });
  mkdirSync(dirname(output), { recursive: true });
  const rustdocOutput = resolve(output, "rustdoc");
  cpSync(rustdoc, rustdocOutput, { recursive: true, dereference: true });

  const typescriptOutput = resolve(output, "typescript");
  const cliOutput = resolve(output, "cli");
  const protobufOutput = resolve(output, "protobuf");
  mkdirSync(typescriptOutput, { recursive: true });
  mkdirSync(cliOutput, { recursive: true });
  mkdirSync(protobufOutput, { recursive: true });
  for (const declaration of declarationFiles) {
    cpSync(resolve(typescript, declaration), resolve(typescriptOutput, declaration));
  }
  cpSync(resolve(cliHelp), resolve(cliOutput, "agentguard-help.txt"));
  cpSync(resolve(serverHelp), resolve(cliOutput, "agentguard-server-help.txt"));
  cpSync(resolve(protobufSource), resolve(protobufOutput, "agentguard.proto"));
  cpSync(resolve(protobufDescriptor), resolve(protobufOutput, "agentguard.pb"));

  writeFileSync(resolve(output, "index.html"), page());
  return output;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const destination = stageApiReference({
    rustdocSource: "target/doc",
    typescriptSource: "typescript/agentguard/dist",
    destination: "site/dist/reference/generated",
    cliHelp: "target/api-reference/agentguard-cli-help.txt",
    serverHelp: "target/api-reference/agentguard-server-help.txt",
    protobufSource: "crates/agentguard-server/proto/agentguard.proto",
    protobufDescriptor: "target/api-reference/agentguard.pb",
  });
  console.log(`staged generated multi-language API reference at ${destination}`);
}
