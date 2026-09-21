export const policy = `permit (
  principal == Agent::"research",
  action == Action::"ToolCall::repo_read",
  resource == Repository::"demo"
) when {
  context.session has mfa &&
  context.session.mfa
};`;
export const request = {
 principal: { type: 'agent', uid: 'research' },
 action: { tool: 'repo_read' },
 resource: { entity_type: 'Repository', uid: 'demo', attrs: { org: 'example' } },
 context: { args: { repo: 'demo' }, session: { mfa: true } },
};
export const httpRequest = {
 subject: { type: 'Agent', id: 'research' },
 action: { type: 'Action', id: 'ToolCall::repo_read' },
 resource: { type: 'Repository', id: 'demo' },
 context: { args: { repo: 'demo' }, session: { mfa: true } },
};
export const integrationExamples = [
 { name:'TypeScript', lang:'typescript', title:'authorize.ts', description:'Node.js SDK. Spawns the installed CLI synchronously. Call your tool only after check() returns.', code:`import { Client, Principal, Action } from "agentguard";

const guard = new Client({ store: ".agentguard" });
guard.check(
  Principal.agent("research"),
  Action.tool("repo_read"),
  { entity_type: "Repository", uid: "demo", attrs: { org: "example" } },
  { args: { repo: "demo" }, session: { mfa: true } },
);
// Permission granted. Your application may now run the tool.
// On denial, check() throws AuthorizationDenied.` },
 { name:'HTTP / AuthZEN', lang:'bash', title:'Local HTTP request', description:'For the loopback quickstart. Remote deployments need transport protection and authenticated access.', code:`curl --fail-with-body http://127.0.0.1:8443/access/v1/evaluation \\
  -H 'Content-Type: application/json' \\
  -d '${JSON.stringify(httpRequest,null,2)}'
# Proceed only if the response succeeds and decision === true.` },
 { name:'CLI', lang:'bash', title:'Evaluate and inspect', description:'request.json is the CLI request from the quickstart. Exit code 2 means deny; other failures must also stop execution.', code:`agentguard validate
agentguard --output json authorize request.json
agentguard sim request.json
agentguard log tail --n 10
agentguard doctor` },
 { name:'Rust', lang:'rust', title:'Embedded authorizer', description:'Inside a function returning Result. The embedded engine returns a decision; your application owns enforcement, identity, and audit wiring.', code:`use agentguard_core::{AgentRequest, Authorizer, PolicyStore};
use cedar_policy::Entities;

let store = PolicyStore::open(".agentguard")?;
let authorizer = Authorizer::new(store)?;
let req: AgentRequest = serde_json::from_str(request_json)?;
// This policy uses IDs and context, not entity attributes.
let entities = Entities::empty();
let decision = authorizer.authorize(&req, &entities)?;
// Check decision.effect before executing the tool.
// Append to your configured DecisionLog at this boundary.` },
 { name:'Strands', lang:'typescript', title:'Repository example', description:'The guarded() helper belongs to examples/strands-tool-authz. It is an example adapter, not an exported SDK method.', code:`import { AgentGuard, guarded } from "./guard.js";

const guard = new AgentGuard({
  principal: { type: "Agent", id: "research" },
  resource: { type: "Repository", id: "demo" },
});
// Wrap your tool config before registering it with Strands:
const protectedTool = guarded(guard, toolConfig);
// The callback runs only after an explicit HTTP allow.
// Tailor the schema and policy to toolConfig's input.` },
];
