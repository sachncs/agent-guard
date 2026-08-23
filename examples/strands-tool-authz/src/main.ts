/**
 * Strands Agents (TypeScript) demo where every tool call is authorized by
 * agentguard before it executes.
 *
 * Prereqs (see README.md):
 *   cargo install --path crates/agentguard-cli && agentguard init --name acme
 *   agentguard serve --http 127.0.0.1:8443 &
 *   export AWS_REGION=us-east-1            # Bedrock credentials via your
 *   aws sso login                          # usual AWS credential chain
 *
 * Run:  pnpm --filter strands-tool-authz start
 */

import {
  Agent,
  BedrockModel,
  BeforeToolCallEvent,
} from "@strands-agents/sdk";
import { z } from "zod";
import type { AuthZenEntity } from "./guard.js";
import { AgentGuard, guarded } from "./guard.js";

const principal = (): AuthZenEntity | undefined => {
  const id = process.env.AGENTGUARD_USER;
  if (!id) return undefined; // fail closed when no identity is configured
  return { type: "User", id };
};

const guard = new AgentGuard({ principal });

const web_search = guarded(guard, {
  name: "web_search",
  description: "Search the web and return the top results as text.",
  inputSchema: z.object({ query: z.string().describe("Search query") }),
  callback: async ({ query }) =>
    `(demo) Top results for "${query}": agent-guard docs, AuthZEN spec.`,
});

const send_email = guarded(guard, {
  name: "send_email",
  description: "Send an email on behalf of the signed-in user.",
  inputSchema: z.object({
    to: z.string().email(),
    subject: z.string(),
    body: z.string(),
  }),
  callback: async ({ to }) => `Sent email to ${to}.`,
});

const model = new BedrockModel({
  modelId: process.env.BEDROCK_MODEL_ID ?? "us.anthropic.claude-sonnet-4-20250514-v1:0",
});

const agent = new Agent({ model, tools: [web_search, send_email] });

// Optional: log every tool call as the framework sees it.
agent.hooks.addCallback(BeforeToolCallEvent, (event) => {
  console.log(`[strands] tool call -> ${event.toolUse.name}`);
});

const prompt =
  "Search the web for 'agentguard cedar' and then email the summary to " +
  "security@example.com with subject 'agentguard notes'.";

console.log(`user: ${prompt}\n`);
const result = await agent.invoke(prompt);
console.log(`\nassistant: ${result}`);
