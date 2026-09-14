"use client";

import * as React from "react";
import { Copy, Check } from "lucide-react";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import { cn } from "@/lib/utils";

const snippets = {
  typescript: {
    label: "TypeScript SDK",
    file: "agent.ts",
    code: `import { Client, Principal, Action } from "agentguard";

const client = new Client({ store: ".agentguard" });

const decision = client.check(
  Principal.user("alice"),
  Action.tool("send_email"),
  { entity_type: "Mailbox", uid: "alice@acme" },
  { args: { to: "bob@acme.dev" }, session: { ip: "10.0.0.1", mfa: true } },
);
// → Allow

// Scoped delegation (RFC 8693, JWS-signed, time-boxed):
await client.delegate(
  'Agent::"research"',
  'Agent::"summarizer"',
  ["ToolCall::send_email"],
  ["Mailbox::*"],
  300, // seconds
);`,
  },
  http: {
    label: "AuthZEN HTTP",
    file: "curl",
    code: `curl -X POST https://localhost:8443/access/v1/evaluation \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer $AGENTGUARD_BEARER" \\
  -d '{
    "subject":  { "type": "User",  "id": "alice" },
    "action":   { "type": "Action", "id": "ToolCall::send_email" },
    "resource": { "type": "Mailbox", "id": "alice@acme" },
    "context":  {
      "args":   { "to": "bob@acme.dev" },
      "session": { "ip": "10.0.0.1", "mfa": true }
    }
  }'
# → { "decision": true, "context": { "decision_id": "0x9f4a…" } }`,
  },
  cli: {
    label: "CLI",
    file: "shell",
    code: `# Initialize a project
agentguard init --name acme

# Edit the schema and policies in .agentguard/
$EDITOR .agentguard/policies/20_agents.cedar

# Validate policies against the schema
agentguard validate
# ✓ schema loads
# ✓ policies parse
# ✓ schema validation passes

# Authorize a single request
agentguard authorize request.json
# ✓  ALLOW alice send_email alice@acme

# Walk the chain, verify every HMAC
agentguard audit verify \\
  --audit .audit/decisions.jsonl \\
  --secret-file .chain-secret
# ✓ chain integrity verified across 12,481 records`,
  },
};

type SnippetKey = keyof typeof snippets;

export function CodeShowcase() {
  const [active, setActive] = React.useState<SnippetKey>("typescript");
  const [copied, setCopied] = React.useState(false);

  const handleCopy = React.useCallback(async () => {
    try {
      await navigator.clipboard.writeText(snippets[active].code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {}
  }, [active]);

  return (
    <div className="w-full">
      <Tabs value={active} onValueChange={(v) => setActive(v as SnippetKey)}>
        <div className="mb-4 flex flex-col items-start justify-between gap-3 sm:flex-row sm:items-center">
          <TabsList>
            {(Object.keys(snippets) as SnippetKey[]).map((key) => (
              <TabsTrigger key={key} value={key}>
                {snippets[key].label}
              </TabsTrigger>
            ))}
          </TabsList>
          <button
            type="button"
            onClick={handleCopy}
            aria-label="Copy code"
            className="inline-flex h-8 items-center gap-1.5 rounded-full border border-[var(--border)] bg-[var(--bg-inset)] px-3 text-xs text-[var(--fg-muted)] transition-all hover:border-[var(--border-strong)] hover:text-[var(--fg)]"
          >
            {copied ? (
              <>
                <Check className="size-3.5 text-emerald-500" />
                Copied
              </>
            ) : (
              <>
                <Copy className="size-3.5" />
                Copy
              </>
            )}
          </button>
        </div>

        {(Object.keys(snippets) as SnippetKey[]).map((key) => (
          <TabsContent key={key} value={key} className="mt-0">
            <CodeBlock code={snippets[key].code} file={snippets[key].file} />
          </TabsContent>
        ))}
      </Tabs>
    </div>
  );
}

function CodeBlock({ code, file }: { code: string; file: string }) {
  const lines = code.split("\n");
  return (
    <div className="surface relative overflow-hidden rounded-2xl">
      <div className="flex items-center justify-between border-b border-[var(--border)] bg-[var(--bg-inset)] px-4 py-2.5">
        <div className="flex items-center gap-2">
          <span className="size-2.5 rounded-full bg-rose-400/60" />
          <span className="size-2.5 rounded-full bg-amber-400/60" />
          <span className="size-2.5 rounded-full bg-emerald-400/60" />
          <span className="ml-2 font-mono text-xs text-[var(--fg-subtle)]">{file}</span>
        </div>
        <span className="font-mono text-[10px] uppercase tracking-wider text-[var(--fg-subtle)]">
          {lines.length} lines
        </span>
      </div>
      <pre className="overflow-x-auto bg-[var(--bg)] p-5 font-mono text-[12.5px] leading-relaxed text-[var(--fg)]">
        <code>{highlight(code)}</code>
      </pre>
    </div>
  );
}

function highlight(code: string) {
  return code;
}
