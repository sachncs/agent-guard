"use client";

import { useState } from "react";
import type { DecisionDto } from "@/lib/api-types";
import { fetchApi } from "@/lib/fetch-api";
import { CliAlert } from "@/components/cli-alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";

export default function SimulatorPage() {
  const [principalType, setPrincipalType] = useState("user");
  const [uid, setUid] = useState("alice");
  const [parentUid, setParentUid] = useState("");
  const [tool, setTool] = useState("send_email");
  const [operation, setOperation] = useState("");
  const [resourceType, setResourceType] = useState("Mailbox");
  const [resourceId, setResourceId] = useState("alice@acme");
  const [argsJson, setArgsJson] = useState('{ "to": "bob@example.com" }');
  const [sessionJson, setSessionJson] =
    useState('{ "ip": "10.0.0.1", "mfa": true }');
  const [decision, setDecision] = useState<DecisionDto | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [cliMissing, setCliMissing] = useState(false);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    let args: unknown;
    let session: unknown;
    try {
      args = argsJson.trim() ? JSON.parse(argsJson) : {};
      session = sessionJson.trim() ? JSON.parse(sessionJson) : {};
    } catch (err) {
      toast.error(`Invalid JSON: ${err instanceof Error ? err.message : err}`);
      return;
    }

    setBusy(true);
    try {
      const res = await fetchApi("/api/authorize", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          principalType,
          uid,
          parentUid: parentUid || undefined,
          tool,
          operation: operation || undefined,
          resourceType,
          resourceId,
          args,
          session,
        }),
      });
      const body = await res.json();
      if (!res.ok) {
        setDecision(null);
        setError(body.error ?? `request failed (${res.status})`);
        setCliMissing(body.kind === "cli_unavailable");
        return;
      }
      setDecision(body as DecisionDto);
      setError(null);
      setCliMissing(false);
      if (body.effect === "allow") {
        toast.success("Allowed");
      } else {
        toast.error("Denied");
      }
    } catch {
      toast.error("Network error while authorizing");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">
          Policy Simulator
        </h1>
        <p className="text-muted-foreground text-sm">
          Evaluate a single authorization request against your Cedar policies
          in <code>.agentguard/policies/</code>.
        </p>
      </div>

      {cliMissing && error && <CliAlert message={error} />}

      <div className="grid items-start gap-6 lg:grid-cols-[1fr_1fr]">
        <Card>
          <CardHeader>
            <CardTitle>Request</CardTitle>
            <CardDescription>principal, action, resource, context</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={submit} className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <Field label="Principal type">
                  <Select value={principalType} onValueChange={setPrincipalType}>
                    <SelectTrigger id="principal-type" className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="user">User</SelectItem>
                      <SelectItem value="agent">Agent</SelectItem>
                    </SelectContent>
                  </Select>
                </Field>
                <Field label="UID">
                  <Input
                    className="font-mono"
                    value={uid}
                    onChange={(e) => setUid(e.target.value)}
                    required
                  />
                </Field>
              </div>

              {principalType === "agent" && (
                <Field label="Parent UID (optional, marks this a sub-agent)">
                  <Input
                    className="font-mono"
                    placeholder='User::"alice"'
                    value={parentUid}
                    onChange={(e) => setParentUid(e.target.value)}
                  />
                </Field>
              )}

              <Separator />

              <div className="grid grid-cols-2 gap-4">
                <Field label="Tool">
                  <Input
                    className="font-mono"
                    value={tool}
                    onChange={(e) => setTool(e.target.value)}
                    required
                  />
                </Field>
                <Field label="Operation (optional)">
                  <Input
                    className="font-mono"
                    value={operation}
                    onChange={(e) => setOperation(e.target.value)}
                  />
                </Field>
              </div>

              <Separator />

              <div className="grid grid-cols-[8rem_1fr] gap-4">
                <Field label="Resource type">
                  <Input
                    className="font-mono"
                    value={resourceType}
                    onChange={(e) => setResourceType(e.target.value)}
                    required
                  />
                </Field>
                <Field label="Resource ID">
                  <Input
                    className="font-mono"
                    value={resourceId}
                    onChange={(e) => setResourceId(e.target.value)}
                    required
                  />
                </Field>
              </div>

              <Separator />

              <Field label='Context · args (JSON object)'>
                <Textarea
                  rows={3}
                  className="font-mono text-xs"
                  value={argsJson}
                  onChange={(e) => setArgsJson(e.target.value)}
                />
              </Field>
              <Field label='Context · session (JSON object)'>
                <Textarea
                  rows={3}
                  className="font-mono text-xs"
                  value={sessionJson}
                  onChange={(e) => setSessionJson(e.target.value)}
                />
              </Field>

              <Button type="submit" disabled={busy}>
                {busy ? "Evaluating…" : "Evaluate"}
              </Button>
            </form>
          </CardContent>
        </Card>

        <Card className="min-h-[16rem]">
          <CardHeader>
            <CardTitle>Decision</CardTitle>
            {error && !cliMissing && (
              <CardDescription className="text-red-600 dark:text-red-400">
                {error}
              </CardDescription>
            )}
          </CardHeader>
          <CardContent className="space-y-4">
            {!decision && !error && (
              <p className="text-muted-foreground text-sm">
                Submit a request to see the Allow / Deny decision, the policies
                that matched, and any step-up requirements.
              </p>
            )}
            {decision && <DecisionResult decision={decision} />}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function DecisionResult({ decision }: { decision: DecisionDto }) {
  const allow = decision.effect === "allow";
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Badge
          variant={allow ? "outline" : "destructive"}
          className={`text-sm ${allow ? "border-green-600 text-green-600 dark:text-green-400" : ""}`}
        >
          {allow ? "ALLOW" : "DENY"}
        </Badge>
        {decision.step_up && (
          <Badge variant="secondary">step-up required</Badge>
        )}
        {decision.trace_id && (
          <span className="text-muted-foreground font-mono text-xs">
            trace {decision.trace_id.slice(0, 12)}…
          </span>
        )}
      </div>

      {decision.policies.length > 0 && (
        <div>
          <h3 className="mb-1.5 text-xs font-medium tracking-wide uppercase">
            Matched policies
          </h3>
          <div className="flex flex-wrap gap-1.5">
            {decision.policies.map((p) => (
              <Badge key={p} variant="outline" className="font-mono text-xs">
                {p}
              </Badge>
            ))}
          </div>
        </div>
      )}

      {decision.reasons.length > 0 && (
        <div>
          <h3 className="mb-1.5 text-xs font-medium tracking-wide uppercase">
            Reasons
          </h3>
          <ul className="list-disc space-y-0.5 pl-5 text-sm">
            {decision.reasons.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </div>
      )}

      {decision.step_up && (
        <p className="text-muted-foreground text-sm">
          Re-authentication with{" "}
          <code className="font-mono text-xs">
            acr_values={decision.step_up.acr_values}
          </code>{" "}
          is required before this action can be allowed.
        </p>
      )}

      <details className="text-sm">
        <summary className="text-muted-foreground cursor-pointer select-none">
          Raw response
        </summary>
        <pre className="bg-muted mt-2 max-h-64 overflow-auto rounded-md p-3 font-mono text-xs">
          {JSON.stringify(decision.raw, null, 2)}
        </pre>
      </details>
    </div>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1.5">
      <Label>{label}</Label>
      {children}
    </div>
  );
}
