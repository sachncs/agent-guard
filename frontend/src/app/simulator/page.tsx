"use client";

import { useState } from "react";
import type { DecisionDto } from "@/lib/api_types";
import { decisionPresentation } from "@/lib/decision_presentation";
import {
  decisionResponseSchema,
  errorResponseSchema,
} from "@/lib/api_schemas";
import { fetchApi } from "@/lib/fetch_api";
import { parseJsonObject } from "@/lib/json_object";
import { CliAlert } from "@/components/cli_alert";
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
  const [tool, setTool] = useState("send_email");
  const [operation, setOperation] = useState("");
  const [resourceType, setResourceType] = useState("Mailbox");
  const [resourceId, setResourceId] = useState("alice@acme");
  const [argsJson, setArgsJson] = useState('{ "to": "bob@example.com" }');
  const [sessionJson, setSessionJson] =
    useState('{ "ip": "10.0.0.1", "mfa": true }');
  const [decision, setDecision] = useState<DecisionDto | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [invalidContextField, setInvalidContextField] = useState<"args" | "session" | null>(null);
  const [cliMissing, setCliMissing] = useState(false);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setValidationError(null);
    setInvalidContextField(null);
    setDecision(null);
    setError(null);
    setCliMissing(false);
    const parsedArgs = parseJsonObject(argsJson, "Arguments");
    if (!parsedArgs.ok) {
      setValidationError(parsedArgs.error);
      setInvalidContextField("args");
      return;
    }
    const parsedSession = parseJsonObject(sessionJson, "Session");
    if (!parsedSession.ok) {
      setValidationError(parsedSession.error);
      setInvalidContextField("session");
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
          tool,
          operation: operation || undefined,
          resourceType,
          resourceId,
          args: parsedArgs.value,
          session: parsedSession.value,
        }),
      });
      const body: unknown = await res.json();
      if (!res.ok) {
        const err = errorResponseSchema.safeParse(body);
        setDecision(null);
        setError(
          err.success && err.data.error ? err.data.error : `request failed (${res.status})`
        );
        setCliMissing(err.success && err.data.kind === "cli_unavailable");
        return;
      }
      const ok = decisionResponseSchema.safeParse(body);
      if (!ok.success) {
        setError("PDP returned an unexpected payload");
        setCliMissing(false);
        return;
      }
      setDecision(ok.data);
      setError(null);
      setCliMissing(false);
      if (ok.data.effect === "allow") {
        toast.success("Allowed");
      } else {
        toast.error("Denied");
      }
    } catch {
      setDecision(null);
      setError("Could not reach the authorization service. Check the console backend and PDP, then try again.");
      setCliMissing(false);
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
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <Field label="Principal type" htmlFor="principal-type">
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
                <Field label="UID" htmlFor="principal-uid">
                  <Input
                    id="principal-uid"
                    className="font-mono"
                    value={uid}
                    onChange={(e) => setUid(e.target.value)}
                    required
                  />
                </Field>
              </div>

              {principalType === "agent" && (
                <p
                  role="note"
                  className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-200"
                >
                  The HTTP simulator evaluates a top-level agent only. Parent
                  relationships are carried by delegation tokens and are
                  managed in the Delegation workflow.
                </p>
              )}

              <Separator />

              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <Field label="Tool" htmlFor="action-tool">
                  <Input
                    id="action-tool"
                    className="font-mono"
                    value={tool}
                    onChange={(e) => setTool(e.target.value)}
                    required
                  />
                </Field>
                <Field label="Operation (optional)" htmlFor="action-operation">
                  <Input
                    id="action-operation"
                    className="font-mono"
                    value={operation}
                    onChange={(e) => setOperation(e.target.value)}
                  />
                </Field>
              </div>

              <Separator />

              <div className="grid grid-cols-1 gap-4 sm:grid-cols-[8rem_1fr]">
                <Field label="Resource type" htmlFor="resource-type">
                  <Input
                    id="resource-type"
                    className="font-mono"
                    value={resourceType}
                    onChange={(e) => setResourceType(e.target.value)}
                    required
                  />
                </Field>
                <Field label="Resource ID" htmlFor="resource-id">
                  <Input
                    id="resource-id"
                    className="font-mono"
                    value={resourceId}
                    onChange={(e) => setResourceId(e.target.value)}
                    required
                  />
                </Field>
              </div>

              <Separator />

              <Field label="Arguments · JSON object" htmlFor="request-args">
                <Textarea
                  id="request-args"
                  rows={3}
                  className="font-mono text-xs"
                  value={argsJson}
                  aria-invalid={invalidContextField === "args"}
                  aria-describedby={invalidContextField === "args" ? "request-context-error" : undefined}
                  onChange={(e) => setArgsJson(e.target.value)}
                />
              </Field>
              <Field label="Session · JSON object" htmlFor="request-session">
                <Textarea
                  id="request-session"
                  rows={3}
                  className="font-mono text-xs"
                  value={sessionJson}
                  aria-invalid={invalidContextField === "session"}
                  aria-describedby={invalidContextField === "session" ? "request-context-error" : undefined}
                  onChange={(e) => setSessionJson(e.target.value)}
                />
              </Field>

              {validationError && (
                <p id="request-context-error" role="alert" className="text-sm text-deny">
                  {validationError}
                </p>
              )}

              <Button type="submit" disabled={busy} aria-busy={busy}>
                {busy ? "Evaluating…" : "Evaluate"}
              </Button>
            </form>
          </CardContent>
        </Card>

        <Card className="min-h-[16rem]">
          <CardHeader>
            <CardTitle>Decision</CardTitle>
            {error && !cliMissing && (
              <CardDescription role="alert" aria-live="assertive" className="text-deny">
                {error}
              </CardDescription>
            )}
          </CardHeader>
          <CardContent className="space-y-4">
            {busy ? (
              <p role="status" aria-live="polite" className="text-muted-foreground text-sm">
                Evaluating this request against the configured policies…
              </p>
            ) : !decision && !error ? (
              <p className="text-muted-foreground text-sm">
                Submit a request to see the Allow / Deny decision, the policies
                that matched, and any step-up requirements.
              </p>
            ) : decision ? <DecisionResult decision={decision} /> : null}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function DecisionResult({ decision }: { decision: DecisionDto }) {
  const presentation = decisionPresentation(decision.effect);
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Badge
          variant="outline"
          className={`text-sm ${presentation.className}`}
          aria-label={presentation.ariaLabel}
        >
          {presentation.label}
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
  htmlFor,
  children,
}: {
  label: string;
  htmlFor: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={htmlFor}>{label}</Label>
      {children}
    </div>
  );
}
