"use client";

import { useState } from "react";
import { fetchApi } from "@/lib/fetch_api";
import {
  delegateResponseSchema,
  errorResponseSchema,
} from "@/lib/api_schemas";
import { Copy } from "lucide-react";
import { CliAlert } from "@/components/cli_alert";
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";

export default function DelegationPage() {
  const [error, setError] = useState<string | null>(null);
  const [cliMissing, setCliMissing] = useState(false);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Delegation</h1>
        <p className="text-muted-foreground text-sm">
          Mint scoped, time-boxed JWS delegation tokens (RFC 8693) and verify
          existing ones.
        </p>
      </div>

      <div
        role="note"
        className="rounded-lg border border-warning/40 bg-warning/10 px-4 py-3 text-sm leading-relaxed"
      >
        <span className="font-semibold">Enforcement boundary:</span> these tools
        mint and verify grant claims; they do not authorize a tool call or enforce
        the grant&apos;s scope. Your tool adapter must check signature, expiry,
        audience, sender binding, and action/resource scope before execution.
      </div>

      {cliMissing && error ? (
        <CliAlert message={error} />
      ) : error ? (
        <p role="alert" className="rounded-md border border-deny/40 bg-deny/5 px-3 py-2 text-sm text-deny">
          {error}
        </p>
      ) : null}

      <Tabs defaultValue="issue">
        <TabsList>
          <TabsTrigger value="issue">Issue token</TabsTrigger>
          <TabsTrigger value="verify">Verify token</TabsTrigger>
        </TabsList>
        <TabsContent value="issue">
          <IssueForm
            onClearError={() => {
              setError(null);
              setCliMissing(false);
            }}
            onError={(msg, cli) => {
              setError(msg);
              setCliMissing(cli);
            }}
          />
        </TabsContent>
        <TabsContent value="verify">
          <VerifyForm
            onClearError={() => {
              setError(null);
              setCliMissing(false);
            }}
            onError={(msg, cli) => {
              setError(msg);
              setCliMissing(cli);
            }}
          />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function IssueForm({
  onError,
  onClearError,
}: {
  onError: (message: string, cliMissing: boolean) => void;
  onClearError: () => void;
}) {
  const [from, setFrom] = useState('Agent::"research"');
  const [to, setTo] = useState('Agent::"summarizer"');
  const [actions, setActions] = useState("ToolCall::send_email");
  const [resources, setResources] = useState("Mailbox::*");
  const [ttl, setTtl] = useState(300);
  const [token, setToken] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    onClearError();
    setToken(null);
    setBusy(true);
    try {
      const res = await fetchApi("/api/delegate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          from,
          to,
          actions: splitList(actions),
          resources: splitList(resources),
          ttlSeconds: ttl,
        }),
      });
      const body: unknown = await res.json();
      if (!res.ok) {
        const err = errorResponseSchema.safeParse(body);
        onError(
          err.success && err.data.error
            ? err.data.error
            : `request failed (${res.status})`,
          err.success && err.data.kind === "cli_unavailable"
        );
        return;
      }
      const ok = delegateResponseSchema.safeParse(body);
      if (!ok.success) {
        onError("unexpected response payload", false);
        return;
      }
      setToken(ok.data.token);
      toast.success("Delegation token issued");
    } catch {
      onError("Could not reach the delegation service. Check the console backend and try again.", false);
    } finally {
      setBusy(false);
    }
  }

  async function copy() {
    if (!token) return;
    try {
      await navigator.clipboard.writeText(token);
      toast.success("Token copied to clipboard");
    } catch {
      toast.error("Clipboard access failed. Select and copy the token manually.");
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Scoped delegation</CardTitle>
        <CardDescription>
          The sub-agent can only perform the listed actions on the listed
          resources, until the TTL expires.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="From (parent)" htmlFor="delegate-from">
              <Input id="delegate-from" className="font-mono" value={from} onChange={(e) => setFrom(e.target.value)} required />
            </Field>
            <Field label="To (sub-agent)" htmlFor="delegate-to">
              <Input id="delegate-to" className="font-mono" value={to} onChange={(e) => setTo(e.target.value)} required />
            </Field>
            <Field label="Actions (comma-separated)" htmlFor="delegate-actions">
              <Input id="delegate-actions" className="font-mono" value={actions} onChange={(e) => setActions(e.target.value)} required />
            </Field>
            <Field label="Resources (comma-separated)" htmlFor="delegate-resources">
              <Input id="delegate-resources" className="font-mono" value={resources} onChange={(e) => setResources(e.target.value)} required />
            </Field>
            <Field label="TTL (seconds)" htmlFor="delegate-ttl">
              <Input
                id="delegate-ttl"
                type="number"
                min={1}
                value={ttl}
                onChange={(e) => setTtl(Number(e.target.value))}
                required
              />
            </Field>
          </div>
          <Button type="submit" disabled={busy}>
            {busy ? "Signing…" : "Issue token"}
          </Button>
        </form>

        {token && (
          <div className="mt-6 space-y-2">
            <div className="flex items-center justify-between">
              <Label htmlFor="issued-token">JWS compact token</Label>
              <Button type="button" variant="ghost" size="sm" onClick={() => void copy()}>
                <Copy /> Copy
              </Button>
            </div>
            <Textarea id="issued-token" readOnly rows={5} value={token} className="font-mono text-xs break-all" />
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function VerifyForm({
  onError,
  onClearError,
}: {
  onError: (message: string, cliMissing: boolean) => void;
  onClearError: () => void;
}) {
  const [token, setToken] = useState("");
  const [keysFile, setKeysFile] = useState(".agentguard/delegate.pub");
  const [result, setResult] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    onClearError();
    setResult(null);
    setBusy(true);
    try {
      const res = await fetchApi("/api/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, keysFile }),
      });
      const body = await res.json();
      if (!res.ok) {
        setResult(null);
        onError(body.error ?? `request failed (${res.status})`, body.kind === "cli_unavailable");
        return;
      }
      setResult(body.result);
      toast.success("Token verified — see claims below");
    } catch {
      onError("Could not reach the verification service. Check the console backend and try again.", false);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Verify a delegation token</CardTitle>
        <CardDescription>
          Checks the JWS signature and claims against the delegated public-key
          file.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <form onSubmit={submit} className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="v-token">Token</Label>
            <Textarea
              id="v-token"
              rows={5}
              className="font-mono text-xs break-all"
              placeholder="eyJhbGciOiJFZERTQSIs..."
              value={token}
              onChange={(e) => setToken(e.target.value)}
              required
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="v-keys">Keys file path</Label>
            <Input
              id="v-keys"
              className="font-mono"
              value={keysFile}
              onChange={(e) => setKeysFile(e.target.value)}
              required
            />
          </div>
          <Button type="submit" disabled={busy}>
            {busy ? "Verifying…" : "Verify"}
          </Button>
        </form>

        {result !== null && (
          <div className="space-y-2">
            <h2 className="text-sm font-medium">Verified claims</h2>
            <pre className="bg-muted max-h-64 overflow-auto rounded-md p-3 font-mono text-xs">
              {JSON.stringify(result, null, 2)}
            </pre>
          </div>
        )}
      </CardContent>
    </Card>
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

function splitList(value: string): string[] {
  return value
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}
