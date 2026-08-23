"use client";

import { useState } from "react";
import { Copy } from "lucide-react";
import { CliAlert } from "@/components/cli-alert";
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

      {cliMissing && error && <CliAlert message={error} />}

      <Tabs defaultValue="issue">
        <TabsList>
          <TabsTrigger value="issue">Issue token</TabsTrigger>
          <TabsTrigger value="verify">Verify token</TabsTrigger>
        </TabsList>
        <TabsContent value="issue">
          <IssueForm
            onError={(msg, cli) => {
              setError(msg);
              setCliMissing(cli);
            }}
          />
        </TabsContent>
        <TabsContent value="verify">
          <VerifyForm
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
}: {
  onError: (message: string, cliMissing: boolean) => void;
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
    setBusy(true);
    try {
      const res = await fetch("/api/delegate", {
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
      const body = await res.json();
      if (!res.ok) {
        onError(body.error ?? `request failed (${res.status})`, body.kind === "cli_unavailable");
        return;
      }
      setToken(body.token as string);
      toast.success("Delegation token issued");
    } catch {
      toast.error("Network error while issuing token");
    } finally {
      setBusy(false);
    }
  }

  async function copy() {
    if (!token) return;
    await navigator.clipboard.writeText(token);
    toast.success("Token copied to clipboard");
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
            <Field label="From (parent)">
              <Input className="font-mono" value={from} onChange={(e) => setFrom(e.target.value)} required />
            </Field>
            <Field label="To (sub-agent)">
              <Input className="font-mono" value={to} onChange={(e) => setTo(e.target.value)} required />
            </Field>
            <Field label="Actions (comma-separated)">
              <Input className="font-mono" value={actions} onChange={(e) => setActions(e.target.value)} required />
            </Field>
            <Field label="Resources (comma-separated)">
              <Input className="font-mono" value={resources} onChange={(e) => setResources(e.target.value)} required />
            </Field>
            <Field label="TTL (seconds)">
              <Input
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
              <Label>JWS compact token</Label>
              <Button type="button" variant="ghost" size="sm" onClick={() => void copy()}>
                <Copy /> Copy
              </Button>
            </div>
            <Textarea readOnly rows={5} value={token} className="font-mono text-xs break-all" />
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function VerifyForm({
  onError,
}: {
  onError: (message: string, cliMissing: boolean) => void;
}) {
  const [token, setToken] = useState("");
  const [keysFile, setKeysFile] = useState(".agentguard/delegate.pub");
  const [result, setResult] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const res = await fetch("/api/verify", {
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
      toast.error("Network error while verifying token");
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
            <Label>Verified claims</Label>
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

function splitList(value: string): string[] {
  return value
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}
