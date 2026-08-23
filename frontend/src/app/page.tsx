"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { RefreshCw } from "lucide-react";
import type { LogRecord } from "@/lib/api-types";
import {
  errorResponseSchema,
  logResponseSchema,
} from "@/lib/api-schemas";
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { toast } from "sonner";

const REFRESH_MS = 10_000;

export default function DashboardPage() {
  const [records, setRecords] = useState<LogRecord[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [cliMissing, setCliMissing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [principalFilter, setPrincipalFilter] = useState("");
  const [actionFilter, setActionFilter] = useState("");
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  const load = useCallback(
    async (p = principalFilter, a = actionFilter) => {
      try {
        const qs = new URLSearchParams({ n: "100" });
        if (p) qs.set("principal", p);
        if (a) qs.set("action", a);
        const res = await fetchApi(`/api/log?${qs}`);
        const body: unknown = await res.json();
        if (!res.ok) {
          const err = errorResponseSchema.safeParse(body);
          setError(
            err.success && err.data.error ? err.data.error : "failed to load audit log"
          );
          setCliMissing(err.success && err.data.kind === "cli_unavailable");
          return;
        }
        const ok = logResponseSchema.safeParse(body);
        if (!ok.success) {
          setError("audit log returned an unexpected payload");
          return;
        }
        setRecords(ok.data.records);
        setError(null);
        setCliMissing(false);
      } catch {
        toast.error("Network error while loading the audit log");
      } finally {
        setLoading(false);
      }
    },
    [principalFilter, actionFilter]
  );

  useEffect(() => {
    // Initial fetch on mount; state updates happen after await inside load().
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function refetch(e?: React.FormEvent) {
    e?.preventDefault();
    setBusy(true);
    void load(principalFilter, actionFilter).finally(() => setBusy(false));
  }

  useEffect(() => {
    if (!autoRefresh) return;
    timer.current = setInterval(() => void load(), REFRESH_MS);
    return () => {
      if (timer.current) clearInterval(timer.current);
    };
  }, [autoRefresh, load]);

  const allowed = records.filter((r) => r.effect === "allow").length;
  const denied = records.length - allowed;

  function applyFilters(e: React.FormEvent) {
    refetch(e);
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
        <p className="text-muted-foreground text-sm">
          Hash-chained audit log — every authorization decision, newest first.
        </p>
      </div>

      {cliMissing && error && <CliAlert message={error} />}

      <div className="grid gap-4 sm:grid-cols-3">
        <StatCard title="Decisions" value={records.length} />
        <StatCard title="Allowed" value={allowed} tone="allow" />
        <StatCard title="Denied" value={denied} tone="deny" />
      </div>

      <form onSubmit={applyFilters} className="flex flex-wrap items-end gap-3">
        <div className="space-y-1.5">
          <Label htmlFor="f-principal">Principal</Label>
          <Input
            id="f-principal"
            placeholder="alice"
            className="w-44 font-mono"
            value={principalFilter}
            onChange={(e) => setPrincipalFilter(e.target.value)}
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="f-action">Action</Label>
          <Input
            id="f-action"
            placeholder="send_email"
            className="w-44 font-mono"
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
          />
        </div>
        <Button type="submit" variant="outline" disabled={busy}>
          Filter
        </Button>
        <Button
          type="button"
          variant="ghost"
          disabled={busy}
          onClick={() => refetch()}
        >
          <RefreshCw className={busy ? "animate-spin" : undefined} />
          Refresh
        </Button>
        <Button
          type="button"
          variant={autoRefresh ? "secondary" : "ghost"}
          onClick={() => setAutoRefresh((v) => !v)}
        >
          Auto-refresh {autoRefresh ? "on" : "off"}
        </Button>
      </form>

      <Card>
        <CardContent className="px-0">
          {records.length === 0 && !loading && !error ? (
            <p className="text-muted-foreground px-6 py-10 text-center text-sm">
              No decisions recorded yet. Run the Policy Simulator to generate
              some.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="pl-6">Time</TableHead>
                  <TableHead>Effect</TableHead>
                  <TableHead>Principal</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Resource</TableHead>
                  <TableHead className="pr-6">Reasons</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {records.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell className="pl-6 font-mono text-xs">
                      {formatTime(r.timestamp)}
                    </TableCell>
                    <TableCell>
                      <EffectBadge effect={r.effect} />
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {r.principal}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {r.action}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {r.resource}
                    </TableCell>
                    <TableCell className="max-w-[24rem] truncate pr-6 text-muted-foreground text-xs">
                      {(r.reasons ?? []).join("; ")}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function StatCard({
  title,
  value,
  tone,
}: {
  title: string;
  value: number;
  tone?: "allow" | "deny";
}) {
  return (
    <Card>
      <CardHeader>
        <CardDescription>{title}</CardDescription>
        <CardTitle
          className={
            tone === "allow"
              ? "text-green-600 dark:text-green-400"
              : tone === "deny"
                ? "text-red-600 dark:text-red-400"
                : undefined
          }
        >
          {value}
        </CardTitle>
      </CardHeader>
    </Card>
  );
}

function EffectBadge({ effect }: { effect: string }) {
  const allow = effect === "allow";
  return (
    <Badge
      variant={allow ? "outline" : "destructive"}
      className={allow ? "border-green-600 text-green-600 dark:text-green-400" : undefined}
    >
      {effect.toUpperCase()}
    </Badge>
  );
}

function formatTime(ts: string): string {
  try {
    return new Date(ts).toLocaleTimeString();
  } catch {
    return ts;
  }
}
