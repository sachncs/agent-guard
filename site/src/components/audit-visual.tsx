"use client";

import * as React from "react";
import { motion } from "motion/react";
import { cn } from "@/lib/utils";

type Record = {
  id: string;
  decision: "allow" | "deny";
  principal: string;
  action: string;
  hash: string;
};

const records: Record[] = [
  { id: "0x9f4a", decision: "allow", principal: 'Agent::"research"', action: "send_email", hash: "0xa3b8" },
  { id: "0x9f4b", decision: "allow", principal: 'Agent::"summarizer"', action: "read_doc", hash: "0x71c2" },
  { id: "0x9f4c", decision: "deny", principal: 'Agent::"untrusted"', action: "delete_db", hash: "0x4e8f" },
  { id: "0x9f4d", decision: "allow", principal: 'User::"alice"', action: "send_email", hash: "0x8d12" },
  { id: "0x9f4e", decision: "allow", principal: 'Agent::"research"', action: "search", hash: "0x33aa" },
];

const formats = [
  { name: "ECS", desc: "Elastic Common Schema" },
  { name: "CEF", desc: "ArcSight Common Event Format" },
  { name: "LEEF", desc: "IBM QRadar Log Event Extended Format" },
  { name: "JSONL", desc: "Line-delimited, custom schemas" },
];

export function AuditVisual() {
  const [tick, setTick] = React.useState(0);

  React.useEffect(() => {
    const id = setInterval(() => setTick((t) => (t + 1) % records.length), 1800);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="grid gap-6 lg:grid-cols-[1.6fr_1fr]">
      <div className="surface relative overflow-hidden rounded-2xl p-1">
        <div className="rounded-[14px] bg-[var(--bg-inset)] p-6">
          <div className="mb-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs uppercase tracking-wider text-[var(--fg-subtle)]">
                .audit/decisions.jsonl
              </span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="size-1.5 animate-pulse rounded-full bg-emerald-500" />
              <span className="font-mono text-[10px] uppercase tracking-wider text-[var(--fg-subtle)]">
                append-only
              </span>
            </div>
          </div>

          <div className="space-y-1.5">
            {records.map((r, i) => {
              const active = i === tick;
              const past = i < tick;
              return (
                <motion.div
                  key={r.id}
                  initial={false}
                  animate={{
                    opacity: past ? 0.55 : 1,
                    backgroundColor: active
                      ? "color-mix(in oklab, var(--accent) 8%, transparent)"
                      : "transparent",
                  }}
                  transition={{ duration: 0.4 }}
                  className="grid grid-cols-[auto_1fr_auto_auto] items-center gap-3 rounded-md border border-transparent px-3 py-2 font-mono text-[11.5px]"
                  style={{
                    borderColor: active ? "color-mix(in oklab, var(--accent) 28%, transparent)" : undefined,
                  }}
                >
                  <span className="text-[var(--fg-subtle)]">{r.id}</span>
                  <span className="truncate text-[var(--fg-muted)]">
                    <span className="text-[var(--fg-subtle)]">principal=</span>
                    {r.principal}
                    <span className="text-[var(--fg-subtle)]"> action=</span>
                    {r.action}
                  </span>
                  <span
                    className={cn(
                      "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[9px] font-medium uppercase tracking-wider",
                      r.decision === "allow"
                        ? "border-emerald-500/30 bg-emerald-500/8 text-emerald-600 dark:text-emerald-400"
                        : "border-rose-500/30 bg-rose-500/8 text-rose-600 dark:text-rose-400",
                    )}
                  >
                    {r.decision}
                  </span>
                  <span className="text-[var(--fg-subtle)]">↳ {r.hash}</span>
                </motion.div>
              );
            })}
          </div>

          <div className="mt-4 flex items-center justify-between border-t border-[var(--border)] pt-3 font-mono text-[10px] text-[var(--fg-subtle)]">
            <span>5 records · chain head 0xa3b8…</span>
            <span>HMAC-SHA-256</span>
          </div>
        </div>
      </div>

      <div className="flex flex-col gap-6">
        <div className="surface-inset rounded-2xl p-6">
          <div className="mb-4 flex items-center gap-2">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              className="size-4 text-[var(--accent)]"
            >
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
            <span className="font-mono text-xs uppercase tracking-wider text-[var(--fg-subtle)]">
              Verify the chain
            </span>
          </div>
          <pre className="overflow-x-auto rounded-lg border border-[var(--border)] bg-[var(--bg)] p-3 font-mono text-[11px] leading-relaxed text-[var(--fg-muted)]">
{`agentguard audit verify \\
  --audit .audit/decisions.jsonl \\
  --secret-file .chain-secret
# ✓ chain integrity verified
#   12,481 records · head 0xa3b8…`}
          </pre>
        </div>

        <div className="surface-inset rounded-2xl p-6">
          <div className="mb-4 flex items-center gap-2">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              className="size-4 text-[var(--accent)]"
            >
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3" />
            </svg>
            <span className="font-mono text-xs uppercase tracking-wider text-[var(--fg-subtle)]">
              Export
            </span>
          </div>
          <div className="grid grid-cols-2 gap-2">
            {formats.map((f) => (
              <div
                key={f.name}
                className="rounded-lg border border-[var(--border)] bg-[var(--bg)] p-3 transition-colors hover:border-[var(--border-strong)]"
              >
                <div className="font-mono text-xs font-medium">{f.name}</div>
                <div className="mt-0.5 text-[10px] leading-snug text-[var(--fg-subtle)]">
                  {f.desc}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
