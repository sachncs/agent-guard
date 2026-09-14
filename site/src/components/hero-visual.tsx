"use client";

import * as React from "react";
import { motion, AnimatePresence } from "motion/react";
import { Check, X, ArrowRight } from "lucide-react";
import { cn } from "@/lib/utils";

type Step = "request" | "evaluate" | "decision";

const requests = [
  {
    principal: 'Agent::"research"',
    action: 'ToolCall::send_email',
    resource: 'Mailbox::"alice@acme"',
    context: { session: { mfa: true }, args: { to: "bob@acme.dev" } },
  },
  {
    principal: 'Agent::"summarizer"',
    action: 'ToolCall::read_doc',
    resource: 'Doc::"Q4-plan"',
    context: { session: { mfa: true } },
  },
  {
    principal: 'Agent::"untrusted"',
    action: 'ToolCall::delete_db',
    resource: 'Database::*',
    context: { session: { mfa: false } },
  },
];

const decisions = [
  { allow: true, reason: "policy: 20_agents.cedar — scoped subset matches" },
  { allow: true, reason: "policy: 30_read.cedar — read_doc is permitted" },
  { allow: false, reason: "deny: 90_default — privileged action outside scope" },
];

export function HeroVisual() {
  const [index, setIndex] = React.useState(0);
  const [step, setStep] = React.useState<Step>("request");

  React.useEffect(() => {
    const cycle = setInterval(() => {
      setStep((s) => {
        if (s === "request") return "evaluate";
        if (s === "evaluate") return "decision";
        setIndex((i) => (i + 1) % requests.length);
        return "request";
      });
    }, 1400);
    return () => clearInterval(cycle);
  }, []);

  const req = requests[index];
  const dec = decisions[index];

  return (
    <div className="relative isolate w-full max-w-xl">
      <div className="surface relative overflow-hidden rounded-3xl p-1 shadow-[var(--shadow-elevated)]">
        <div className="rounded-[20px] bg-[var(--bg-inset)] p-6">
          <div className="mb-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="flex size-6 items-center justify-center rounded-md bg-[var(--accent)]/12">
                <div className="size-1.5 rounded-full bg-[var(--accent)]" />
              </div>
              <span className="font-mono text-xs text-[var(--fg-muted)]">
                agentguard · authz.evaluate
              </span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="size-2 rounded-full bg-emerald-500/80" />
              <span className="font-mono text-[10px] uppercase tracking-wider text-[var(--fg-subtle)]">
                live
              </span>
            </div>
          </div>

          <div className="relative min-h-[280px]">
            <AnimatePresence mode="wait">
              {step === "request" && (
                <motion.div
                  key={`r-${index}`}
                  initial={{ opacity: 0, y: 12 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -12 }}
                  transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
                  className="space-y-3"
                >
                  <div className="font-mono text-[10px] uppercase tracking-wider text-[var(--fg-subtle)]">
                    Request
                  </div>
                  <Row label="principal" value={req.principal} />
                  <Row label="action" value={req.action} />
                  <Row label="resource" value={req.resource} />
                  <Row label="context" value={JSON.stringify(req.context)} truncate />
                </motion.div>
              )}

              {step === "evaluate" && (
                <motion.div
                  key={`e-${index}`}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.3 }}
                  className="flex h-full flex-col items-center justify-center gap-4 py-10"
                >
                  <motion.div
                    animate={{ rotate: 360 }}
                    transition={{ duration: 1.2, repeat: Infinity, ease: "linear" }}
                    className="relative size-14"
                  >
                    <div className="absolute inset-0 rounded-full border-2 border-[var(--border)]" />
                    <div className="absolute inset-0 animate-spin rounded-full border-2 border-transparent border-t-[var(--accent)] border-r-[var(--accent)]" />
                  </motion.div>
                  <div className="space-y-1 text-center">
                    <div className="font-mono text-[10px] uppercase tracking-wider text-[var(--fg-subtle)]">
                      Evaluating
                    </div>
                    <div className="font-mono text-xs text-[var(--fg-muted)]">
                      Cedar 4.x · 12 policies
                    </div>
                  </div>
                </motion.div>
              )}

              {step === "decision" && (
                <motion.div
                  key={`d-${index}`}
                  initial={{ opacity: 0, scale: 0.96 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.96 }}
                  transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
                  className="space-y-3"
                >
                  <div className="flex items-center justify-between">
                    <div className="font-mono text-[10px] uppercase tracking-wider text-[var(--fg-subtle)]">
                      Decision
                    </div>
                    <div
                      className={cn(
                        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium",
                        dec.allow
                          ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                          : "border-rose-500/30 bg-rose-500/10 text-rose-600 dark:text-rose-400",
                      )}
                    >
                      {dec.allow ? <Check className="size-3" /> : <X className="size-3" />}
                      {dec.allow ? "Allow" : "Deny"}
                    </div>
                  </div>
                  <div className="font-mono text-xs leading-relaxed text-[var(--fg-muted)]">
                    {dec.reason}
                  </div>
                  <div className="flex items-center gap-2 border-t border-[var(--border)] pt-3 font-mono text-[10px] text-[var(--fg-subtle)]">
                    <span>decision_id</span>
                    <span className="rounded bg-[var(--bg)] px-1.5 py-0.5 text-[var(--fg-muted)]">
                      0x9f4a · {Math.random().toString(36).slice(2, 10)}
                    </span>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          <div className="mt-4 flex items-center justify-between border-t border-[var(--border)] pt-3 font-mono text-[10px] text-[var(--fg-subtle)]">
            <div className="flex items-center gap-2">
              <ArrowRight className="size-3" />
              <span>hash-chained · append-only</span>
            </div>
            <div className="flex gap-1">
              {requests.map((_, i) => (
                <div
                  key={i}
                  className={cn(
                    "size-1 rounded-full transition-colors",
                    i === index ? "bg-[var(--accent)]" : "bg-[var(--border-strong)]",
                  )}
                />
              ))}
            </div>
          </div>
        </div>
      </div>
      <div className="pointer-events-none absolute -inset-x-12 -inset-y-8 -z-10 bg-[var(--gradient-glow)] opacity-60" />
    </div>
  );
}

function Row({
  label,
  value,
  truncate,
}: {
  label: string;
  value: string;
  truncate?: boolean;
}) {
  return (
    <div className="grid grid-cols-[80px_1fr] items-baseline gap-3 border-b border-[var(--border)] py-1.5 font-mono text-xs last:border-b-0">
      <span className="text-[10px] uppercase tracking-wider text-[var(--fg-subtle)]">
        {label}
      </span>
      <span
        className={cn(
          "text-[var(--fg)]",
          truncate && "truncate",
        )}
      >
        {value}
      </span>
    </div>
  );
}
