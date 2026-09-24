import Link from "next/link";
import { ArrowUpRight, ClipboardCheck, FlaskConical, ScrollText } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
} from "@/components/ui/card";

const steps = [
  {
    number: "01",
    title: "Simulate a tool call",
    description: "Try a safe request and see which policy permits or denies it.",
    icon: FlaskConical,
  },
  {
    number: "02",
    title: "Inspect the audit record",
    description: "Return here to review the decision, principal, action, and resource.",
    icon: ScrollText,
    href: "#audit-log",
  },
  {
    number: "03",
    title: "Validate a Cedar policy",
    description: "Learn how to make a narrow change and check it before activation.",
    icon: ClipboardCheck,
  },
];

export function GettingStarted() {
  return (
    <Card className="border-brand-200 bg-brand-50/60 dark:border-brand-900 dark:bg-brand-950/30">
      <CardHeader className="pb-3">
        <h2 className="font-heading text-base leading-snug font-medium">Getting started</h2>
        <CardDescription>
          Follow one request from simulation to policy review. The console does not execute tools.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <ol className="grid gap-4 md:grid-cols-3">
          {steps.map(({ number, title, description, icon: Icon, href }) => (
            <li key={number} className="flex gap-3">
              <span className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-background text-brand-700 ring-1 ring-border dark:text-brand-300">
                <Icon aria-hidden="true" className="size-4" />
              </span>
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-brand-700 dark:text-brand-300">
                  {number} / {href ? (
                    <Link className="underline-offset-4 hover:underline" href={href}>
                      {title}
                    </Link>
                  ) : title}
                </p>
                <p className="mt-1 text-sm text-muted-foreground">{description}</p>
              </div>
            </li>
          ))}
        </ol>
        <div className="flex flex-wrap items-center gap-3">
          <Button asChild>
            <Link href="/simulator">Try a policy request</Link>
          </Button>
          <Link
            href="https://sachncs.github.io/agent-guard/docs/policy-authoring/"
            target="_blank"
            rel="noreferrer"
            className="inline-flex min-h-10 items-center gap-1 rounded-md px-3 text-sm text-muted-foreground underline-offset-4 hover:text-foreground hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
          >
            Policy authoring guide <ArrowUpRight aria-hidden="true" className="size-4" />
          </Link>
        </div>
      </CardContent>
    </Card>
  );
}
