"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { SessionClaims } from "@/lib/auth/session";
import { Badge } from "@/components/ui/badge";

const links = [
  { href: "/", label: "Dashboard" },
  { href: "/simulator", label: "Policy Simulator" },
  { href: "/delegation", label: "Delegation" },
];

export function ConsoleNav({ user }: { user: SessionClaims | null }) {
  const pathname = usePathname();
  return (
    <header className="border-b">
      <div className="mx-auto flex h-14 max-w-6xl items-center gap-8 px-6">
        <Link href="/" className="font-mono text-sm font-bold tracking-tight">
          agentguard<span className="text-muted-foreground">_console</span>
        </Link>
        <nav className="flex items-center gap-1 text-sm">
          {links.map((link) => {
            const active = pathname === link.href;
            return (
              <Link
                key={link.href}
                href={link.href}
                className={`rounded-md px-3 py-1.5 transition-colors ${
                  active
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:bg-muted hover:text-foreground"
                }`}
              >
                {link.label}
              </Link>
            );
          })}
        </nav>
        {user && (
          <div className="ml-auto flex items-center gap-3 text-sm">
            <span className="text-muted-foreground">
              {user.email ?? user.name ?? user.sub}
            </span>
            {user.admin && <Badge variant="default">admin</Badge>}
            <a
              href="/api/auth/logout"
              className="rounded-md px-2 py-1 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
            >
              Sign out
            </a>
          </div>
        )}
      </div>
    </header>
  );
}
