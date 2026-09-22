"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { SessionClaims } from "@/lib/auth/session";
import { Badge } from "@/components/ui/badge";
import { Brand } from "@/components/brand";

const links = [
  { href: "/", label: "Dashboard" },
  { href: "/simulator", label: "Policy Simulator" },
  { href: "/delegation", label: "Delegation" },
];

export function ConsoleNav({ user }: { user: SessionClaims | null }) {
  const pathname = usePathname();
  return (
    <header className="console-header border-b">
      <div className="mx-auto flex min-h-16 max-w-7xl items-center gap-5 px-4 sm:px-6">
        <Brand />
        <nav className="flex items-center gap-1 text-sm" aria-label="Console navigation">
          {links.map((link) => {
            const active = pathname === link.href;
            return (
              <Link
                key={link.href}
                href={link.href}
                aria-current={active ? "page" : undefined}
                className={`rounded-md px-3 py-1.5 transition-colors ${
                  active
                    ? "bg-primary text-primary-foreground shadow-sm"
                    : "text-muted-foreground hover:bg-accent hover:text-foreground"
                }`}
              >
                {link.label}
              </Link>
            );
          })}
        </nav>
        {user && (
          <div className="ml-auto flex items-center gap-3 text-sm">
            <span className="hidden text-muted-foreground md:inline">
              {user.email ?? user.name ?? user.sub}
            </span>
            <Badge variant={user.admin ? "default" : "outline"}>{user.admin ? "admin" : "viewer"}</Badge>
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
