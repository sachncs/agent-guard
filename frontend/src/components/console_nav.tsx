"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ChevronDown } from "lucide-react";
import type { SessionClaims } from "@/lib/auth/session";
import { Badge } from "@/components/ui/badge";
import { Brand } from "@/components/brand";
import { ThemeToggle } from "@/components/theme_toggle";

const links = [
  { href: "/", label: "Dashboard" },
  { href: "/simulator", label: "Policy Simulator" },
  { href: "/delegation", label: "Delegation" },
];

export function ConsoleNav({ user }: { user: SessionClaims | null }) {
  const pathname = usePathname();
  return (
    <header className="console-header border-b">
      <div className="mx-auto flex min-h-16 max-w-7xl items-center gap-3 px-4 sm:gap-5 sm:px-6">
        <Brand />
        <nav className="hidden items-center gap-1 text-sm sm:flex" aria-label="Console navigation">
          <NavigationLinks pathname={pathname} />
        </nav>
        <details className="group relative sm:hidden">
          <summary className="flex min-h-9 cursor-pointer list-none items-center gap-1 rounded-md px-3 text-sm text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring [&::-webkit-details-marker]:hidden">
            Menu
            <ChevronDown aria-hidden="true" className="size-4 transition-transform group-open:rotate-180" />
          </summary>
          <nav
            aria-label="Mobile console navigation"
            className="absolute left-0 top-full z-50 mt-2 grid min-w-52 gap-1 rounded-xl border bg-popover p-2 text-sm text-popover-foreground shadow-xl"
          >
            <NavigationLinks pathname={pathname} />
          </nav>
        </details>
        {user && (
          <div className="ml-auto flex items-center gap-3 text-sm">
            <span className="hidden text-muted-foreground md:inline">
              {user.email ?? user.name ?? user.sub}
            </span>
            <Badge variant={user.admin ? "default" : "outline"}>{user.admin ? "admin" : "viewer"}</Badge>
            <form action="/api/auth/logout" method="post">
              <button
                type="submit"
                className="rounded-md px-2 py-1 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
              >
                Sign out
              </button>
            </form>
          </div>
        )}
        <div className={user ? undefined : "ml-auto"}>
          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}

function NavigationLinks({ pathname }: { pathname: string }) {
  return (
    <>
      {links.map((link) => {
        const active = pathname === link.href;
        return (
          <Link
            key={link.href}
            href={link.href}
            aria-current={active ? "page" : undefined}
            className={`rounded-md px-3 py-2 transition-colors ${
              active
                ? "bg-primary text-primary-foreground shadow-sm"
                : "text-muted-foreground hover:bg-accent hover:text-foreground"
            }`}
          >
            {link.label}
          </Link>
        );
      })}
    </>
  );
}
