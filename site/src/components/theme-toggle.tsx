"use client";

import * as React from "react";
import { Moon, Sun } from "lucide-react";
import { cn } from "@/lib/utils";

export function ThemeToggle({ className }: { className?: string }) {
  const [theme, setTheme] = React.useState<"light" | "dark">("light");
  const [mounted, setMounted] = React.useState(false);

  React.useEffect(() => {
    const current = document.documentElement.classList.contains("dark") ? "dark" : "light";
    setTheme(current);
    setMounted(true);
  }, []);

  const toggle = React.useCallback(() => {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    if (document.startViewTransition) {
      document.startViewTransition(() => {
        document.documentElement.classList.toggle("dark", next === "dark");
        document.documentElement.dataset.theme = next;
      });
    } else {
      document.documentElement.classList.toggle("dark", next === "dark");
      document.documentElement.dataset.theme = next;
    }
    try {
      localStorage.setItem("theme", next);
    } catch {}
  }, [theme]);

  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={mounted ? `Switch to ${theme === "dark" ? "light" : "dark"} mode` : "Toggle theme"}
      className={cn(
        "inline-flex size-9 items-center justify-center rounded-full border border-[var(--border)] bg-[var(--bg-inset)] text-[var(--fg-muted)] transition-all hover:border-[var(--border-strong)] hover:text-[var(--fg)]",
        className,
      )}
    >
      <Sun
        className={cn(
          "size-4 transition-all",
          mounted && theme === "dark" ? "-rotate-90 scale-0" : "rotate-0 scale-100",
        )}
      />
      <Moon
        className={cn(
          "absolute size-4 transition-all",
          mounted && theme === "dark" ? "rotate-0 scale-100" : "rotate-90 scale-0",
        )}
      />
    </button>
  );
}
