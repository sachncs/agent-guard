"use client";

import { Laptop, Moon, Sun } from "lucide-react";
import { useTheme } from "next-themes";
import { Button } from "@/components/ui/button";

export function ThemeToggle() {
  const { setTheme } = useTheme();

  return (
    <Button
      type="button"
      variant="ghost"
      size="icon"
      aria-label="Toggle color theme"
      title="Toggle color theme"
      onClick={() => {
        const currentTheme = document.documentElement.classList.contains("dark")
          ? "dark"
          : "light";
        setTheme(currentTheme === "dark" ? "light" : "dark");
      }}
    >
      <Sun className="size-4 dark:hidden" aria-hidden="true" />
      <Moon className="hidden size-4 dark:block" aria-hidden="true" />
      <span className="sr-only">Toggle color theme</span>
    </Button>
  );
}

export function SystemThemeButton() {
  const { setTheme } = useTheme();
  return (
    <Button
      type="button"
      variant="ghost"
      size="icon"
      aria-label="Use system color mode"
      title="Use system color mode"
      onClick={() => setTheme("system")}
    >
      <Laptop className="size-4" aria-hidden="true" />
    </Button>
  );
}
