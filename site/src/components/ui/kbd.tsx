import * as React from "react";
import { cn } from "@/lib/utils";

const Kbd = React.forwardRef<
  HTMLElement,
  React.HTMLAttributes<HTMLElement> & { asChild?: boolean }
>(({ className, ...props }, ref) => (
  <kbd
    ref={ref}
    className={cn(
      "pointer-events-none inline-flex h-5 select-none items-center gap-1 rounded border border-[var(--border-strong)] bg-[var(--bg-inset)] px-1.5 font-mono text-[10px] font-medium text-[var(--fg-muted)]",
      className,
    )}
    {...props}
  />
));
Kbd.displayName = "Kbd";

export { Kbd };
