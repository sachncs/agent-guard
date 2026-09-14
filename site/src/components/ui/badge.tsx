import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium tracking-wide transition-colors",
  {
    variants: {
      variant: {
        default:
          "border-[var(--border)] bg-[var(--bg-inset)] text-[var(--fg-muted)]",
        accent:
          "border-transparent bg-[var(--accent)]/12 text-[var(--accent)]",
        outline:
          "border-[var(--border-strong)] bg-transparent text-[var(--fg-muted)]",
        muted:
          "border-transparent bg-[var(--bg-inset)] text-[var(--fg-subtle)]",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}

export { Badge, badgeVariants };
