import * as React from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-full text-sm font-medium transition-all duration-200 disabled:pointer-events-none disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--bg)] select-none [&_svg]:size-4 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        primary:
          "bg-[var(--accent)] text-[var(--accent-fg)] hover:brightness-110 active:brightness-95 shadow-[var(--shadow-cedar)]",
        secondary:
          "bg-[var(--bg-inset)] text-[var(--fg)] border border-[var(--border)] hover:border-[var(--border-strong)] hover:bg-[var(--bg-elevated)]",
        ghost:
          "bg-transparent text-[var(--fg)] hover:bg-[var(--bg-inset)] border border-transparent",
        outline:
          "bg-transparent text-[var(--fg)] border border-[var(--border)] hover:border-[var(--border-strong)] hover:bg-[var(--bg-inset)]",
        link: "text-[var(--fg)] underline-offset-4 hover:underline rounded-none",
      },
      size: {
        sm: "h-9 px-4 text-xs",
        md: "h-10 px-5",
        lg: "h-12 px-7 text-base",
        icon: "size-10",
      },
    },
    defaultVariants: {
      variant: "primary",
      size: "md",
    },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return (
      <Comp
        className={cn(buttonVariants({ variant, size }), className)}
        ref={ref}
        {...props}
      />
    );
  },
);
Button.displayName = "Button";

export { Button, buttonVariants };
