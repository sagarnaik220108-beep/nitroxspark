"use client";

import type { ReactNode } from "react";

export type SeverityBadgeVariant =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info"
  | "fixed"
  | "blocked"
  | "compromised";

export interface SeverityBadgeProps {
  variant: SeverityBadgeVariant;
  label?: ReactNode;
  size?: "sm" | "md";
  pulse?: boolean;
  className?: string;
}

interface VariantStyle {
  pill: string;
  dot: string;
  defaultLabel: string;
}

const VARIANT_STYLES: Record<SeverityBadgeVariant, VariantStyle> = {
  critical: {
    pill: "bg-error-container/75 text-on-error-container border-error/45",
    dot: "bg-error shadow-[0_0_8px_rgba(255,179,173,0.9)]",
    defaultLabel: "Critical",
  },
  compromised: {
    pill: "bg-error-container/80 text-on-error-container border-error/50",
    dot: "bg-error shadow-[0_0_8px_rgba(255,179,173,0.95)]",
    defaultLabel: "Compromised",
  },
  high: {
    pill: "bg-warning-container/75 text-on-warning-container border-warning/45",
    dot: "bg-warning shadow-[0_0_8px_rgba(255,185,95,0.9)]",
    defaultLabel: "High",
  },
  medium: {
    pill: "bg-[#4A3B12]/75 text-[#FFE08A] border-[#FBBF24]/40",
    dot: "bg-[#FBBF24] shadow-[0_0_8px_rgba(251,191,36,0.85)]",
    defaultLabel: "Medium",
  },
  low: {
    pill: "bg-secondary-container/35 text-secondary border-secondary/35",
    dot: "bg-secondary shadow-[0_0_8px_rgba(173,198,255,0.85)]",
    defaultLabel: "Low",
  },
  info: {
    pill: "bg-surface-container-high/85 text-primary border-primary/35",
    dot: "bg-primary shadow-[0_0_8px_rgba(138,235,255,0.85)]",
    defaultLabel: "Info",
  },
  fixed: {
    pill: "bg-success-container/75 text-on-success-container border-success/45",
    dot: "bg-success shadow-[0_0_8px_rgba(78,222,163,0.9)]",
    defaultLabel: "Fixed",
  },
  blocked: {
    pill: "bg-success-container/80 text-on-success-container border-success/50",
    dot: "bg-success shadow-[0_0_8px_rgba(78,222,163,0.95)]",
    defaultLabel: "Blocked",
  },
};

export function SeverityBadge({
  variant,
  label,
  size = "sm",
  pulse = false,
  className = "",
}: SeverityBadgeProps) {
  const style = VARIANT_STYLES[variant];
  const sizeClasses =
    size === "md"
      ? "px-3 py-1 text-xs gap-2"
      : "px-2.5 py-0.5 text-[11px] gap-1.5";

  return (
    <span
      className={`inline-flex items-center rounded-full border font-label font-medium tracking-wide whitespace-nowrap select-none transition-colors duration-150 ${style.pill} ${sizeClasses} ${className}`.trim()}
    >
      <span
        aria-hidden="true"
        className={`inline-block w-1.5 h-1.5 rounded-full flex-shrink-0 ${style.dot} ${
          pulse ? "animate-pulse" : ""
        }`.trim()}
      />
      <span>{label ?? style.defaultLabel}</span>
    </span>
  );
}
