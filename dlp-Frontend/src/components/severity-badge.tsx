import { cn } from "@/lib/utils";

export type Severity = "low" | "medium" | "high" | "critical";

const SEVERITY_LABELS: Record<Severity, string> = {
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};

const SEVERITY_STYLES: Record<Severity, string> = {
  low: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  medium: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  high: "border-orange-500/30 bg-orange-500/10 text-orange-700 dark:text-orange-300",
  critical: "border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-300",
};

export function SeverityBadge({
  severity,
  className,
}: {
  severity: Severity | string | null | undefined;
  className?: string;
}) {
  const safeSeverity = (severity ?? "medium") as Severity;
  const label = SEVERITY_LABELS[safeSeverity] ?? SEVERITY_LABELS.medium;

  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold tracking-[0.08em] uppercase",
        SEVERITY_STYLES[safeSeverity] ?? SEVERITY_STYLES.medium,
        className,
      )}
      role="status"
      aria-label={`Severity: ${label}`}
    >
      {label}
    </span>
  );
}
