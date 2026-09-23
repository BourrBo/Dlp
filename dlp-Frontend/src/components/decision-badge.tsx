import { cn } from "@/lib/utils";
import { DECISION_LABELS } from "@/lib/dlp";

const STYLES: Record<string, string> = {
  allow: "border-allow/35 text-allow bg-allow/10",
  warn: "border-warn/35 text-warn bg-warn/10",
  block: "border-block/40 text-block bg-block/10",
  log: "border-log/30 text-log bg-log/10",
};

export function DecisionBadge({ decision, className }: { decision: string; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium",
        STYLES[decision] ?? STYLES["log"],
        className,
      )}
    >
      <span className="size-1.5 rounded-full bg-current" />
      {DECISION_LABELS[decision] ?? decision}
    </span>
  );
}
