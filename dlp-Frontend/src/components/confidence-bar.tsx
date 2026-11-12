import { cn } from "@/lib/utils";

export function ConfidenceBar({
  confidence,
  className,
}: {
  confidence: number;
  className?: string;
}) {
  const normalizedConfidence = Number.isFinite(confidence) ? confidence : 0;
  const clamped = Math.min(1, Math.max(0, normalizedConfidence));
  const percent = Math.round(clamped * 100);
  const tone = percent >= 80 ? "bg-emerald-500" : percent >= 50 ? "bg-amber-500" : "bg-sky-500";

  return (
    <div className={cn("flex items-center gap-2", className)}>
      <div
        className="relative h-2 w-16 overflow-hidden rounded-full bg-muted"
        role="progressbar"
        aria-label={`Confidence: ${percent}%`}
        aria-valuenow={percent}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        <div
          className={cn("h-full rounded-full transition-all", tone)}
          style={{ width: `${percent}%` }}
          aria-hidden="true"
        />
      </div>
      <span className="text-[11px] font-medium tabular-nums text-muted-foreground">{percent}%</span>
    </div>
  );
}
