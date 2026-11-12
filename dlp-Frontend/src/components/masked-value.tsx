import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { redact } from "@/lib/dlp";
import { cn } from "@/lib/utils";

export function MaskedValue({
  value,
  className,
  maxLength = 24,
  fallback = "Hidden",
}: {
  value: string | null | undefined;
  className?: string;
  maxLength?: number;
  fallback?: string;
}) {
  const rawText = typeof value === "string" ? value.trim() : "";
  const redactedValue = redact(rawText) || fallback;
  const displayValue =
    redactedValue.length > maxLength
      ? `${redactedValue.slice(0, Math.max(8, maxLength - 1)).trimEnd()}…`
      : redactedValue;

  const trigger = (
    <span
      className={cn(
        "inline-block max-w-full truncate font-mono text-[11px] text-muted-foreground",
        className,
      )}
      aria-label="Sensitive value redacted"
    >
      {displayValue}
    </span>
  );

  if (redactedValue === fallback || redactedValue.length <= maxLength) {
    return trigger;
  }

  return (
    <TooltipProvider delayDuration={100}>
      <Tooltip>
        <TooltipTrigger asChild>{trigger}</TooltipTrigger>
        <TooltipContent side="top" className="max-w-xs">
          Sensitive value redacted
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
