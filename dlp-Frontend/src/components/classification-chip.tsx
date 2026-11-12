import { DATA_TYPES, DATA_TYPE_LABELS } from "@/lib/dlp";
import { cn } from "@/lib/utils";

const isKnownClassification = (
  classification: string | null | undefined,
): classification is (typeof DATA_TYPES)[number] =>
  typeof classification === "string" &&
  DATA_TYPES.includes(classification as (typeof DATA_TYPES)[number]);

function toHumanLabel(value: string | null | undefined) {
  if (!value) return "Unknown";

  const normalized = value.trim();
  if (isKnownClassification(normalized)) {
    return DATA_TYPE_LABELS[normalized] ?? normalized;
  }

  return (
    normalized
      .replace(/[_-]+/g, " ")
      .replace(/\s+/g, " ")
      .split(" ")
      .filter(Boolean)
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
      .join(" ") || "Unknown"
  );
}

export function ClassificationChip({
  classification,
  className,
}: {
  classification: string | null | undefined;
  className?: string;
}) {
  const label = toHumanLabel(classification);

  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border border-border bg-muted/60 px-2 py-0.5 text-[11px] font-medium text-foreground",
        className,
      )}
      aria-label={`Classification: ${label}`}
      title={label}
    >
      {label}
    </span>
  );
}
