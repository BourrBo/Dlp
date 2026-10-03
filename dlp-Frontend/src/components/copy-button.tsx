import { Check, Copy } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export function CopyButton({
  value,
  label = "Copy",
  className,
  size = "sm",
}: {
  value: string | null | undefined;
  label?: string;
  className?: string;
  size?: "default" | "sm" | "lg" | "icon";
}) {
  const [copied, setCopied] = useState(false);

  const copyToClipboard = async () => {
    const safeValue = typeof value === "string" ? value : "";

    if (!safeValue.trim()) {
      toast.error("Nothing to copy");
      return;
    }

    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(safeValue);
      } else if (typeof document !== "undefined") {
        const helper = document.createElement("textarea");
        helper.value = safeValue;
        helper.setAttribute("readonly", "true");
        helper.style.position = "fixed";
        helper.style.top = "-9999px";
        document.body.appendChild(helper);
        helper.select();
        const didCopy = document.execCommand("copy");
        document.body.removeChild(helper);
        if (!didCopy) throw new Error("Copy command failed");
      } else {
        throw new Error("Clipboard API unavailable");
      }

      setCopied(true);
      toast.success("Copied to clipboard");
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      toast.error("Unable to copy to clipboard");
    }
  };

  return (
    <Button
      type="button"
      variant="outline"
      size={size}
      className={cn("gap-2", className)}
      onClick={copyToClipboard}
      aria-live="polite"
    >
      {copied ? (
        <Check className="size-4" aria-hidden="true" />
      ) : (
        <Copy className="size-4" aria-hidden="true" />
      )}
      <span>{copied ? "Copied" : label}</span>
    </Button>
  );
}
