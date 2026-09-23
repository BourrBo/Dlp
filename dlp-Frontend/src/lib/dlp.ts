export const CHANNELS = ["browser", "email", "cloud_storage", "api"] as const;
export type Channel = (typeof CHANNELS)[number];

export const DECISIONS = ["allow", "warn", "block", "log"] as const;
export type Decision = (typeof DECISIONS)[number];

export const ACTIONS = ["allow", "warn", "block", "log"] as const;

export const DATA_TYPES = [
  "pii",
  "pci",
  "phi",
  "credentials",
  "source_code",
  "financials",
  "customer_list",
  "other",
] as const;

export const CHANNEL_LABELS: Record<string, string> = {
  browser: "Browser",
  email: "Email",
  cloud_storage: "Cloud storage",
  api: "API",
};

export const DATA_TYPE_LABELS: Record<string, string> = {
  pii: "PII",
  pci: "PCI",
  phi: "PHI",
  credentials: "Credentials",
  source_code: "Source code",
  financials: "Financials",
  customer_list: "Customer list",
  other: "Other",
};

export const DECISION_LABELS: Record<string, string> = {
  allow: "Allow",
  warn: "Warn",
  block: "Block",
  log: "Log",
};

/** Client-side safety net: mask anything that still looks like raw sensitive data. */
export function redact(snippet: string | null | undefined): string {
  if (!snippet) return "";
  return snippet
    .replace(/[\w.+-]+@[\w-]+\.[\w.]+/g, (m) => `${m[0]}•••@${m.split("@")[1]}`)
    .replace(/\b\d[\d -]{9,}\d\b/g, (m) => `${m.slice(0, 2)}${"•".repeat(Math.max(m.length - 6, 4))}${m.slice(-4)}`)
    .replace(/\b[A-Za-z0-9_-]{24,}\b/g, (m) => `${m.slice(0, 4)}${"•".repeat(12)}${m.slice(-4)}`);
}

export function formatDateTime(value: string): string {
  return new Date(value).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}
