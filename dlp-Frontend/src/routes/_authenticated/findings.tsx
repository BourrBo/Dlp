import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { Search, SlidersHorizontal } from "lucide-react";

import { AppShell } from "@/components/app-shell";
import { ClassificationChip } from "@/components/classification-chip";
import { ConfidenceBar } from "@/components/confidence-bar";
import { CopyButton } from "@/components/copy-button";
import { MaskedValue } from "@/components/masked-value";
import { SeverityBadge } from "@/components/severity-badge";
import { Input } from "@/components/ui/input";

export const Route = createFileRoute("/_authenticated/findings")({
  head: () => ({
    meta: [
      { title: "Findings — DLP Console" },
      {
        name: "description",
        content: "Investigate and manage detected sensitive data.",
      },
      { property: "og:title", content: "Findings — DLP Console" },
    ],
  }),
  component: FindingsPage,
});

type FindingStatus = "open" | "triaged" | "fixed" | "accepted" | "false_positive";

type Finding = {
  id: string;
  severity: "low" | "medium" | "high" | "critical";
  classification: string;
  data_type: string;
  status: FindingStatus;
  source: string;
  detector: string;
  confidence: number;
  created_at: string;
  masked_evidence: string;
};

const FIXTURE_FINDINGS: Finding[] = [
  {
    id: "finding-01",
    severity: "critical",
    classification: "credentials",
    data_type: "api_key",
    status: "open",
    source: "Browser",
    detector: "Secret scanner",
    confidence: 0.98,
    created_at: "2026-10-06T09:42:00.000Z",
    masked_evidence: "sk_live_••••••••••••4K9Q",
  },
  {
    id: "finding-02",
    severity: "high",
    classification: "personal information",
    data_type: "national_id",
    status: "triaged",
    source: "Google Drive",
    detector: "Pattern detector",
    confidence: 0.91,
    created_at: "2026-10-06T08:26:00.000Z",
    masked_evidence: "•••-••-6789",
  },
  {
    id: "finding-03",
    severity: "medium",
    classification: "financial data",
    data_type: "credit_card",
    status: "open",
    source: "Email",
    detector: "Payment card detector",
    confidence: 0.78,
    created_at: "2026-10-05T16:14:00.000Z",
    masked_evidence: "•••• •••• •••• 4242",
  },
  {
    id: "finding-04",
    severity: "low",
    classification: "personal information",
    data_type: "email_pii",
    status: "accepted",
    source: "API",
    detector: "PII detector",
    confidence: 0.63,
    created_at: "2026-10-04T12:03:00.000Z",
    masked_evidence: "a•••••@example.com",
  },
];

const STATUS_STYLES: Record<FindingStatus, string> = {
  open: "border-sky-500/30 bg-sky-500/10 text-sky-700",
  triaged: "border-amber-500/30 bg-amber-500/10 text-amber-700",
  fixed: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700",
  accepted: "border-violet-500/30 bg-violet-500/10 text-violet-700",
  false_positive: "border-border bg-muted text-muted-foreground",
};

function FindingsPage() {
  const [search, setSearch] = useState("");
  const findings = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return FIXTURE_FINDINGS;
    return FIXTURE_FINDINGS.filter((finding) =>
      [
        finding.id,
        finding.classification,
        finding.data_type,
        finding.status,
        finding.source,
        finding.detector,
      ].some((value) => value.toLowerCase().includes(query)),
    );
  }, [search]);

  return (
    <AppShell>
      <main className="space-y-6 px-6 py-6" style={{ minHeight: "calc(100vh - 56px)" }}>
        <header>
          <h1 className="text-2xl font-bold" style={{ color: "oklch(0.15 0.015 250)" }}>
            Findings
          </h1>
          <p className="mt-1 text-sm" style={{ color: "oklch(0.52 0.018 250)" }}>
            Investigate and manage detected sensitive data.
          </p>
        </header>

        <section
          className="rounded-2xl border p-4 backdrop-blur-xl sm:p-5"
          aria-label="Finding search and filters"
          style={{
            background: "oklch(0.97 0 0 / 0.78)",
            borderColor: "oklch(1 0 0 / 0.56)",
            boxShadow: "0 4px 12px oklch(0 0 0 / 0.045), 0 10px 28px oklch(0 0 0 / 0.025)",
          }}
        >
          <div className="flex flex-col gap-3 lg:flex-row">
            <div className="relative min-w-0 flex-1">
              <Search
                className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2"
                style={{ color: "oklch(0.55 0.015 250)" }}
                aria-hidden="true"
              />
              <Input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search findings..."
                aria-label="Search findings"
                className="h-10 border-white/70 bg-white/60 pl-9"
              />
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="sr-only">
                <SlidersHorizontal aria-hidden="true" />
                Filters
              </span>
              {["All severities", "All statuses", "All sources"].map((label) => (
                <button
                  key={label}
                  type="button"
                  disabled
                  title="Filters will be available when the findings API is connected"
                  className="h-9 cursor-not-allowed rounded-md border border-input bg-white/45 px-3 text-xs text-muted-foreground opacity-70"
                >
                  {label}
                </button>
              ))}
            </div>
          </div>
          <p className="mt-3 text-xs text-muted-foreground">
            Showing temporary sample findings for the explorer preview.
          </p>
        </section>

        <section
          className="overflow-hidden rounded-2xl border backdrop-blur-xl"
          aria-label="Findings"
          style={{
            background: "oklch(0.97 0 0 / 0.78)",
            borderColor: "oklch(1 0 0 / 0.56)",
            boxShadow: "0 4px 12px oklch(0 0 0 / 0.045), 0 10px 28px oklch(0 0 0 / 0.025)",
          }}
        >
          <div className="flex items-center justify-between border-b px-5 py-4" style={{ borderColor: "oklch(0.90 0.006 250)" }}>
            <div>
              <h2 className="text-sm font-semibold" style={{ color: "oklch(0.18 0.015 250)" }}>
                Finding queue
              </h2>
              <p className="mt-0.5 text-xs text-muted-foreground">
                {findings.length} {findings.length === 1 ? "finding" : "findings"}
              </p>
            </div>
          </div>

          <div className="hidden overflow-x-auto lg:block">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b" style={{ borderColor: "oklch(0.90 0.006 250)" }}>
                  {["Severity", "Classification", "Finding", "Status", "Source / detector", "Confidence", "Detected"].map((heading) => (
                    <th key={heading} className="px-4 py-3 font-semibold text-muted-foreground first:pl-5">
                      {heading}
                    </th>
                  ))}
                  <th className="px-4 py-3 pr-5"><span className="sr-only">Copy masked evidence</span></th>
                </tr>
              </thead>
              <tbody className="divide-y" style={{ borderColor: "oklch(0.92 0.005 250)" }}>
                {findings.map((finding) => (
                  <tr key={finding.id} className="transition-colors hover:bg-white/45">
                    <td className="whitespace-nowrap px-4 py-4 pl-5">
                      <SeverityBadge severity={finding.severity} />
                    </td>
                    <td className="px-4 py-4"><ClassificationChip classification={finding.classification} /></td>
                    <td className="max-w-[260px] px-4 py-4">
                      <p className="font-medium text-foreground">{finding.data_type.replace(/[_-]+/g, " ")}</p>
                      <MaskedValue value={finding.masked_evidence} />
                    </td>
                    <td className="px-4 py-4">
                      <span className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-medium ${STATUS_STYLES[finding.status]}`}>
                        {finding.status.replace(/_/g, " ")}
                      </span>
                    </td>
                    <td className="px-4 py-4">
                      <p className="font-medium text-foreground">{finding.source}</p>
                      <p className="mt-0.5 text-muted-foreground">{finding.detector}</p>
                    </td>
                    <td className="px-4 py-4"><ConfidenceBar confidence={finding.confidence} /></td>
                    <td className="whitespace-nowrap px-4 py-4 text-muted-foreground">
                      {new Date(finding.created_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-4 pr-5">
                      <CopyButton value={finding.masked_evidence} label="Copy masked" size="sm" />
                    </td>
                  </tr>
                ))}
                {findings.length === 0 && (
                  <tr>
                    <td colSpan={8} className="px-5 py-14 text-center text-sm text-muted-foreground">
                      No findings match your search.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          <div className="space-y-3 p-4 lg:hidden">
            {findings.map((finding) => (
              <article key={finding.id} className="rounded-xl border border-border/70 bg-white/45 p-4 shadow-sm">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <SeverityBadge severity={finding.severity} />
                  <span className={`inline-flex rounded-full border px-2 py-1 text-[10px] font-medium ${STATUS_STYLES[finding.status]}`}>
                    {finding.status.replace(/_/g, " ")}
                  </span>
                </div>
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <ClassificationChip classification={finding.classification} />
                  <span className="text-xs capitalize text-muted-foreground">
                    {finding.data_type.replace(/[_-]+/g, " ")}
                  </span>
                </div>
                <div className="mt-3 flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <p className="text-xs font-medium">{finding.source} · {finding.detector}</p>
                    <div className="mt-1"><MaskedValue value={finding.masked_evidence} /></div>
                  </div>
                  <CopyButton value={finding.masked_evidence} label="Copy masked" size="sm" className="shrink-0" />
                </div>
                <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
                  <ConfidenceBar confidence={finding.confidence} />
                  <time className="text-[11px] text-muted-foreground" dateTime={finding.created_at}>
                    {new Date(finding.created_at).toLocaleString()}
                  </time>
                </div>
              </article>
            ))}
            {findings.length === 0 && (
              <p className="py-12 text-center text-sm text-muted-foreground">
                No findings match your search.
              </p>
            )}
          </div>
        </section>
      </main>
    </AppShell>
  );
}
