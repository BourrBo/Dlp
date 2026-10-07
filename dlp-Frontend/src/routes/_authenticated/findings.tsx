import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { ArrowDown, ArrowUp, Search, SlidersHorizontal } from "lucide-react";

import { AppShell } from "@/components/app-shell";
import { ClassificationChip } from "@/components/classification-chip";
import { ConfidenceBar } from "@/components/confidence-bar";
import { MaskedValue } from "@/components/masked-value";
import { SeverityBadge } from "@/components/severity-badge";
import { Input } from "@/components/ui/input";
import { FINDING_FIXTURES } from "@/lib/fixtures/findings";

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

type FindingStatus = (typeof FINDING_FIXTURES)[number]["status"];

type FindingFilterKey = "severity" | "classification" | "data_type" | "status" | "source" | "detector";
type FindingSortKey = "created_at" | "severity" | "confidence";
type SortDirection = "asc" | "desc";
type FindingSort = { key: FindingSortKey; direction: SortDirection } | null;
type FindingCursor = Pick<(typeof FINDING_FIXTURES)[number], "created_at" | "id">;

const PAGE_SIZE = 10;

const SEVERITY_ORDER: Record<(typeof FINDING_FIXTURES)[number]["severity"], number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

const FILTER_FIELDS: { key: FindingFilterKey; label: string }[] = [
  { key: "severity", label: "Severity" },
  { key: "classification", label: "Classification" },
  { key: "data_type", label: "Data type" },
  { key: "status", label: "Status" },
  { key: "source", label: "Source" },
  { key: "detector", label: "Detector" },
];

const FILTER_OPTIONS = Object.fromEntries(
  FILTER_FIELDS.map(({ key }) => [
    key,
    [...new Set(FINDING_FIXTURES.map((finding) => finding[key]))].sort(),
  ]),
) as Record<FindingFilterKey, string[]>;

const STATUS_STYLES: Record<FindingStatus, string> = {
  open: "border-sky-500/30 bg-sky-500/10 text-sky-700",
  triaged: "border-amber-500/30 bg-amber-500/10 text-amber-700",
  fixed: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700",
  accepted: "border-violet-500/30 bg-violet-500/10 text-violet-700",
  false_positive: "border-border bg-muted text-muted-foreground",
};

function FindingsPage() {
  const [search, setSearch] = useState("");
  const [filters, setFilters] = useState<Record<FindingFilterKey, string>>({
    severity: "all",
    classification: "all",
    data_type: "all",
    status: "all",
    source: "all",
    detector: "all",
  });
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [sort, setSort] = useState<FindingSort>(null);
  const [cursorHistory, setCursorHistory] = useState<(FindingCursor | null)[]>([null]);
  const filteredFindings = useMemo(() => {
    const query = search.trim().toLowerCase();
    return FINDING_FIXTURES.filter((finding) =>
      (filters.severity === "all" || finding.severity === filters.severity) &&
      (filters.classification === "all" || finding.classification === filters.classification) &&
      (filters.data_type === "all" || finding.data_type === filters.data_type) &&
      (filters.status === "all" || finding.status === filters.status) &&
      (filters.source === "all" || finding.source === filters.source) &&
      (filters.detector === "all" || finding.detector === filters.detector) &&
      (!dateFrom || finding.created_at.slice(0, 10) >= dateFrom) &&
      (!dateTo || finding.created_at.slice(0, 10) <= dateTo) &&
      (!query ||
        [
          finding.id,
          finding.classification,
          finding.data_type,
          finding.status,
          finding.source,
          finding.detector,
        ].some((value) => value.toLowerCase().includes(query))),
    );
  }, [dateFrom, dateTo, filters, search]);
  const findings = useMemo(() => {
    if (!sort) return filteredFindings;

    const direction = sort.direction === "asc" ? 1 : -1;
    return [...filteredFindings].sort((left, right) => {
      if (sort.key === "severity") {
        const leftSeverity = SEVERITY_ORDER[left.severity] ?? Number.MAX_SAFE_INTEGER;
        const rightSeverity = SEVERITY_ORDER[right.severity] ?? Number.MAX_SAFE_INTEGER;
        return (leftSeverity - rightSeverity) * direction;
      }

      if (sort.key === "confidence") {
        const leftConfidence = left.confidence;
        const rightConfidence = right.confidence;
        const leftMissing = typeof leftConfidence !== "number" || !Number.isFinite(leftConfidence);
        const rightMissing = typeof rightConfidence !== "number" || !Number.isFinite(rightConfidence);
        if (leftMissing) return rightMissing ? 0 : 1;
        if (rightMissing) return -1;
        return (leftConfidence - rightConfidence) * direction;
      }

      const leftDate = typeof left.created_at === "string" ? Date.parse(left.created_at) : Number.NaN;
      const rightDate = typeof right.created_at === "string" ? Date.parse(right.created_at) : Number.NaN;
      if (Number.isNaN(leftDate)) return Number.isNaN(rightDate) ? 0 : 1;
      if (Number.isNaN(rightDate)) return -1;
      return (leftDate - rightDate) * direction;
    });
  }, [filteredFindings, sort]);

  const cursor = cursorHistory[cursorHistory.length - 1];
  const cursorIndex = cursor
    ? findings.findIndex(
        (finding) => finding.created_at === cursor.created_at && finding.id === cursor.id,
      )
    : -1;
  const startIndex = cursorIndex < 0 ? 0 : cursorIndex + 1;
  const pageFindings = findings.slice(startIndex, startIndex + PAGE_SIZE);
  const hasPrevious = cursorHistory.length > 1;
  const hasNext = startIndex + pageFindings.length < findings.length;

  function resetCursor() {
    setCursorHistory([null]);
  }

  function loadNext() {
    const lastFinding = pageFindings[pageFindings.length - 1];
    if (!lastFinding || !hasNext) return;
    setCursorHistory((history) => [
      ...history,
      { created_at: lastFinding.created_at, id: lastFinding.id },
    ]);
  }

  function loadPrevious() {
    if (hasPrevious) setCursorHistory((history) => history.slice(0, -1));
  }

  function toggleSort(key: FindingSortKey) {
    resetCursor();
    setSort((current) => ({
      key,
      direction: current?.key === key && current.direction === "asc" ? "desc" : "asc",
    }));
  }

  function renderSortHeader(label: string, key: FindingSortKey) {
    const direction = sort?.key === key ? sort.direction : null;
    const SortIcon = direction === "asc" ? ArrowUp : ArrowDown;

    return (
      <th
        key={label}
        aria-sort={direction === "asc" ? "ascending" : direction === "desc" ? "descending" : "none"}
        className="px-4 py-3 font-semibold text-muted-foreground first:pl-5"
      >
        <button
          type="button"
          onClick={() => toggleSort(key)}
          aria-label={`Sort by ${label}${
            direction ? `, ${direction === "asc" ? "ascending" : "descending"}` : ""
          }`}
          className="inline-flex items-center gap-1.5 text-left transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          {label}
          {direction && <SortIcon className="size-3" aria-hidden="true" />}
        </button>
      </th>
    );
  }

  function renderHeader(label: string) {
    return (
      <th key={label} className="px-4 py-3 font-semibold text-muted-foreground first:pl-5">
        {label}
      </th>
    );
  }
  const hasActiveFilters =
    search !== "" ||
    Object.values(filters).some((value) => value !== "all") ||
    dateFrom !== "" ||
    dateTo !== "";

  function clearFilters() {
    resetCursor();
    setSearch("");
    setFilters({
      severity: "all",
      classification: "all",
      data_type: "all",
      status: "all",
      source: "all",
      detector: "all",
    });
    setDateFrom("");
    setDateTo("");
  }

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
                onChange={(event) => {
                  resetCursor();
                  setSearch(event.target.value);
                }}
                placeholder="Search findings..."
                aria-label="Search findings"
                className="h-10 border-white/70 bg-white/60 pl-9"
              />
            </div>
            <span className="sr-only">
              <SlidersHorizontal aria-hidden="true" />
              Filters
            </span>
          </div>
          <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-8">
            {FILTER_FIELDS.map(({ key, label }) => (
              <label key={key} className="min-w-0">
                <span className="sr-only">{label}</span>
                <select
                  aria-label={label}
                  value={filters[key]}
                  onChange={(event) => {
                    resetCursor();
                    setFilters((current) => ({ ...current, [key]: event.target.value }));
                  }}
                  className="h-9 w-full rounded-md border border-input bg-white/60 px-3 text-xs text-foreground outline-none focus-visible:ring-1 focus-visible:ring-ring"
                >
                  <option value="all">All {label.toLowerCase()}</option>
                  {FILTER_OPTIONS[key].map((value) => (
                    <option key={value} value={value}>
                      {value.replace(/[_-]+/g, " ")}
                    </option>
                  ))}
                </select>
              </label>
            ))}
            <label className="min-w-0">
              <span className="sr-only">From date</span>
              <input
                aria-label="From date"
                type="date"
                value={dateFrom}
                max={dateTo || undefined}
                onChange={(event) => {
                  resetCursor();
                  setDateFrom(event.target.value);
                }}
                className="h-9 w-full rounded-md border border-input bg-white/60 px-3 text-xs text-foreground outline-none focus-visible:ring-1 focus-visible:ring-ring"
              />
            </label>
            <label className="min-w-0">
              <span className="sr-only">To date</span>
              <input
                aria-label="To date"
                type="date"
                value={dateTo}
                min={dateFrom || undefined}
                onChange={(event) => {
                  resetCursor();
                  setDateTo(event.target.value);
                }}
                className="h-9 w-full rounded-md border border-input bg-white/60 px-3 text-xs text-foreground outline-none focus-visible:ring-1 focus-visible:ring-ring"
              />
            </label>
          </div>
          <div className="mt-3 flex items-center justify-between gap-3">
            <p className="text-xs text-muted-foreground">
              Showing {findings.length} of {FINDING_FIXTURES.length} fixture findings.
            </p>
            <button
              type="button"
              onClick={clearFilters}
              disabled={!hasActiveFilters}
              className="rounded-md px-2 py-1 text-xs font-medium text-muted-foreground transition-colors hover:bg-white/70 hover:text-foreground disabled:cursor-not-allowed disabled:opacity-50"
            >
              Clear filters
            </button>
          </div>
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
                Showing {pageFindings.length} of {findings.length} matching findings
              </p>
            </div>
          </div>

          <div className="hidden overflow-x-auto lg:block">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b" style={{ borderColor: "oklch(0.90 0.006 250)" }}>
                  {renderSortHeader("Severity", "severity")}
                  {["Classification", "Finding", "Status", "Source / detector"].map(renderHeader)}
                  {renderSortHeader("Confidence", "confidence")}
                  {renderSortHeader("Detected", "created_at")}
                  <th className="px-4 py-3 pr-5" />
                </tr>
              </thead>
              <tbody className="divide-y" style={{ borderColor: "oklch(0.92 0.005 250)" }}>
                {pageFindings.map((finding) => (
                  <tr key={finding.id} className="transition-colors hover:bg-white/45">
                    <td className="whitespace-nowrap px-4 py-4 pl-5">
                      <SeverityBadge severity={finding.severity} />
                    </td>
                    <td className="px-4 py-4"><ClassificationChip classification={finding.classification} /></td>
                    <td className="max-w-[260px] px-4 py-4">
                      <p className="font-medium text-foreground">{finding.data_type.replace(/[_-]+/g, " ")}</p>
                      <MaskedValue value={null} fallback="Evidence unavailable" />
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
                    <td className="px-4 py-4 pr-5" />
                  </tr>
                ))}
                {pageFindings.length === 0 && (
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
            {pageFindings.map((finding) => (
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
                    <div className="mt-1">
                      <MaskedValue value={null} fallback="Evidence unavailable" />
                    </div>
                  </div>
                </div>
                <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
                  <ConfidenceBar confidence={finding.confidence} />
                  <time className="text-[11px] text-muted-foreground" dateTime={finding.created_at}>
                    {new Date(finding.created_at).toLocaleString()}
                  </time>
                </div>
              </article>
            ))}
            {pageFindings.length === 0 && (
              <p className="py-12 text-center text-sm text-muted-foreground">
                No findings match your search.
              </p>
            )}
          </div>
          <div className="flex items-center justify-end gap-2 border-t px-5 py-3" style={{ borderColor: "oklch(0.90 0.006 250)" }}>
            <button
              type="button"
              onClick={loadPrevious}
              disabled={!hasPrevious}
              className="rounded-md border px-3 py-1.5 text-xs font-medium text-muted-foreground transition-colors hover:bg-white/70 disabled:cursor-not-allowed disabled:opacity-50"
            >
              Previous
            </button>
            <button
              type="button"
              onClick={loadNext}
              disabled={!hasNext}
              className="rounded-md border px-3 py-1.5 text-xs font-medium text-muted-foreground transition-colors hover:bg-white/70 disabled:cursor-not-allowed disabled:opacity-50"
            >
              Next
            </button>
          </div>
        </section>
      </main>
    </AppShell>
  );
}
