import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { supabase } from "@/integrations/supabase/client";
import { useOrg } from "@/hooks/use-org";
import { FIXTURE_MODE } from "@/lib/env";
import { AppShell } from "@/components/app-shell";
import { DecisionBadge } from "@/components/decision-badge";
import { Input } from "@/components/ui/input";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  CHANNELS,
  CHANNEL_LABELS,
  DATA_TYPE_LABELS,
  DECISIONS,
  DECISION_LABELS,
  formatDateTime,
  redact,
} from "@/lib/dlp";

export const Route = createFileRoute("/_authenticated/events")({
  head: () => ({
    meta: [
      { title: "Event feed — DLP Console" },
      { name: "description", content: "Filterable feed of data loss prevention events with redacted match detail." },
      { property: "og:title", content: "Event feed — DLP Console" },
      { property: "og:description", content: "Filterable feed of DLP events with redacted match detail." },
    ],
  }),
  component: EventsPage,
});

type EventRow = {
  id: string;
  channel: string;
  data_type: string;
  destination: string | null;
  decision: string;
  confidence: number;
  snippet: string | null;
  user_id: string | null;
  created_at: string;
};

const EVENT_FIXTURE_SAMPLES: Omit<EventRow, "id" | "created_at">[] = [
  { channel: "browser", data_type: "credentials", destination: "portal.example.com", decision: "block", confidence: 0.98, snippet: "Credential-like value detected in form submission.", user_id: "user-fixture-01" },
  { channel: "email", data_type: "pii", destination: "external@example.net", decision: "warn", confidence: 0.91, snippet: "Personal information detected in message body.", user_id: "user-fixture-02" },
  { channel: "cloud_storage", data_type: "financials", destination: "Shared finance folder", decision: "allow", confidence: 0.84, snippet: "Quarterly finance report matched a monitored rule.", user_id: "user-fixture-03" },
  { channel: "api", data_type: "source_code", destination: "api.example.com", decision: "log", confidence: 0.76, snippet: "Source code pattern observed in API payload.", user_id: "user-fixture-04" },
  { channel: "email", data_type: "pci", destination: "vendor@example.net", decision: "block", confidence: 0.96, snippet: "Payment card pattern detected and redacted.", user_id: "user-fixture-05" },
  { channel: "browser", data_type: "customer_list", destination: "crm.example.com", decision: "warn", confidence: 0.88, snippet: "Customer list attachment matched a policy.", user_id: "user-fixture-06" },
  { channel: "cloud_storage", data_type: "phi", destination: "Clinical archive", decision: "block", confidence: 0.93, snippet: "Health information detected in shared file.", user_id: "user-fixture-07" },
  { channel: "api", data_type: "other", destination: null, decision: "allow", confidence: 0.62, snippet: null, user_id: null },
];

const EVENT_FIXTURES: EventRow[] = Array.from({ length: 36 }, (_, index) => {
  const sample = EVENT_FIXTURE_SAMPLES[index % EVENT_FIXTURE_SAMPLES.length];
  if (!sample) throw new Error("Event fixture samples must not be empty.");

  const createdAt = new Date();
  createdAt.setUTCDate(createdAt.getUTCDate() - index);
  createdAt.setUTCHours(12, 0, 0, 0);

  return {
    ...sample,
    id: `event-fixture-${String(index + 1).padStart(2, "0")}`,
    created_at: createdAt.toISOString(),
  };
});

function EventsPage() {
  const org = useOrg();
  const orgId = org.data;
  const [decision, setDecision] = useState<string>("all");
  const [channel, setChannel] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<EventRow | null>(null);

  const pageSize = 25;

  const events = useQuery({
    queryKey: ["events", orgId, decision, channel, startDate, endDate],
    enabled: FIXTURE_MODE || !!orgId,
    queryFn: async () => {
      if (FIXTURE_MODE) {
        const startTime = startDate ? new Date(`${startDate}T00:00:00`).getTime() : -Infinity;
        const endExclusive = endDate ? new Date(`${endDate}T00:00:00`) : null;
        endExclusive?.setDate(endExclusive.getDate() + 1);
        const endTime = endExclusive?.getTime() ?? Infinity;

        return EVENT_FIXTURES.filter((event) =>
          (decision === "all" || event.decision === decision) &&
          (channel === "all" || event.channel === channel) &&
          new Date(event.created_at).getTime() >= startTime &&
          new Date(event.created_at).getTime() < endTime,
        );
      }

      let q = supabase
        .from("dlp_events")
        .select(
          "id, channel, data_type, destination, decision, confidence, snippet, user_id, created_at",
        )
        .eq("org_id", orgId!)
        .order("created_at", { ascending: false })
        .limit(200);

      if (decision !== "all") q = q.eq("decision", decision);
      if (channel !== "all") q = q.eq("channel", channel);
      if (startDate) q = q.gte("created_at", `${startDate}T00:00:00`);
      if (endDate) {
        const endExclusive = new Date(`${endDate}T00:00:00`);
        endExclusive.setDate(endExclusive.getDate() + 1);
        q = q.lt("created_at", endExclusive.toISOString());
      }

      const { data, error } = await q;
      if (error) throw error;
      return data as EventRow[];
    },
  });

  const rows = events.data ?? [];

  const filteredRows = rows.filter((event) => {
    const term = search.trim().toLowerCase();
    if (!term) return true;

    return [
      event.channel,
      CHANNEL_LABELS[event.channel],
      event.data_type,
      DATA_TYPE_LABELS[event.data_type],
      event.destination,
      event.decision,
      event.snippet,
      event.user_id,
    ].some((value) => String(value ?? "").toLowerCase().includes(term));
  });

  const totalPages = Math.max(1, Math.ceil(filteredRows.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const paginatedRows = filteredRows.slice(
    (currentPage - 1) * pageSize,
    currentPage * pageSize,
  );

  return (
    <AppShell
      title="Event feed"
      description="Every inspected transfer, newest first"
    >
      <div className="mx-auto mb-3 grid w-full min-w-0 grid-cols-2 items-center gap-3 px-4 py-3 md:grid-cols-4 lg:grid-cols-[minmax(0,2fr)_repeat(4,minmax(0,1.1fr))]">
        <Input
          type="search"
          placeholder="Search events..."
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setPage(1);
          }}
          className="col-span-2 h-12 min-w-0 w-full text-xs md:col-span-4 lg:col-span-1"
          aria-label="Search events"
        />
        <Input
          type="date"
          value={startDate}
          onChange={(e) => {
            setStartDate(e.target.value);
            setPage(1);
          }}
          className="h-12 min-w-0 w-full text-xs"
          aria-label="Start date"
        />
        <Input
          type="date"
          value={endDate}
          min={startDate || undefined}
          onChange={(e) => {
            setEndDate(e.target.value);
            setPage(1);
          }}
          className="h-12 min-w-0 w-full text-xs"
          aria-label="End date"
        />
        <Select
          value={decision}
          onValueChange={(value) => {
            setDecision(value);
            setPage(1);
          }}
        >
          <SelectTrigger className="h-12 min-w-0 w-full text-xs">
            <SelectValue placeholder="Decision" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All decisions</SelectItem>
            {DECISIONS.map((d) => (
              <SelectItem key={d} value={d}>
                {DECISION_LABELS[d]}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select
          value={channel}
          onValueChange={(value) => {
            setChannel(value);
            setPage(1);
          }}
        >
          <SelectTrigger className="h-12 min-w-0 w-full text-xs">
            <SelectValue placeholder="Channel" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All channels</SelectItem>
            {CHANNELS.map((c) => (
              <SelectItem key={c} value={c}>
                {CHANNEL_LABELS[c]}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="panel overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="w-[180px]">Time</TableHead>
              <TableHead>Channel</TableHead>
              <TableHead>Data type</TableHead>
              <TableHead>Destination</TableHead>
              <TableHead className="w-[110px]">Confidence</TableHead>
              <TableHead className="w-[110px]">Decision</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {org.isError ? (
              <TableRow>
                <TableCell colSpan={6} className="py-12 text-center" role="alert">
                  <p className="text-sm text-destructive">
                    Unable to load your organization. {org.error instanceof Error ? org.error.message : "Please try again."}
                  </p>
                  <button
                    type="button"
                    onClick={() => void org.refetch()}
                    className="mt-3 rounded-md border border-border px-3 py-1.5 text-xs"
                  >
                    Retry
                  </button>
                </TableCell>
              </TableRow>
            ) : org.isLoading && !FIXTURE_MODE ? (
              <TableRow>
                <TableCell colSpan={6} className="py-12 text-center text-sm text-muted-foreground">
                  Loading your organization...
                </TableCell>
              </TableRow>
            ) : events.isLoading ? (
              <TableRow>
                <TableCell colSpan={6} className="py-12 text-center text-sm text-muted-foreground">
                  Loading events...
                </TableCell>
              </TableRow>
            ) : events.isError ? (
              <TableRow>
                <TableCell colSpan={6} className="py-12 text-center">
                  <p className="text-sm text-destructive">
                    Failed to load events. Please try again.
                  </p>
                  <button
                    type="button"
                    onClick={() => events.refetch()}
                    className="mt-3 rounded-md border border-border px-3 py-1.5 text-xs"
                  >
                    Retry
                  </button>
                </TableCell>
              </TableRow>
            ) : filteredRows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="py-12 text-center text-sm text-muted-foreground">
                  No events match these filters.
                </TableCell>
              </TableRow>
            ) : (
              paginatedRows.map((e) => (
                <TableRow key={e.id} className="cursor-pointer" onClick={() => setSelected(e)}>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {formatDateTime(e.created_at)}
                  </TableCell>
                  <TableCell className="text-sm">{CHANNEL_LABELS[e.channel] ?? e.channel}</TableCell>
                  <TableCell className="text-sm">{DATA_TYPE_LABELS[e.data_type] ?? e.data_type}</TableCell>
                  <TableCell className="max-w-[260px] truncate font-mono text-xs">
                    {e.destination ?? "—"}
                  </TableCell>
                  <TableCell className="font-mono text-xs tabular-nums">
                    {Math.round(Number(e.confidence) * 100)}%
                  </TableCell>
                  <TableCell>
                    <DecisionBadge decision={e.decision} />
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 px-1 py-3">
        <p className="text-xs text-muted-foreground">
          {filteredRows.length === 0
            ? "No results"
            : `Showing ${(currentPage - 1) * pageSize + 1}–${Math.min(
                currentPage * pageSize,
                filteredRows.length,
              )} of ${filteredRows.length} events`}
        </p>
        <div className="flex items-center gap-2">
          <button
            type="button"
            className="rounded-md border border-border px-3 py-1.5 text-xs disabled:cursor-not-allowed disabled:opacity-40"
            disabled={currentPage <= 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
          >
            Previous
          </button>
          <span className="text-xs text-muted-foreground">
            Page {currentPage} of {totalPages}
          </span>
          <button
            type="button"
            className="rounded-md border border-border px-3 py-1.5 text-xs disabled:cursor-not-allowed disabled:opacity-40"
            disabled={currentPage >= totalPages}
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
          >
            Next
          </button>
        </div>
      </div>

      <Sheet open={!!selected} onOpenChange={(open) => !open && setSelected(null)}>
        <SheetContent className="w-full overflow-y-auto sm:max-w-lg">
          {selected ? (
            <>
              <SheetHeader>
                <SheetTitle className="flex items-center gap-2">
                  Event detail
                  <DecisionBadge decision={selected.decision} />
                </SheetTitle>
                <SheetDescription className="font-mono text-xs">{selected.id}</SheetDescription>
              </SheetHeader>

              <dl className="grid grid-cols-2 gap-x-4 gap-y-4 px-4 text-sm">
                <Field label="Time" value={formatDateTime(selected.created_at)} />
                <Field label="Channel" value={CHANNEL_LABELS[selected.channel] ?? selected.channel} />
                <Field label="Data type" value={DATA_TYPE_LABELS[selected.data_type] ?? selected.data_type} />
                <Field label="Confidence" value={`${Math.round(Number(selected.confidence) * 100)}%`} />
                <Field label="Destination" value={selected.destination ?? "—"} mono className="col-span-2" />
                <Field label="Actor" value={selected.user_id ?? "Unattributed"} mono className="col-span-2" />
              </dl>

              <div className="px-4 pb-8">
                <p className="text-xs uppercase tracking-wide text-muted-foreground">Matched snippet (redacted)</p>
                <pre className="mt-2 max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-md border border-border bg-background p-3 font-mono text-xs leading-relaxed">
                  {redact(selected.snippet) || "No snippet captured for this event."}
                </pre>
                <p className="mt-2 text-xs text-muted-foreground">
                  Sensitive values are masked before storage and again on display. Raw content is never retained.
                </p>
              </div>
            </>
          ) : null}
        </SheetContent>
      </Sheet>
    </AppShell>
  );
}

function Field({
  label,
  value,
  mono,
  className,
}: {
  label: string;
  value: string;
  mono?: boolean;
  className?: string;
}) {
  return (
    <div className={className}>
      <dt className="text-xs uppercase tracking-wide text-muted-foreground">{label}</dt>
      <dd className={mono ? "mt-1 break-all font-mono text-xs" : "mt-1 text-sm"}>{value}</dd>
    </div>
  );
}
