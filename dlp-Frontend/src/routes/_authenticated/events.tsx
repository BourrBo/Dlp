import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { supabase } from "@/integrations/supabase/client";
import { useOrg } from "@/hooks/use-org";
import { AppShell } from "@/components/app-shell";
import { DecisionBadge } from "@/components/decision-badge";
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

function EventsPage() {
  const { data: orgId } = useOrg();
  const [decision, setDecision] = useState<string>("all");
  const [channel, setChannel] = useState<string>("all");
  const [selected, setSelected] = useState<EventRow | null>(null);

  const events = useQuery({
    queryKey: ["events", orgId, decision, channel],
    enabled: !!orgId,
    queryFn: async () => {
      let q = supabase
        .from("dlp_events")
        .select("id, channel, data_type, destination, decision, confidence, snippet, user_id, created_at")
        .eq("org_id", orgId!)
        .order("created_at", { ascending: false })
        .limit(200);
      if (decision !== "all") q = q.eq("decision", decision);
      if (channel !== "all") q = q.eq("channel", channel);
      const { data, error } = await q;
      if (error) throw error;
      return data as EventRow[];
    },
  });

  const rows = events.data ?? [];

  return (
    <AppShell
      title="Event feed"
      description="Every inspected transfer, newest first"
      actions={
        <div className="flex gap-2">
          <Select value={decision} onValueChange={setDecision}>
            <SelectTrigger className="h-8 w-[150px] text-xs">
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
          <Select value={channel} onValueChange={setChannel}>
            <SelectTrigger className="h-8 w-[160px] text-xs">
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
      }
    >
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
            {events.isLoading ? (
              <TableRow>
                <TableCell colSpan={6} className="py-12 text-center text-sm text-muted-foreground">
                  Loading events…
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="py-12 text-center text-sm text-muted-foreground">
                  No events match these filters.
                </TableCell>
              </TableRow>
            ) : (
              rows.map((e) => (
                <TableRow key={e.id} className="cursor-pointer" onClick={() => setSelected(e)}>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {formatDateTime(e.created_at)}
                  </TableCell>
                  <TableCell className="text-sm">{CHANNEL_LABELS[e.channel] ?? e.channel}</TableCell>
                  <TableCell className="text-sm">{DATA_TYPE_LABELS[e.data_type] ?? e.data_type}</TableCell>
                  <TableCell className="max-w-[260px] truncate font-mono text-xs">{e.destination ?? "—"}</TableCell>
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
