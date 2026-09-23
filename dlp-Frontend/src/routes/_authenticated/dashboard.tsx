import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Chrome, HardDrive, Mail } from "lucide-react";

import { supabase } from "@/integrations/supabase/client";
import { useOrg } from "@/hooks/use-org";
import { AppShell } from "@/components/app-shell";
import { Button } from "@/components/ui/button";
import { DECISIONS, DECISION_LABELS } from "@/lib/dlp";

export const Route = createFileRoute("/_authenticated/dashboard")({
  head: () => ({
    meta: [
      { title: "Overview — DLP Console" },
      { name: "description", content: "Event volume by decision and connected channel status for your organization." },
      { property: "og:title", content: "Overview — DLP Console" },
      { property: "og:description", content: "Event volume by decision and connected channel status." },
    ],
  }),
  component: DashboardPage,
});

const DECISION_COLOR: Record<string, string> = {
  allow: "var(--allow)",
  warn: "var(--warn)",
  block: "var(--block)",
  log: "var(--log)",
};

const CHANNEL_CARDS = [
  { key: "gmail", label: "Gmail", description: "Outbound mail inspection", icon: Mail },
  { key: "drive", label: "Google Drive", description: "File share monitoring", icon: HardDrive },
  { key: "browser", label: "Browser agent", description: "Paste & upload capture", icon: Chrome },
];

function DashboardPage() {
  const [range, setRange] = useState<7 | 30>(7);
  const { data: orgId } = useOrg();

  const since = useMemo(() => {
    const d = new Date();
    d.setDate(d.getDate() - range);
    d.setHours(0, 0, 0, 0);
    return d;
  }, [range]);

  const events = useQuery({
    queryKey: ["dashboard-events", orgId, range],
    enabled: !!orgId,
    queryFn: async () => {
      const { data, error } = await supabase
        .from("dlp_events")
        .select("decision, created_at")
        .eq("org_id", orgId!)
        .gte("created_at", since.toISOString())
        .order("created_at", { ascending: true })
        .limit(5000);
      if (error) throw error;
      return data;
    },
  });

  const channels = useQuery({
    queryKey: ["channels", orgId],
    enabled: !!orgId,
    queryFn: async () => {
      const { data, error } = await supabase
        .from("dlp_channels")
        .select("channel_type, connected_at")
        .eq("org_id", orgId!);
      if (error) throw error;
      return data;
    },
  });

  const rows = events.data ?? [];

  const totals = useMemo(() => {
    const t: Record<string, number> = { allow: 0, warn: 0, block: 0, log: 0 };
    for (const r of rows) t[r.decision] = (t[r.decision] ?? 0) + 1;
    return t;
  }, [rows]);

  const series = useMemo(() => {
    const buckets: Record<string, Record<string, number>> = {};
    for (let i = range - 1; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      const key = d.toISOString().slice(0, 10);
      buckets[key] = { allow: 0, warn: 0, block: 0, log: 0 };
    }
    for (const r of rows) {
      const key = r.created_at.slice(0, 10);
      const bucket = buckets[key];
      if (bucket) bucket[r.decision] = (bucket[r.decision] ?? 0) + 1;
    }
    return Object.entries(buckets).map(([date, counts]) => ({
      date: date.slice(5),
      ...counts,
    }));
  }, [rows, range]);

  return (
    <AppShell
      title="Overview"
      description={`Event decisions across the last ${range} days`}
      actions={
        <div className="flex rounded-md border border-border p-0.5">
          {([7, 30] as const).map((r) => (
            <Button
              key={r}
              size="sm"
              variant={range === r ? "secondary" : "ghost"}
              className="h-7 px-3 text-xs"
              onClick={() => setRange(r)}
            >
              {r}d
            </Button>
          ))}
        </div>
      }
    >
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {DECISIONS.map((d) => (
          <div key={d} className="panel p-4">
            <div className="flex items-center gap-2 text-xs uppercase tracking-wide text-muted-foreground">
              <span className="size-1.5 rounded-full" style={{ backgroundColor: DECISION_COLOR[d] }} />
              {DECISION_LABELS[d]}
            </div>
            <p className="mt-2 font-mono text-3xl tabular-nums">{totals[d] ?? 0}</p>
            <p className="mt-1 text-xs text-muted-foreground">events in {range} days</p>
          </div>
        ))}
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <div className="panel p-5 lg:col-span-2">
          <h2 className="text-sm font-semibold">Events by decision</h2>
          <p className="mt-0.5 text-xs text-muted-foreground">Daily volume, stacked by enforcement decision</p>
          <div className="mt-5 h-72">
            {rows.length === 0 ? (
              <div className="flex h-full items-center justify-center rounded-md border border-dashed border-border text-sm text-muted-foreground">
                No events recorded yet. Events appear here once a channel starts reporting.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={series}>
                  <CartesianGrid vertical={false} stroke="var(--border)" />
                  <XAxis dataKey="date" tickLine={false} axisLine={false} fontSize={11} stroke="var(--muted-foreground)" />
                  <YAxis tickLine={false} axisLine={false} fontSize={11} width={30} stroke="var(--muted-foreground)" allowDecimals={false} />
                  <Tooltip
                    cursor={{ fill: "var(--accent)" }}
                    contentStyle={{
                      background: "var(--popover)",
                      border: "1px solid var(--border)",
                      borderRadius: 8,
                      fontSize: 12,
                    }}
                  />
                  {DECISIONS.map((d) => (
                    <Bar key={d} dataKey={d} stackId="a" fill={DECISION_COLOR[d]} radius={d === "log" ? [3, 3, 0, 0] : 0} />
                  ))}
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        <div className="panel p-5">
          <h2 className="text-sm font-semibold">Channels connected</h2>
          <p className="mt-0.5 text-xs text-muted-foreground">Collection sources reporting into DLP</p>
          <ul className="mt-4 space-y-3">
            {CHANNEL_CARDS.map((c) => {
              const row = channels.data?.find((x) => x.channel_type === c.key);
              const connected = !!row?.connected_at;
              return (
                <li key={c.key} className="flex items-center gap-3 rounded-md border border-border bg-surface-2/50 p-3">
                  <div className="flex size-9 items-center justify-center rounded-md bg-accent text-muted-foreground">
                    <c.icon className="size-4" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium">{c.label}</p>
                    <p className="truncate text-xs text-muted-foreground">{c.description}</p>
                  </div>
                  <span
                    className={
                      connected
                        ? "rounded-full border border-allow/35 bg-allow/10 px-2 py-0.5 text-[11px] text-allow"
                        : "rounded-full border border-border px-2 py-0.5 text-[11px] text-muted-foreground"
                    }
                  >
                    {connected ? "Connected" : "Not connected"}
                  </span>
                </li>
              );
            })}
          </ul>
          <p className="mt-4 text-xs text-muted-foreground">
            Connectors are provisioned by the collection backend. Status updates automatically once a source begins
            reporting.
          </p>
        </div>
      </div>
    </AppShell>
  );
}
