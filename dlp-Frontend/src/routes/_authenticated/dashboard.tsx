import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  AlertTriangle,
  ArrowRight,
  Calendar,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Chrome,
  ExternalLink,
  FileText,
  FolderOpen,
  HardDrive,
  Mail,
  MessageSquare,
  RefreshCw,
  ScanSearch,
  Shield,
  ShieldAlert,
  TrendingDown,
  TrendingUp,
  Wifi,
  WifiOff,
} from "lucide-react";

import { supabase } from "@/integrations/supabase/client";
import { useOrg } from "@/hooks/use-org";
import { FIXTURE_MODE } from "@/lib/env";
import { AppShell } from "@/components/app-shell";
import { SeverityBadge } from "@/components/severity-badge";
import { ClassificationChip } from "@/components/classification-chip";

export const Route = createFileRoute("/_authenticated/dashboard")({
  head: () => ({
    meta: [
      { title: "Overview — DLP Console" },
      {
        name: "description",
        content:
          "Organization data loss prevention overview — findings, trends, and channel status.",
      },
      { property: "og:title", content: "Overview — DLP Console" },
    ],
  }),
  component: DashboardPage,
});

// ─── Mock / fixture data ───────────────────────────────────────────────────

const MOCK_TREND = Array.from({ length: 7 }, (_, i) => {
  const d = new Date();
  d.setDate(d.getDate() - (6 - i));
  return {
    date: d.toISOString().slice(5, 10),
    critical: Math.round(Math.random() * 12 + 2),
    high: Math.round(Math.random() * 25 + 8),
    medium: Math.round(Math.random() * 40 + 15),
    low: Math.round(Math.random() * 30 + 10),
  };
});

const MOCK_DONUT = [
  { name: "PII", value: 38, color: "oklch(0.55 0.22 25)" },
  { name: "Credentials", value: 22, color: "oklch(0.44 0.17 255)" },
  { name: "Financial", value: 18, color: "oklch(0.62 0.18 75)" },
  { name: "Health", value: 11, color: "oklch(0.54 0.17 155)" },
  { name: "Secrets", value: 7, color: "oklch(0.60 0.18 310)" },
  { name: "Other", value: 4, color: "oklch(0.65 0.015 250)" },
];

const MOCK_CHANNEL_ACTIVITY = [
  { icon: Mail, name: "Gmail", events: 342, pct: 72 },
  { icon: HardDrive, name: "Google Drive", events: 218, pct: 46 },
  { icon: Chrome, name: "Browser Agent", events: 187, pct: 39 },
  { icon: MessageSquare, name: "Slack", events: 94, pct: 20 },
];

const MOCK_FINDINGS = [
  {
    id: "f1",
    severity: "critical",
    dataType: "credentials",
    title: "AWS Secret Key detected in email attachment",
    source: "Gmail",
    user: "j.smith@corp.com",
    time: "2 min ago",
  },
  {
    id: "f2",
    severity: "high",
    dataType: "pii",
    title: "SSN pattern found in Drive document",
    source: "Google Drive",
    user: "m.jones@corp.com",
    time: "14 min ago",
  },
  {
    id: "f3",
    severity: "high",
    dataType: "financials",
    title: "Credit card numbers in uploaded CSV",
    source: "Browser",
    user: "r.patel@corp.com",
    time: "31 min ago",
  },
  {
    id: "f4",
    severity: "medium",
    dataType: "phi",
    title: "Health record shared externally",
    source: "Google Drive",
    user: "k.chen@corp.com",
    time: "1 hr ago",
  },
  {
    id: "f5",
    severity: "low",
    dataType: "source_code",
    title: "Internal source code snippet in Slack",
    source: "Slack",
    user: "a.kumar@corp.com",
    time: "2 hr ago",
  },
];

const CHART_COLORS = {
  critical: "oklch(0.55 0.22 25)",
  high: "oklch(0.62 0.18 45)",
  medium: "oklch(0.62 0.18 75)",
  low: "oklch(0.54 0.17 155)",
};

// ─── Helpers ────────────────────────────────────────────────────────────────

function GlassCard({
  className = "",
  children,
  style,
}: {
  className?: string;
  children: React.ReactNode;
  style?: React.CSSProperties;
}) {
  return (
    <div
      className={`rounded-2xl border ${className}`}
      style={{
        background: "oklch(1 0 0 / 0.80)",
        borderColor: "oklch(0.92 0.006 250)",
        backdropFilter: "blur(16px)",
        boxShadow: "0 1px 2px oklch(0 0 0 / 0.03), 0 4px 16px oklch(0 0 0 / 0.05)",
        ...style,
      }}
    >
      {children}
    </div>
  );
}

function SkeletonLine({ w = "w-full", h = "h-4" }: { w?: string; h?: string }) {
  return (
    <div
      className={`${w} ${h} rounded-md animate-pulse`}
      style={{ background: "oklch(0.90 0.005 250)" }}
    />
  );
}

function TrendBadge({ pct, inverted = false }: { pct: number; inverted?: boolean }) {
  const good = inverted ? pct < 0 : pct > 0;
  return (
    <span
      className="inline-flex items-center gap-0.5 rounded-full px-2 py-0.5 text-[10px] font-semibold"
      style={{
        background: good
          ? "oklch(0.54 0.17 155 / 0.12)"
          : "oklch(0.55 0.22 25 / 0.12)",
        color: good ? "oklch(0.44 0.17 155)" : "oklch(0.50 0.22 25)",
      }}
    >
      {pct > 0 ? (
        <TrendingUp className="size-2.5" />
      ) : (
        <TrendingDown className="size-2.5" />
      )}
      {Math.abs(pct)}%
    </span>
  );
}

// ─── Page ───────────────────────────────────────────────────────────────────

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
      if (FIXTURE_MODE) return [];
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
      if (FIXTURE_MODE) return [];
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

  const totalFindings = Object.values(totals).reduce((a, b) => a + b, 0);

  // ── Channel status rows ──────────────────────────────────────────────────
  const CHANNEL_STATUS = [
    { key: "gmail", label: "Gmail", icon: Mail, lastSync: "2 min ago" },
    { key: "drive", label: "Google Drive", icon: HardDrive, lastSync: "5 min ago" },
    { key: "browser", label: "Browser Agent", icon: Chrome, lastSync: "12 min ago" },
    { key: "slack", label: "Slack", icon: MessageSquare, lastSync: "Never" },
  ];

  const now = new Date();
  const dateLabel = now.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });

  return (
    <AppShell>
      <div
        className="px-6 py-6 space-y-6"
        style={{ minHeight: "calc(100vh - 56px)" }}
      >
        {/* ── Page header ─────────────────────────────────────────────────── */}
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold" style={{ color: "oklch(0.15 0.015 250)" }}>
              Hello, Ashish 👋
            </h1>
            <p className="mt-1 text-sm" style={{ color: "oklch(0.52 0.018 250)" }}>
              Here's your organization's data loss prevention overview.
            </p>
          </div>
          {/* Date range selector */}
          <button
            className="flex items-center gap-2 rounded-xl border px-3 py-2 text-sm transition-colors hover:bg-white/60"
            style={{
              background: "oklch(1 0 0 / 0.7)",
              borderColor: "oklch(0.88 0.008 250)",
              color: "oklch(0.30 0.015 250)",
            }}
          >
            <Calendar className="size-4" style={{ color: "oklch(0.44 0.17 255)" }} />
            <span className="font-medium">{dateLabel}</span>
            <span style={{ color: "oklch(0.65 0.015 250)" }}>— Last {range} days</span>
            <ChevronDown className="size-3.5" style={{ color: "oklch(0.55 0.015 250)" }} />
          </button>
        </div>

        {/* ── Hero card ────────────────────────────────────────────────────── */}
        <div
          className="relative overflow-hidden rounded-2xl p-7"
          style={{
            background: "linear-gradient(135deg, oklch(0.18 0.015 255) 0%, oklch(0.28 0.20 275) 60%, oklch(0.38 0.18 305) 100%)",
            boxShadow: "0 8px 32px oklch(0.28 0.18 275 / 0.35)",
          }}
        >
          {/* Decorative circles */}
          <div
            className="absolute -top-8 -right-8 size-40 rounded-full opacity-10"
            style={{ background: "white" }}
          />
          <div
            className="absolute top-4 right-32 size-20 rounded-full opacity-10"
            style={{ background: "white" }}
          />
          <div
            className="absolute -bottom-10 right-16 size-28 rounded-full opacity-10"
            style={{ background: "white" }}
          />

          <div className="relative z-10 flex flex-wrap items-center justify-between gap-6">
            <div className="max-w-lg">
              <div
                className="mb-3 inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-[11px] font-semibold"
                style={{
                  background: "oklch(1 0 0 / 0.12)",
                  borderColor: "oklch(1 0 0 / 0.2)",
                  color: "oklch(0.90 0.004 250)",
                }}
              >
                <Shield className="size-3" />
                Real-time Protection Active
              </div>
              <h2
                className="text-2xl font-bold tracking-tight"
                style={{ color: "oklch(0.98 0.002 250)" }}
              >
                Detect. Monitor. Prevent.
              </h2>
              <p className="mt-2 text-sm leading-relaxed" style={{ color: "oklch(0.78 0.006 250)" }}>
                Keep your sensitive data safe across all channels with real-time monitoring and intelligent policy enforcement.
              </p>
              <div className="mt-5 flex flex-wrap gap-3">
                <button
                  className="flex items-center gap-2 rounded-xl px-4 py-2.5 text-sm font-semibold transition-all hover:shadow-lg"
                  style={{
                    background: "oklch(1 0 0)",
                    color: "oklch(0.25 0.015 250)",
                    boxShadow: "0 2px 8px oklch(0 0 0 / 0.15)",
                  }}
                >
                  <ScanSearch className="size-4" style={{ color: "oklch(0.44 0.17 255)" }} />
                  Run New Scan
                  <ArrowRight className="size-3.5" />
                </button>
                <button
                  className="flex items-center gap-2 rounded-xl border px-4 py-2.5 text-sm font-semibold transition-opacity hover:opacity-80"
                  style={{
                    background: "oklch(1 0 0 / 0.12)",
                    borderColor: "oklch(1 0 0 / 0.25)",
                    color: "oklch(0.95 0.003 250)",
                  }}
                >
                  <FileText className="size-4" />
                  View Findings
                </button>
              </div>
            </div>

            {/* Hero illustration */}
            <div className="flex items-center gap-4">
              <div className="flex flex-col gap-3">
                <div
                  className="flex items-center gap-2 rounded-xl border px-3 py-2"
                  style={{
                    background: "rgba(223, 235, 255, 0.14)",
                    borderColor: "rgba(255, 255, 255, 0.24)",
                    backdropFilter: "blur(14px)",
                    boxShadow:
                      "0 8px 24px rgba(7, 16, 42, 0.14), inset 0 1px 0 rgba(255, 255, 255, 0.22)",
                  }}
                >
                  <Shield className="size-5" style={{ color: "oklch(0.80 0.10 155)" }} />
                  <div>
                    <p className="text-[10px] font-medium" style={{ color: "oklch(0.70 0.006 250)" }}>Protected</p>
                    <p className="text-sm font-bold text-white">24/7</p>
                  </div>
                </div>
                <div
                  className="flex items-center gap-2 rounded-xl border px-3 py-2"
                  style={{
                    background: "rgba(223, 235, 255, 0.14)",
                    borderColor: "rgba(255, 255, 255, 0.24)",
                    backdropFilter: "blur(14px)",
                    boxShadow:
                      "0 8px 24px rgba(7, 16, 42, 0.14), inset 0 1px 0 rgba(255, 255, 255, 0.22)",
                  }}
                >
                  <ShieldAlert className="size-5" style={{ color: "oklch(0.75 0.18 45)" }} />
                  <div>
                    <p className="text-[10px] font-medium" style={{ color: "oklch(0.70 0.006 250)" }}>Findings</p>
                    <p className="text-sm font-bold text-white">
                      {totalFindings || "—"}
                    </p>
                  </div>
                </div>
              </div>
              <div
                className="flex size-20 items-center justify-center rounded-2xl"
                style={{
                  background: "oklch(1 0 0 / 0.12)",
                  border: "1px solid oklch(1 0 0 / 0.2)",
                }}
              >
                <Shield className="size-10 text-white/80" />
              </div>
            </div>
          </div>
        </div>

        {/* ── KPI cards ────────────────────────────────────────────────────── */}
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {[
            {
              label: "Total Findings",
              value: totalFindings || 847,
              pct: 12,
              icon: FolderOpen,
              color: "oklch(0.44 0.17 255)",
              bg: "oklch(0.44 0.17 255 / 0.08)",
              inverted: true,
            },
            {
              label: "Critical",
              value: totals.block || 34,
              pct: -8,
              icon: ShieldAlert,
              color: "oklch(0.55 0.22 25)",
              bg: "oklch(0.55 0.22 25 / 0.08)",
              inverted: true,
            },
            {
              label: "High",
              value: totals.warn || 128,
              pct: 5,
              icon: AlertTriangle,
              color: "oklch(0.62 0.18 45)",
              bg: "oklch(0.62 0.18 45 / 0.08)",
              inverted: true,
            },
            {
              label: "Data Types",
              value: 6,
              pct: 0,
              icon: Shield,
              color: "oklch(0.54 0.17 155)",
              bg: "oklch(0.54 0.17 155 / 0.08)",
              inverted: false,
            },
          ].map((kpi) => (
            <GlassCard key={kpi.label} className="p-5">
              <div className="flex items-start justify-between">
                <div
                  className="flex size-10 items-center justify-center rounded-xl"
                  style={{ background: kpi.bg }}
                >
                  <kpi.icon className="size-5" style={{ color: kpi.color }} />
                </div>
                <TrendBadge pct={kpi.pct} inverted={kpi.inverted} />
              </div>
              {events.isLoading ? (
                <div className="mt-4 space-y-2">
                  <SkeletonLine w="w-16" h="h-7" />
                  <SkeletonLine w="w-24" h="h-3" />
                </div>
              ) : (
                <>
                  <p
                    className="mt-3 font-mono text-3xl font-bold tabular-nums"
                    style={{ color: "oklch(0.15 0.015 250)" }}
                  >
                    {kpi.value.toLocaleString()}
                  </p>
                  <p className="mt-0.5 text-xs" style={{ color: "oklch(0.52 0.018 250)" }}>
                    {kpi.label}
                  </p>
                  <p className="mt-1 text-[10px]" style={{ color: "oklch(0.65 0.012 250)" }}>
                    vs previous {range} days
                  </p>
                  {/* Mini trend bars */}
                  <div className="mt-3 flex items-end gap-0.5 h-6">
                    {[40, 55, 35, 70, 45, 80, 60].map((h, i) => (
                      <div
                        key={i}
                        className="flex-1 rounded-sm"
                        style={{
                          height: `${h}%`,
                          background: kpi.color,
                          opacity: i === 6 ? 1 : 0.3 + i * 0.1,
                        }}
                      />
                    ))}
                  </div>
                </>
              )}
            </GlassCard>
          ))}
        </div>

        {/* ── Charts row ───────────────────────────────────────────────────── */}
        <div className="grid gap-4 lg:grid-cols-3">
          {/* Findings Trend */}
          <GlassCard className="p-5 lg:col-span-2">
            <div className="flex items-start justify-between mb-5">
              <div>
                <h2 className="text-sm font-semibold" style={{ color: "oklch(0.18 0.015 250)" }}>
                  Findings Trend
                </h2>
                <p className="mt-0.5 text-xs" style={{ color: "oklch(0.55 0.015 250)" }}>
                  Daily findings by severity
                </p>
              </div>
              <div className="flex items-center gap-1">
                {([7, 30] as const).map((r) => (
                  <button
                    key={r}
                    onClick={() => setRange(r)}
                    className="rounded-lg px-2.5 py-1 text-xs font-medium transition-colors"
                    style={
                      range === r
                        ? {
                            background: "oklch(0.18 0.015 250)",
                            color: "white",
                          }
                        : {
                            color: "oklch(0.55 0.015 250)",
                          }
                    }
                  >
                    {r}d
                  </button>
                ))}
              </div>
            </div>

            {/* Legend */}
            <div className="flex flex-wrap gap-3 mb-4">
              {(["critical", "high", "medium", "low"] as const).map((s) => (
                <div key={s} className="flex items-center gap-1.5 text-xs" style={{ color: "oklch(0.50 0.015 250)" }}>
                  <span className="size-2 rounded-sm" style={{ background: CHART_COLORS[s] }} />
                  {s.charAt(0).toUpperCase() + s.slice(1)}
                </div>
              ))}
            </div>

            <div className="h-60">
              {events.isLoading ? (
                <div className="flex h-full items-center justify-center">
                  <RefreshCw className="size-5 animate-spin" style={{ color: "oklch(0.65 0.015 250)" }} />
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={MOCK_TREND} barSize={14} barCategoryGap="30%">
                    <CartesianGrid vertical={false} stroke="oklch(0.90 0.006 250)" />
                    <XAxis
                      dataKey="date"
                      tickLine={false}
                      axisLine={false}
                      fontSize={11}
                      stroke="oklch(0.60 0.012 250)"
                    />
                    <YAxis
                      tickLine={false}
                      axisLine={false}
                      fontSize={11}
                      width={28}
                      stroke="oklch(0.60 0.012 250)"
                      allowDecimals={false}
                    />
                    <Tooltip
                      cursor={{ fill: "oklch(0.44 0.17 255 / 0.06)", radius: 6 }}
                      contentStyle={{
                        background: "white",
                        border: "1px solid oklch(0.88 0.008 250)",
                        borderRadius: 12,
                        fontSize: 12,
                        boxShadow: "0 4px 16px oklch(0 0 0 / 0.08)",
                      }}
                    />
                    {(["low", "medium", "high", "critical"] as const).map((s) => (
                      <Bar
                        key={s}
                        dataKey={s}
                        stackId="a"
                        fill={CHART_COLORS[s]}
                        radius={s === "critical" ? [4, 4, 0, 0] : 0}
                      />
                    ))}
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </GlassCard>

          {/* Data Types Distribution */}
          <GlassCard className="p-5">
            <div className="flex items-start justify-between mb-4">
              <div>
                <h2 className="text-sm font-semibold" style={{ color: "oklch(0.18 0.015 250)" }}>
                  Data Types Distribution
                </h2>
                <p className="mt-0.5 text-xs" style={{ color: "oklch(0.55 0.015 250)" }}>
                  Last {range} days
                </p>
              </div>
              <button
                className="text-xs rounded-lg border px-2 py-1"
                style={{
                  color: "oklch(0.44 0.17 255)",
                  borderColor: "oklch(0.44 0.17 255 / 0.25)",
                  background: "oklch(0.44 0.17 255 / 0.06)",
                }}
              >
                Last {range} Days
              </button>
            </div>

            <div className="flex justify-center">
              <ResponsiveContainer width={160} height={160}>
                <PieChart>
                  <Pie
                    data={MOCK_DONUT}
                    cx="50%"
                    cy="50%"
                    innerRadius={48}
                    outerRadius={72}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {MOCK_DONUT.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: "white",
                      border: "1px solid oklch(0.88 0.008 250)",
                      borderRadius: 10,
                      fontSize: 12,
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>

            <div className="mt-3 space-y-2">
              {MOCK_DONUT.map((item) => (
                <div key={item.name} className="flex items-center gap-2 text-xs">
                  <span className="size-2.5 shrink-0 rounded-sm" style={{ background: item.color }} />
                  <span className="flex-1" style={{ color: "oklch(0.35 0.015 250)" }}>
                    {item.name}
                  </span>
                  <span className="font-semibold tabular-nums" style={{ color: "oklch(0.22 0.015 250)" }}>
                    {item.value}%
                  </span>
                </div>
              ))}
            </div>
          </GlassCard>
        </div>

        {/* ── Channel Activity + Channel Status ────────────────────────────── */}
        <div className="grid gap-4 lg:grid-cols-2">
          {/* Channel Activity */}
          <GlassCard className="p-5">
            <div className="flex items-start justify-between mb-5">
              <div>
                <h2 className="text-sm font-semibold" style={{ color: "oklch(0.18 0.015 250)" }}>
                  Channel Activity
                </h2>
                <p className="mt-0.5 text-xs" style={{ color: "oklch(0.55 0.015 250)" }}>
                  Events detected per channel
                </p>
              </div>
              <button
                className="text-xs rounded-lg border px-2 py-1"
                style={{
                  color: "oklch(0.44 0.17 255)",
                  borderColor: "oklch(0.44 0.17 255 / 0.25)",
                  background: "oklch(0.44 0.17 255 / 0.06)",
                }}
              >
                Last {range} Days
              </button>
            </div>

            <div className="space-y-3">
              {MOCK_CHANNEL_ACTIVITY.map((ch) => (
                <div key={ch.name} className="flex items-center gap-3">
                  <div
                    className="flex size-9 shrink-0 items-center justify-center rounded-xl"
                    style={{ background: "oklch(0.93 0.006 250)" }}
                  >
                    <ch.icon className="size-4" style={{ color: "oklch(0.44 0.17 255)" }} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-medium" style={{ color: "oklch(0.25 0.015 250)" }}>
                        {ch.name}
                      </span>
                      <div className="flex items-center gap-2">
                        <span className="text-xs tabular-nums font-semibold" style={{ color: "oklch(0.22 0.015 250)" }}>
                          {ch.events.toLocaleString()}
                        </span>
                        <span className="text-[10px]" style={{ color: "oklch(0.60 0.015 250)" }}>
                          {ch.pct}%
                        </span>
                      </div>
                    </div>
                    <div
                      className="h-1.5 rounded-full overflow-hidden"
                      style={{ background: "oklch(0.90 0.006 250)" }}
                    >
                      <div
                        className="h-full rounded-full transition-all"
                        style={{
                          width: `${ch.pct}%`,
                          background: "oklch(0.44 0.17 255)",
                        }}
                      />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </GlassCard>

          {/* Channel Status */}
          <GlassCard className="p-5">
            <div className="flex items-start justify-between mb-5">
              <div>
                <h2 className="text-sm font-semibold" style={{ color: "oklch(0.18 0.015 250)" }}>
                  Channel Status
                </h2>
                <p className="mt-0.5 text-xs" style={{ color: "oklch(0.55 0.015 250)" }}>
                  Integration connection health
                </p>
              </div>
              <button
                className="flex items-center gap-1 text-xs font-medium"
                style={{ color: "oklch(0.44 0.17 255)" }}
              >
                View All
                <ExternalLink className="size-3" />
              </button>
            </div>

            <div className="space-y-2">
              {channels.isLoading ? (
                Array.from({ length: 4 }).map((_, i) => (
                  <div key={i} className="flex items-center gap-3 rounded-xl p-3">
                    <SkeletonLine w="w-9" h="h-9" />
                    <div className="flex-1 space-y-1.5">
                      <SkeletonLine w="w-24" h="h-3" />
                      <SkeletonLine w="w-16" h="h-2.5" />
                    </div>
                  </div>
                ))
              ) : (
                CHANNEL_STATUS.map((ch) => {
                  const row = channels.data?.find((x) => x.channel_type === ch.key);
                  const connected = !!row?.connected_at;
                  return (
                    <div
                      key={ch.key}
                      className="flex items-center gap-3 rounded-xl p-3 transition-colors cursor-pointer hover:bg-white/50"
                      style={{ border: "1px solid oklch(0.92 0.006 250)" }}
                    >
                      <div
                        className="flex size-9 shrink-0 items-center justify-center rounded-xl"
                        style={{
                          background: connected
                            ? "oklch(0.54 0.17 155 / 0.10)"
                            : "oklch(0.93 0.006 250)",
                        }}
                      >
                        <ch.icon
                          className="size-4"
                          style={{
                            color: connected
                              ? "oklch(0.44 0.17 155)"
                              : "oklch(0.55 0.015 250)",
                          }}
                        />
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-semibold" style={{ color: "oklch(0.22 0.015 250)" }}>
                          {ch.label}
                        </p>
                        <p className="text-[10px]" style={{ color: "oklch(0.60 0.012 250)" }}>
                          {connected ? `Synced ${ch.lastSync}` : "Not connected"}
                        </p>
                      </div>
                      <div className="flex items-center gap-2">
                        {connected ? (
                          <span
                            className="flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-semibold"
                            style={{
                              background: "oklch(0.54 0.17 155 / 0.12)",
                              color: "oklch(0.40 0.17 155)",
                            }}
                          >
                            <Wifi className="size-2.5" />
                            Connected
                          </span>
                        ) : (
                          <span
                            className="flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-semibold"
                            style={{
                              background: "oklch(0.55 0.22 25 / 0.10)",
                              color: "oklch(0.50 0.22 25)",
                            }}
                          >
                            <WifiOff className="size-2.5" />
                            Connect
                          </span>
                        )}
                        <ChevronRight className="size-3.5" style={{ color: "oklch(0.65 0.012 250)" }} />
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </GlassCard>
        </div>

        {/* ── Recent Findings ──────────────────────────────────────────────── */}
        <GlassCard className="p-5">
          <div className="flex items-start justify-between mb-5">
            <div>
              <h2 className="text-sm font-semibold" style={{ color: "oklch(0.18 0.015 250)" }}>
                Recent Findings
              </h2>
              <p className="mt-0.5 text-xs" style={{ color: "oklch(0.55 0.015 250)" }}>
                Latest policy violations detected across channels
              </p>
            </div>
            <button
              className="flex items-center gap-1 text-xs font-medium"
              style={{ color: "oklch(0.44 0.17 255)" }}
            >
              View All
              <ExternalLink className="size-3" />
            </button>
          </div>

          {/* Desktop table */}
          <div className="hidden sm:block overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr style={{ borderBottom: "1px solid oklch(0.90 0.006 250)" }}>
                  {["Severity", "Data Type", "Title", "Source", "User", "Time", "Action"].map((h) => (
                    <th
                      key={h}
                      className="pb-3 pr-4 text-left font-semibold first:pl-0 last:pr-0"
                      style={{ color: "oklch(0.55 0.015 250)" }}
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y" style={{ borderColor: "oklch(0.92 0.005 250)" }}>
                {MOCK_FINDINGS.map((f) => (
                  <tr key={f.id} className="group">
                    <td className="py-3 pr-4">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="py-3 pr-4">
                      <ClassificationChip classification={f.dataType} />
                    </td>
                    <td
                      className="py-3 pr-4 max-w-[200px] truncate font-medium"
                      style={{ color: "oklch(0.22 0.015 250)" }}
                    >
                      {f.title}
                    </td>
                    <td className="py-3 pr-4" style={{ color: "oklch(0.45 0.015 250)" }}>
                      {f.source}
                    </td>
                    <td className="py-3 pr-4 font-mono" style={{ color: "oklch(0.50 0.015 250)" }}>
                      {f.user.replace(/@.*/, "@…")}
                    </td>
                    <td className="py-3 pr-4" style={{ color: "oklch(0.60 0.012 250)" }}>
                      {f.time}
                    </td>
                    <td className="py-3">
                      <button
                        className="flex items-center gap-1 rounded-lg border px-2 py-1 text-[10px] font-medium opacity-0 group-hover:opacity-100 transition-opacity"
                        style={{
                          color: "oklch(0.44 0.17 255)",
                          borderColor: "oklch(0.44 0.17 255 / 0.25)",
                        }}
                      >
                        Review
                        <ArrowRight className="size-3" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Mobile list */}
          <div className="sm:hidden space-y-3">
            {MOCK_FINDINGS.map((f) => (
              <div
                key={f.id}
                className="rounded-xl border p-3"
                style={{ borderColor: "oklch(0.90 0.006 250)" }}
              >
                <div className="flex items-start justify-between gap-2">
                  <SeverityBadge severity={f.severity} />
                  <span className="text-[10px]" style={{ color: "oklch(0.60 0.012 250)" }}>
                    {f.time}
                  </span>
                </div>
                <p className="mt-2 text-xs font-medium" style={{ color: "oklch(0.22 0.015 250)" }}>
                  {f.title}
                </p>
                <div className="mt-1.5 flex items-center gap-2">
                  <ClassificationChip classification={f.dataType} />
                  <span className="text-[10px]" style={{ color: "oklch(0.55 0.015 250)" }}>
                    {f.source}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </GlassCard>

        {/* ── Events by decision (preserved from original) ─────────────────── */}
        {rows.length > 0 && (
          <GlassCard className="p-5">
            <h2 className="text-sm font-semibold mb-1" style={{ color: "oklch(0.18 0.015 250)" }}>
              Events by Decision
            </h2>
            <p className="text-xs mb-5" style={{ color: "oklch(0.55 0.015 250)" }}>
              Daily volume — last {range} days
            </p>
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={Array.from({ length: range }, (_, i) => {
                    const d = new Date();
                    d.setDate(d.getDate() - (range - 1 - i));
                    const key = d.toISOString().slice(0, 10);
                    const bucket = rows.filter((r) => r.created_at.slice(0, 10) === key);
                    const counts: Record<string, number> = { allow: 0, warn: 0, block: 0, log: 0 };
                    for (const r of bucket) counts[r.decision] = (counts[r.decision] ?? 0) + 1;
                    return { date: key.slice(5), ...counts };
                  })}
                >
                  <CartesianGrid vertical={false} stroke="oklch(0.90 0.006 250)" />
                  <XAxis dataKey="date" tickLine={false} axisLine={false} fontSize={11} stroke="oklch(0.60 0.012 250)" />
                  <YAxis tickLine={false} axisLine={false} fontSize={11} width={28} stroke="oklch(0.60 0.012 250)" allowDecimals={false} />
                  <Tooltip
                    cursor={{ fill: "oklch(0.44 0.17 255 / 0.06)", radius: 6 }}
                    contentStyle={{
                      background: "white",
                      border: "1px solid oklch(0.88 0.008 250)",
                      borderRadius: 12,
                      fontSize: 12,
                    }}
                  />
                  <Bar dataKey="allow" stackId="a" fill="oklch(0.54 0.17 155)" />
                  <Bar dataKey="warn" stackId="a" fill="oklch(0.62 0.18 75)" />
                  <Bar dataKey="block" stackId="a" fill="oklch(0.55 0.22 25)" />
                  <Bar dataKey="log" stackId="a" fill="oklch(0.65 0.015 250)" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </GlassCard>
        )}

        {/* Bottom padding */}
        <div className="h-4" />
      </div>
    </AppShell>
  );
}

// Keep unused imports in scope to avoid TS errors
void CheckCircle2;
