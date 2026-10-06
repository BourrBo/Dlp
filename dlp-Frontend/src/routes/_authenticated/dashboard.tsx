import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
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
  Activity,
  AlertTriangle,
  ArrowRight,
  Calendar,
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
import { toast } from "sonner";

import { supabase } from "@/integrations/supabase/client";
import { useOrg } from "@/hooks/use-org";
import { API_BASE_URL, FIXTURE_MODE } from "@/lib/env";
import serverSecurityArtwork from "../../../../dlp images/Glossy Server Security Icon.png";
import { AppShell } from "@/components/app-shell";
import { ClassificationChip } from "@/components/classification-chip";
import { DecisionBadge } from "@/components/decision-badge";
import { SeverityBadge } from "@/components/severity-badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";

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

type OverviewEvent = {
  id: string;
  decision: string;
  data_type: string;
  channel: string;
  destination: string | null;
  confidence: number | string;
  created_at: string;
};

type OverviewResponse = {
  total_events: number;
  decision_counts: Record<string, number>;
  data_type_counts: Record<string, number>;
  channel_counts: Record<string, number>;
  daily_trend: { date: string; count: number }[];
  recent_events: OverviewEvent[];
  severity_counts: Record<string, number>;
  classification_counts: Record<string, number>;
};

type KpiDefinition = {
  label: string;
  value: number;
  previousValue: number;
  metric: string;
  icon: typeof FolderOpen;
  color: string;
  bg: string;
  inverted: boolean;
  pct: number;
  spark: number[];
};

const MOCK_TREND_VALUES = [
  { critical: 4, high: 18, medium: 32, low: 25 },
  { critical: 8, high: 24, medium: 42, low: 31 },
  { critical: 5, high: 15, medium: 37, low: 28 },
  { critical: 11, high: 29, medium: 48, low: 36 },
  { critical: 7, high: 22, medium: 39, low: 22 },
  { critical: 9, high: 17, medium: 44, low: 33 },
  { critical: 6, high: 26, medium: 35, low: 27 },
];

const MOCK_TREND = MOCK_TREND_VALUES.map((counts, i) => {
  const d = new Date();
  d.setDate(d.getDate() - (6 - i));
  return {
    date: d.toISOString().slice(5, 10),
    ...counts,
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

const DATA_TYPE_COLORS = [
  "oklch(0.55 0.22 25)",
  "oklch(0.44 0.17 255)",
  "oklch(0.62 0.18 75)",
  "oklch(0.54 0.17 155)",
  "oklch(0.60 0.18 310)",
  "oklch(0.65 0.015 250)",
];

const CHANNEL_INFO = {
  browser: { label: "Browser Agent", icon: Chrome },
  email: { label: "Email", icon: Mail },
  cloud_storage: { label: "Cloud storage", icon: HardDrive },
  api: { label: "API", icon: Activity },
} as const;

const MOCK_KPIS: KpiDefinition[] = [
  {
    label: "Total Findings",
    value: 847,
    previousValue: 0,
    metric: "total",
    icon: FolderOpen,
    color: "oklch(0.44 0.17 255)",
    bg: "oklch(0.44 0.17 255 / 0.08)",
    inverted: true,
    pct: 12,
    spark: [40, 55, 35, 70, 45, 80, 60],
  },
  {
    label: "Critical",
    value: 34,
    previousValue: 0,
    metric: "block",
    icon: ShieldAlert,
    color: "oklch(0.55 0.22 25)",
    bg: "oklch(0.55 0.22 25 / 0.08)",
    inverted: true,
    pct: -8,
    spark: [40, 55, 35, 70, 45, 80, 60],
  },
  {
    label: "High",
    value: 128,
    previousValue: 0,
    metric: "warn",
    icon: AlertTriangle,
    color: "oklch(0.62 0.18 45)",
    bg: "oklch(0.62 0.18 45 / 0.08)",
    inverted: true,
    pct: 5,
    spark: [40, 55, 35, 70, 45, 80, 60],
  },
  {
    label: "Data Types",
    value: 6,
    previousValue: 0,
    metric: "types",
    icon: Shield,
    color: "oklch(0.54 0.17 155)",
    bg: "oklch(0.54 0.17 155 / 0.08)",
    inverted: false,
    pct: 0,
    spark: [40, 55, 35, 70, 45, 80, 60],
  },
];

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
      className={`dashboard-elevated-card rounded-2xl border ${className}`}
      style={{
        background: "oklch(0.97 0 0 / 0.78)",
        borderColor: "oklch(1 0 0 / 0.56)",
        backdropFilter: "blur(16px)",
        boxShadow:
          "0 1px 2px oklch(0 0 0 / 0.04), 0 4px 12px oklch(0 0 0 / 0.045), 0 10px 28px oklch(0 0 0 / 0.025)",
        ...style,
      }}
    >
      {children}
    </div>
  );
}

function FindingSeverity({ severity }: { severity: string | null }) {
  if (severity === null) {
    return (
      <span
        className="inline-flex items-center rounded-full border border-border bg-muted/60 px-2 py-0.5 text-[11px] font-semibold tracking-[0.08em] uppercase text-muted-foreground"
        role="status"
        aria-label="Severity: Unknown"
      >
        Unknown
      </span>
    );
  }
  return <SeverityBadge severity={severity} />;
}

function SkeletonLine({ w = "w-full", h = "h-4" }: { w?: string; h?: string }) {
  return (
    <div
      className={`${w} ${h} rounded-md animate-pulse`}
      style={{ background: "oklch(0.90 0.005 250)" }}
    />
  );
}

function TrendBadge({ pct, inverted = false }: { pct: number | null; inverted?: boolean }) {
  if (pct === null) {
    return (
      <span className="inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold"
        style={{ background: "oklch(0.65 0.015 250 / 0.12)", color: "oklch(0.50 0.015 250)" }}>
        —
      </span>
    );
  }
  if (pct === 0) {
    return (
      <span className="inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold"
        style={{ background: "oklch(0.65 0.015 250 / 0.12)", color: "oklch(0.50 0.015 250)" }}>
        0%
      </span>
    );
  }
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
  const [scanOpen, setScanOpen] = useState(false);
  const [scanContent, setScanContent] = useState("");
  const [scanPending, setScanPending] = useState(false);
  const { data: orgId } = useOrg();
  const queryClient = useQueryClient();

  const events = useQuery({
    queryKey: ["dashboard-events", orgId, range],
    enabled: !!orgId,
    queryFn: async () => {
      if (FIXTURE_MODE) return null;
      const params = new URLSearchParams({ org_id: orgId!, days: String(range) });
      const response = await fetch(
        `${API_BASE_URL.replace(/\/+$/, "")}/api/overview?${params.toString()}`,
      );
      const data = await response.json().catch(() => null);
      if (!response.ok) {
        throw new Error(data?.detail ?? `Overview request failed (${response.status}).`);
      }
      return data as OverviewResponse;
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

  const overview = events.data;
  const totals = overview?.decision_counts ?? {};
  const dailyTrend = (overview?.daily_trend ?? []).map(({ date, count }) => ({
    date: date.slice(5),
    count,
  }));

  const typeDistribution = useMemo(() => {
    if (FIXTURE_MODE) return MOCK_DONUT;
    return Object.entries(overview?.data_type_counts ?? {}).map(([name, value], i) => ({
      name: name.replace(/[_-]+/g, " ").replace(/\b\w/g, (part) => part.toUpperCase()),
      value,
      color: DATA_TYPE_COLORS[i % DATA_TYPE_COLORS.length],
    }));
  }, [overview]);

  const channelActivity = useMemo(() => {
    if (FIXTURE_MODE) {
      return MOCK_CHANNEL_ACTIVITY.map(({ name, ...channel }) => ({ ...channel, label: name }));
    }
    const counts = Object.entries(overview?.channel_counts ?? {});
    const maxCount = Math.max(1, ...counts.map(([, count]) => count));
    return counts
      .sort((a, b) => b[1] - a[1])
      .map(([channel, count]) => ({
        ...CHANNEL_INFO[channel as keyof typeof CHANNEL_INFO] ?? {
          label: channel.replace(/[_-]+/g, " ").replace(/\b\w/g, (part) => part.toUpperCase()),
          icon: Activity,
        },
        events: count,
        pct: Math.round((count / maxCount) * 100),
      }));
  }, [overview]);

  const recentFindings = (overview?.recent_events ?? []).slice(0, 5);
  const displayedFindings = FIXTURE_MODE
    ? MOCK_FINDINGS
    : recentFindings.map((finding) => ({
        id: finding.id,
        severity: null,
        classification: null,
        title: `${finding.data_type.replace(/[_-]+/g, " ")} detected`,
        source: CHANNEL_INFO[finding.channel as keyof typeof CHANNEL_INFO]?.label ?? finding.channel,
        user: "—",
        time: new Date(finding.created_at).toLocaleString(),
      }));

  const totalFindings = FIXTURE_MODE ? 847 : overview?.total_events ?? 0;
  const dataTypeCount = FIXTURE_MODE ? 6 : Object.keys(overview?.data_type_counts ?? {}).length;
  const totalDailyEvents = dailyTrend.map((day) => day.count);
  const totalSpark = Array.from({ length: 7 }, (_, index) => {
    const start = Math.floor((index * totalDailyEvents.length) / 7);
    const end = Math.floor(((index + 1) * totalDailyEvents.length) / 7);
    return totalDailyEvents.slice(start, end).reduce((sum, count) => sum + count, 0);
  });

  const liveKpis: KpiDefinition[] = ([
    {
      label: "Total Findings",
      value: totalFindings,
      previousValue: 0,
      metric: "total",
      icon: FolderOpen,
      color: "oklch(0.44 0.17 255)",
      bg: "oklch(0.44 0.17 255 / 0.08)",
      inverted: true,
    },
    {
      label: "Blocked",
      value: totals["block"] ?? 0,
      previousValue: 0,
      metric: "block",
      icon: ShieldAlert,
      color: "oklch(0.55 0.22 25)",
      bg: "oklch(0.55 0.22 25 / 0.08)",
      inverted: true,
    },
    {
      label: "Warned",
      value: totals["warn"] ?? 0,
      previousValue: 0,
      metric: "warn",
      icon: AlertTriangle,
      color: "oklch(0.62 0.18 45)",
      bg: "oklch(0.62 0.18 45 / 0.08)",
      inverted: true,
    },
    {
      label: "Data Types",
      value: dataTypeCount,
      previousValue: 0,
      metric: "types",
      icon: Shield,
      color: "oklch(0.54 0.17 155)",
      bg: "oklch(0.54 0.17 155 / 0.08)",
      inverted: false,
    },
  ] satisfies Omit<KpiDefinition, "pct" | "spark">[]).map((kpi) => ({
    ...kpi,
    pct: null,
    spark: kpi.metric === "total" ? totalSpark : [],
  }));
  const kpis = FIXTURE_MODE ? MOCK_KPIS : liveKpis;

  async function runScan(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!orgId || FIXTURE_MODE) return;
    setScanPending(true);
    try {
      const { data, error } = await supabase.auth.getUser();
      if (error) throw error;
      if (!data.user) throw new Error("Sign in before running a scan.");

      const response = await fetch(`${API_BASE_URL.replace(/\/+$/, "")}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          org_id: orgId,
          user_id: data.user.id,
          channel: "api",
          destination: "manual-dashboard-scan",
          content: scanContent,
          filename: null,
        }),
      });
      const result = await response.json().catch(() => null);
      if (!response.ok) {
        throw new Error(result?.detail ?? `Scan request failed (${response.status}).`);
      }
      if (!result || typeof result.decision !== "string" || typeof result.reason !== "string") {
        throw new Error("The scan service returned an invalid response.");
      }

      toast.success(`Scan ${result.decision}: ${result.reason}`);
      setScanOpen(false);
      setScanContent("");
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["dashboard-events", orgId] }),
        queryClient.invalidateQueries({ queryKey: ["events", orgId] }),
      ]);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Could not run scan.");
    } finally {
      setScanPending(false);
    }
  }

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
      <style>{`
        .dashboard-elevated-card {
          transition: transform 220ms ease, box-shadow 220ms ease;
        }
        @media (hover: hover) and (prefers-reduced-motion: no-preference) {
          .dashboard-elevated-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 12px 30px oklch(0 0 0 / 0.12), 0 4px 10px oklch(0 0 0 / 0.07) !important;
          }
        }
        @media (prefers-reduced-motion: reduce) {
          .dashboard-elevated-card { transition: none; }
        }
      `}</style>
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
          <label
            className="flex items-center gap-2 rounded-xl border px-3 py-2 text-sm transition-colors hover:bg-white/60"
            style={{
              background: "oklch(1 0 0 / 0.7)",
              borderColor: "oklch(0.88 0.008 250)",
              color: "oklch(0.30 0.015 250)",
            }}
          >
            <Calendar className="size-4" style={{ color: "oklch(0.44 0.17 255)" }} />
            <span className="sr-only">Dashboard date range</span>
            <select
              aria-label="Dashboard date range"
              className="cursor-pointer appearance-none bg-transparent font-medium outline-none"
              value={range}
              onChange={(event) => setRange(event.target.value === "30" ? 30 : 7)}
            >
              <option value={7}>{dateLabel} — Last 7 days</option>
              <option value={30}>{dateLabel} — Last 30 days</option>
            </select>
            <ChevronDown className="size-3.5" style={{ color: "oklch(0.55 0.015 250)" }} />
          </label>
        </div>

        {/* ── Hero card ────────────────────────────────────────────────────── */}
        <div
          className="dashboard-elevated-card relative overflow-hidden rounded-2xl border p-7 backdrop-blur-xl"
          style={{
            background: "linear-gradient(135deg, oklch(0.12 0 0 / 0.94), oklch(0.20 0 0 / 0.88))",
            borderColor: "oklch(1 0 0 / 0.18)",
            boxShadow:
              "0 12px 36px oklch(0 0 0 / 0.28), inset 0 1px 0 oklch(1 0 0 / 0.10)",
          }}
        >
          {/* Decorative circles */}
          <div
            className="absolute -top-8 -right-8 size-40 rounded-full opacity-10"
            style={{ background: "oklch(1 0 0 / 0.30)" }}
          />
          <div
            className="absolute top-4 right-32 size-20 rounded-full opacity-10"
            style={{ background: "oklch(1 0 0 / 0.24)" }}
          />
          <div
            className="absolute -bottom-10 right-16 size-28 rounded-full opacity-10"
            style={{ background: "oklch(1 0 0 / 0.20)" }}
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
                  type="button"
                  disabled={!orgId || FIXTURE_MODE}
                  onClick={() => setScanOpen(true)}
                  title={FIXTURE_MODE ? "Scanning requires a configured Supabase account" : undefined}
                  className="flex items-center gap-2 rounded-xl px-4 py-2.5 text-sm font-semibold transition-all hover:shadow-lg"
                  style={{
                    background: "oklch(1 0 0)",
                    color: "oklch(0.25 0.015 250)",
                    boxShadow: "0 2px 8px oklch(0 0 0 / 0.15)",
                  }}
                >
                  <ScanSearch className="size-4" style={{ color: "oklch(0.35 0 0)" }} />
                  Run New Scan
                  <ArrowRight className="size-3.5" />
                </button>
                <Link
                  to="/events"
                  className="flex items-center gap-2 rounded-xl border px-4 py-2.5 text-sm font-semibold transition-opacity hover:opacity-80"
                  style={{
                    background: "oklch(1 0 0 / 0.12)",
                    borderColor: "oklch(1 0 0 / 0.25)",
                    color: "oklch(0.95 0.003 250)",
                  }}
                >
                  <FileText className="size-4" />
                  View Findings
                </Link>
              </div>
            </div>

              {/* Hero illustration */}
              <div
                className="relative flex w-full max-w-72 shrink-0 items-center justify-center overflow-hidden rounded-[28px] border p-4 sm:w-[32%] sm:min-w-64"
                style={{
                  aspectRatio: "1 / 1",
                  background: "linear-gradient(145deg, oklch(1 0 0 / 0.10), oklch(1 0 0 / 0.04))",
                  borderColor: "oklch(1 0 0 / 0.20)",
                  boxShadow:
                    "0 10px 28px oklch(0 0 0 / 0.24), inset 0 1px 0 oklch(1 0 0 / 0.16)",
                }}
              >
                <img
                  src={serverSecurityArtwork}
                  alt="Servers protected by a shield and lock"
                  className="relative z-10 block h-full w-full object-contain drop-shadow-[0_12px_24px_rgba(0,0,0,0.32)]"
                />
                <div
                  aria-hidden="true"
                  className="pointer-events-none absolute inset-x-0 bottom-0 z-20 h-10"
                  style={{
                    background:
                      "linear-gradient(to bottom, transparent, oklch(0.16 0 0 / 0.18))",
                  }}
                />
              </div>
            </div>
          </div>

        {/* ── KPI cards ────────────────────────────────────────────────────── */}
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {kpis.map((kpi) => (
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
                    {kpi.spark.map((value, i) => (
                      <div
                        key={i}
                        className="flex-1 rounded-sm"
                        style={{
                          height: `${value === 0 ? 0 : Math.max(8, (value / Math.max(...kpi.spark, 1)) * 100)}%`,
                          background: kpi.color,
                          opacity: i === 6 ? 1 : 0.45,
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
                  {FIXTURE_MODE ? "Findings Trend" : "Event Trend"}
                </h2>
                <p className="mt-0.5 text-xs" style={{ color: "oklch(0.55 0.015 250)" }}>
                  {FIXTURE_MODE ? "Daily findings by severity"                   : "Daily event volume"}
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
              {FIXTURE_MODE
                ? (["critical", "high", "medium", "low"] as const).map((severity) => (
                    <div key={severity} className="flex items-center gap-1.5 text-xs" style={{ color: "oklch(0.50 0.015 250)" }}>
                      <span className="size-2 rounded-sm" style={{ background: CHART_COLORS[severity] }} />
                      {severity.charAt(0).toUpperCase() + severity.slice(1)}
                    </div>
                  ))
                : (
                    <div className="flex items-center gap-1.5 text-xs" style={{ color: "oklch(0.50 0.015 250)" }}>
                      <span className="size-2 rounded-sm" style={{ background: "oklch(0.44 0.17 255)" }} />
                      Events
                    </div>
                  )}
            </div>

            <div className="h-60">
              {events.isLoading ? (
                <div className="flex h-full items-center justify-center">
                  <RefreshCw className="size-5 animate-spin" style={{ color: "oklch(0.65 0.015 250)" }} />
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={FIXTURE_MODE ? MOCK_TREND : dailyTrend}
                    barSize={14}
                    barCategoryGap="30%"
                  >
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
                    {FIXTURE_MODE
                      ? (["low", "medium", "high", "critical"] as const).map((severity) => (
                          <Bar
                            key={severity}
                            dataKey={severity}
                            stackId="a"
                            fill={CHART_COLORS[severity]}
                            radius={severity === "critical" ? [4, 4, 0, 0] : 0}
                          />
                        ))
                      : (
                          <Bar
                            dataKey="count"
                            fill="oklch(0.44 0.17 255)"
                            radius={[4, 4, 0, 0]}
                          />
                        )}
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
                type="button"
                onClick={() => setRange((value) => value === 7 ? 30 : 7)}
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
                    data={typeDistribution}
                    cx="50%"
                    cy="50%"
                    innerRadius={48}
                    outerRadius={72}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {typeDistribution.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} />
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
              {typeDistribution.map((item) => (
                <div key={item.name} className="flex items-center gap-2 text-xs">
                  <span className="size-2.5 shrink-0 rounded-sm" style={{ background: item.color }} />
                  <span className="flex-1" style={{ color: "oklch(0.35 0.015 250)" }}>
                    {item.name}
                  </span>
                  <span className="font-semibold tabular-nums" style={{ color: "oklch(0.22 0.015 250)" }}>
                    {FIXTURE_MODE
                      ? item.value
                      : Math.round((item.value / Math.max(totalFindings, 1)) * 100)}
                    %
                  </span>
                </div>
              ))}
              {!typeDistribution.length && (
                <p className="text-center text-xs text-muted-foreground">No findings in this date range.</p>
              )}
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
                type="button"
                onClick={() => setRange((value) => value === 7 ? 30 : 7)}
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
              {channelActivity.map((ch) => (
                <div key={ch.label} className="flex items-center gap-3">
                  <div
                    className="flex size-9 shrink-0 items-center justify-center rounded-xl"
                    style={{ background: "oklch(0.93 0.006 250)" }}
                  >
                    <ch.icon className="size-4" style={{ color: "oklch(0.44 0.17 255)" }} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-medium" style={{ color: "oklch(0.25 0.015 250)" }}>
                        {ch.label}
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
              {!channelActivity.length && (
                <p className="text-center text-xs text-muted-foreground">No channel activity in this date range.</p>
              )}
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
                type="button"
                disabled
                title="Channel management is not available yet"
                className="flex items-center gap-1 text-xs font-medium cursor-not-allowed opacity-60"
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
                  const connectedAt = row?.connected_at;
                  const connected = !!connectedAt;
                  return (
                    <div
                      key={ch.key}
                      className="flex items-center gap-3 rounded-xl p-3"
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
                          {connectedAt
                            ? `Synced ${FIXTURE_MODE ? ch.lastSync : new Date(connectedAt).toLocaleString()}`
                            : "Not connected"}
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
            <Link
              to="/events"
              className="flex items-center gap-1 text-xs font-medium"
              style={{ color: "oklch(0.44 0.17 255)" }}
            >
              View All
              <ExternalLink className="size-3" />
            </Link>
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
                {events.isLoading ? (
                  <tr>
                    <td colSpan={7} className="py-8 text-center text-muted-foreground">Loading findings...</td>
                  </tr>
                ) : displayedFindings.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-8 text-center text-muted-foreground">No findings in this date range.</td>
                  </tr>
                ) : displayedFindings.map((finding) => (
                  <tr key={finding.id} className="group">
                    <td className="py-3 pr-4">
                      <FindingSeverity severity={finding.severity} />
                    </td>
                    <td className="py-3 pr-4">
                      <ClassificationChip classification={FIXTURE_MODE ? finding.dataType : null} />
                    </td>
                    <td
                      className="py-3 pr-4 max-w-[200px] truncate font-medium"
                      style={{ color: "oklch(0.22 0.015 250)" }}
                    >
                      {finding.title}
                    </td>
                    <td className="py-3 pr-4" style={{ color: "oklch(0.45 0.015 250)" }}>
                      {finding.source}
                    </td>
                    <td className="py-3 pr-4 font-mono" style={{ color: "oklch(0.50 0.015 250)" }}>
                      {finding.user.replace(/@.*/, "@…")}
                    </td>
                    <td className="py-3 pr-4" style={{ color: "oklch(0.60 0.012 250)" }}>
                      {finding.time}
                    </td>
                    <td className="py-3">
                      <Link
                        to="/events"
                        className="flex items-center gap-1 rounded-lg border px-2 py-1 text-[10px] font-medium opacity-0 group-hover:opacity-100 transition-opacity"
                        style={{
                          color: "oklch(0.44 0.17 255)",
                          borderColor: "oklch(0.44 0.17 255 / 0.25)",
                        }}
                      >
                        Review
                        <ArrowRight className="size-3" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Mobile list */}
          <div className="sm:hidden space-y-3">
            {displayedFindings.map((finding) => (
              <Link
                key={finding.id}
                to="/events"
                aria-label={`View details for ${finding.title}`}
                className="rounded-xl border p-3"
                style={{ borderColor: "oklch(0.90 0.006 250)" }}
              >
                <div className="flex items-start justify-between gap-2">
                  <FindingSeverity severity={finding.severity} />
                  <span className="text-[10px]" style={{ color: "oklch(0.60 0.012 250)" }}>
                    {finding.time}
                  </span>
                </div>
                <p className="mt-2 text-xs font-medium" style={{ color: "oklch(0.22 0.015 250)" }}>
                  {finding.title}
                </p>
                <div className="mt-1.5 flex items-center gap-2">
                  <ClassificationChip classification={FIXTURE_MODE ? finding.dataType : null} />
                  <span className="text-[10px]" style={{ color: "oklch(0.55 0.015 250)" }}>
                    {finding.source}
                  </span>
                </div>
              </Link>
            ))}
            {!events.isLoading && !displayedFindings.length && (
              <p className="py-8 text-center text-xs text-muted-foreground">No findings in this date range.</p>
            )}
          </div>
        </GlassCard>

        {/* ── Events by decision (preserved from original) ─────────────────── */}
        {!FIXTURE_MODE && (overview?.total_events ?? 0) > 0 && (
          <GlassCard className="p-5">
            <h2 className="text-sm font-semibold mb-1" style={{ color: "oklch(0.18 0.015 250)" }}>
              Event Volume
            </h2>
            <p className="text-xs mb-5" style={{ color: "oklch(0.55 0.015 250)" }}>
              Daily volume — last {range} days
            </p>
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={dailyTrend}
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
                  <Bar dataKey="count" fill="oklch(0.44 0.17 255)" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </GlassCard>
        )}

        {/* Bottom padding */}
        <div className="h-4" />
      </div>
      <Dialog open={scanOpen} onOpenChange={(open) => !scanPending && setScanOpen(open)}>
        <DialogContent>
          <form onSubmit={runScan} className="space-y-4">
            <DialogHeader>
              <DialogTitle>Run a new scan</DialogTitle>
              <DialogDescription>
                Enter text to scan using your organization&apos;s configured detection rules and policies.
              </DialogDescription>
            </DialogHeader>
            <Textarea
              autoFocus
              required
              aria-label="Text to scan"
              placeholder="Paste text to scan..."
              value={scanContent}
              onChange={(event) => setScanContent(event.target.value)}
              className="min-h-40"
            />
            <DialogFooter>
              <Button type="button" variant="outline" disabled={scanPending} onClick={() => setScanOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={scanPending || !scanContent.trim()}>
                {scanPending ? "Scanning..." : "Scan text"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </AppShell>
  );
}
