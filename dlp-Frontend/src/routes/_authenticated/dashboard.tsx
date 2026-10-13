import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import {
  Area,
  AreaChart,
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
import serverSecurityArtwork from "../../../../dlp images/Metallic Server Security Icons.png";
import gmailIcon from "../../../../dlp images/Pastel Gmail Envelope Icon.png";
import googleDriveIcon from "../../../../dlp images/Pastel Google Drive Ribbon Logo.png";
import chromeIcon from "../../../../dlp images/Soft Gradient Chrome Icon.png";
import slackIcon from "../../../../dlp images/Slack Multicolor Logo on White.png";
import { AppShell } from "@/components/app-shell";
import { ClassificationChip } from "@/components/classification-chip";
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
  { name: "PII", value: 38, color: "oklch(0.25 0 0)" },
  { name: "Credentials", value: 22, color: "oklch(0.40 0 0)" },
  { name: "Financial", value: 18, color: "oklch(0.55 0 0)" },
  { name: "Health", value: 11, color: "oklch(0.68 0 0)" },
  { name: "Secrets", value: 7, color: "oklch(0.78 0 0)" },
  { name: "Other", value: 4, color: "oklch(0.88 0 0)" },
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
  critical: "oklch(0.20 0 0)",
  high: "oklch(0.38 0 0)",
  medium: "oklch(0.58 0 0)",
  low: "oklch(0.78 0 0)",
};

const DATA_TYPE_COLORS = [
  "oklch(0.25 0 0)",
  "oklch(0.40 0 0)",
  "oklch(0.55 0 0)",
  "oklch(0.68 0 0)",
  "oklch(0.78 0 0)",
  "oklch(0.88 0 0)",
];

const CHANNEL_INFO = {
  browser: { label: "Browser Agent", icon: Chrome },
  email: { label: "Email", icon: Mail },
  cloud_storage: { label: "Cloud storage", icon: HardDrive },
  api: { label: "API", icon: Activity },
} as const;

const CHANNEL_LOGOS: Record<string, string> = {
  gmail: gmailIcon,
  email: gmailIcon,
  drive: googleDriveIcon,
  google_drive: googleDriveIcon,
  cloud_storage: googleDriveIcon,
  browser: chromeIcon,
  browser_agent: chromeIcon,
  chrome: chromeIcon,
  slack: slackIcon,
};

function ChannelIcon({
  name,
  fallback: FallbackIcon,
  className = "size-6 object-contain",
}: {
  name?: string;
  fallback?: React.ComponentType<{ className?: string; style?: React.CSSProperties }>;
  className?: string;
}) {
  const normalized = name?.toLowerCase().replace(/[\s-]+/g, "_") ?? "";
  const logo =
    CHANNEL_LOGOS[normalized] ??
    (normalized.includes("gmail") || normalized.includes("email")
      ? gmailIcon
      : normalized.includes("drive")
      ? googleDriveIcon
      : normalized.includes("browser") || normalized.includes("chrome")
      ? chromeIcon
      : normalized.includes("slack")
      ? slackIcon
      : null);

  if (logo) {
    return <img src={logo} alt={name ?? "Channel"} className={className} />;
  }

  if (FallbackIcon) {
    return <FallbackIcon className="size-3.5" style={{ color: "var(--muted-foreground)" }} />;
  }

  return null;
}

const MOCK_KPIS: KpiDefinition[] = [
  {
    label: "Total Findings",
    value: 847,
    previousValue: 0,
    metric: "total",
    icon: FolderOpen,
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
    inverted: false,
    pct: 0,
    spark: [40, 55, 35, 70, 45, 80, 60],
  },
  {
    label: "Active Policies",
    value: 12,
    previousValue: 0,
    metric: "policies",
    icon: ShieldAlert,
    inverted: false,
    pct: 0,
    spark: [8, 10, 10, 11, 11, 12, 12],
  },
];

// ─── Helpers ────────────────────────────────────────────────────────────────

function GlassCard({
  className = "",
  children,
  style,
  hoverable = true,
}: {
  className?: string;
  children: React.ReactNode;
  style?: React.CSSProperties;
  hoverable?: boolean;
}) {
  return (
    <div
      className={`${hoverable ? "dashboard-card" : ""} rounded-2xl border ${className}`}
      style={{
        background: "var(--card)",
        borderColor: "var(--border)",
        backdropFilter: "blur(14px)",
        boxShadow:
          "0 1px 2px oklch(0 0 0 / 0.03), 0 2px 8px oklch(0 0 0 / 0.035)",
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
      style={{ background: "var(--muted)" }}
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
        style={{ background: "var(--muted)", color: "var(--muted-foreground)" }}>
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
          ? "oklch(0.54 0.17 155 / 0.10)"
          : "oklch(0.55 0.22 25 / 0.10)",
        color: good ? "oklch(0.40 0.17 155)" : "oklch(0.48 0.22 25)",
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

function MiniSparkBars({ data, color }: { data: number[]; color: string }) {
  const max = Math.max(...data, 1);
  return (
    <div className="flex items-end gap-[3px] h-5">
      {data.map((value, i) => (
        <div
          key={i}
          className="flex-1 rounded-[2px] min-w-[3px]"
          style={{
            height: `${value === 0 ? 0 : Math.max(12, (value / max) * 100)}%`,
            background: color,
            opacity: i === data.length - 1 ? 1 : 0.3,
          }}
        />
      ))}
    </div>
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
      inverted: true,
    },
    {
      label: "Blocked",
      value: totals["block"] ?? 0,
      previousValue: 0,
      metric: "block",
      icon: ShieldAlert,
      inverted: true,
    },
    {
      label: "Warned",
      value: totals["warn"] ?? 0,
      previousValue: 0,
      metric: "warn",
      icon: AlertTriangle,
      inverted: true,
    },
    {
      label: "Data Types",
      value: dataTypeCount,
      previousValue: 0,
      metric: "types",
      icon: Shield,
      inverted: false,
    },
    {
      label: "Active Policies",
      value: 12,
      previousValue: 0,
      metric: "policies",
      icon: ShieldAlert,
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
      const { data, error } = await supabase.auth.getSession();
      if (error) throw error;
      const accessToken = data.session?.access_token;
      if (!accessToken) throw new Error("Sign in before running a scan.");

      const response = await fetch(`${API_BASE_URL.replace(/\/+$/, "")}/api/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          org_id: orgId,
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

  const donutTotal = typeDistribution.reduce((s, d) => s + d.value, 0);

  return (
    <AppShell>
      <style>{`
        .dashboard-card {
          transition: transform 200ms cubic-bezier(0.22,1,0.36,1), box-shadow 200ms cubic-bezier(0.22,1,0.36,1);
        }
        @media (hover: hover) and (prefers-reduced-motion: no-preference) {
          .dashboard-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px oklch(0 0 0 / 0.08), 0 2px 6px oklch(0 0 0 / 0.05) !important;
          }
        }
        @media (prefers-reduced-motion: reduce) {
          .dashboard-card { transition: none; }
        }
        .hero-overview-card {
          background: linear-gradient(135deg, rgba(255, 255, 255, 0.88) 0%, rgba(246, 248, 251, 0.78) 50%, rgba(238, 242, 246, 0.68) 100%);
          border: 1px solid rgba(255, 255, 255, 0.85);
          box-shadow:
            0 10px 30px -5px rgba(0, 0, 0, 0.04),
            0 20px 40px -15px rgba(0, 0, 0, 0.05),
            inset 0 1px 0 rgba(255, 255, 255, 0.95);
          backdrop-filter: blur(20px);
          -webkit-backdrop-filter: blur(20px);
          transition: transform 250ms cubic-bezier(0.22, 1, 0.36, 1), box-shadow 250ms cubic-bezier(0.22, 1, 0.36, 1);
        }
        @media (hover: hover) and (prefers-reduced-motion: no-preference) {
          .hero-overview-card:hover {
            transform: translateY(-2px);
            box-shadow:
              0 14px 34px -4px rgba(0, 0, 0, 0.07),
              0 24px 44px -12px rgba(0, 0, 0, 0.06),
              inset 0 1px 0 rgba(255, 255, 255, 0.95) !important;
          }
        }
        .dark .hero-overview-card {
          background: linear-gradient(135deg, rgba(255, 255, 255, 0.08) 0%, rgba(255, 255, 255, 0.04) 50%, rgba(255, 255, 255, 0.02) 100%);
          border: 1px solid rgba(255, 255, 255, 0.12);
          box-shadow:
            0 10px 30px -5px rgba(0, 0, 0, 0.35),
            inset 0 1px 0 rgba(255, 255, 255, 0.15);
        }
        @media (hover: hover) and (prefers-reduced-motion: no-preference) {
          .dark .hero-overview-card:hover {
            box-shadow:
              0 16px 36px -4px rgba(0, 0, 0, 0.45),
              inset 0 1px 0 rgba(255, 255, 255, 0.2) !important;
          }
        }
        @media (prefers-reduced-motion: reduce) {
          .hero-overview-card { transition: none; }
        }
        .area-chart-gradient-critical { stop-color: oklch(0.20 0 0); }
        .area-chart-gradient-high { stop-color: oklch(0.38 0 0); }
        .area-chart-gradient-medium { stop-color: oklch(0.58 0 0); }
        .area-chart-gradient-low { stop-color: oklch(0.78 0 0); }
      `}</style>
      <div
        className="px-6 py-5 space-y-5"
        style={{ minHeight: "calc(100vh - 48px)" }}
      >
        {/* ── Page header ─────────────────────────────────────────────────── */}
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold" style={{ color: "var(--foreground)" }}>
              Hello, Ashish 👋
            </h1>
            <p className="mt-0.5 text-[13px]" style={{ color: "var(--muted-foreground)" }}>
              Here's your organization's data loss prevention overview.
            </p>
          </div>
          {/* Date range selector */}
          <label
            className="flex items-center gap-2 rounded-xl border px-3 py-[7px] text-[13px] transition-colors hover:bg-accent/50 cursor-pointer"
            style={{
              background: "var(--card)",
              borderColor: "var(--border)",
              color: "var(--foreground)",
            }}
          >
            <Calendar className="size-3.5" style={{ color: "var(--muted-foreground)" }} />
            <span className="sr-only">Dashboard date range</span>
            <select
              aria-label="Dashboard date range"
              className="cursor-pointer appearance-none bg-transparent font-medium outline-none text-[13px]"
              value={range}
              onChange={(event) => setRange(event.target.value === "30" ? 30 : 7)}
            >
              <option value={7}>{dateLabel} — Last 7 days</option>
              <option value={30}>{dateLabel} — Last 30 days</option>
            </select>
            <ChevronDown className="size-3" style={{ color: "var(--muted-foreground)" }} />
          </label>
        </div>

        {/* ── Hero card ────────────────────────────────────────────────────── */}
        <div
          className="hero-overview-card relative overflow-hidden rounded-[24px] p-6"
        >
          {/* Black-greyish ambient gradient on the right side to suit the illustration */}
          <div
            className="pointer-events-none absolute inset-y-0 right-0 w-full sm:w-[55%] overflow-hidden rounded-r-[24px]"
          >
            <div
              className="absolute inset-0"
              style={{
                background:
                  "linear-gradient(to left, rgba(18, 22, 28, 0.14) 0%, rgba(35, 42, 52, 0.07) 45%, transparent 100%)",
              }}
            />
            <div
              className="absolute -right-8 top-1/2 -translate-y-1/2 size-72 rounded-full blur-xl"
              style={{
                background:
                  "radial-gradient(circle, rgba(15, 20, 26, 0.25) 0%, rgba(35, 43, 54, 0.14) 45%, rgba(65, 75, 90, 0.04) 65%, transparent 75%)",
              }}
            />
          </div>

          <div className="relative z-10 flex flex-wrap items-center justify-between gap-6">
            <div className="max-w-lg">
              <div className="mb-3 inline-flex items-center gap-1.5 rounded-full border border-black/[0.07] dark:border-white/[0.12] bg-white/70 dark:bg-white/[0.08] backdrop-blur-md px-2.5 py-1 text-[11px] font-medium text-neutral-700 dark:text-neutral-300 shadow-xs">
                <Shield className="size-3 text-neutral-600 dark:text-neutral-400" strokeWidth={2.2} />
                <span>Real-time Protection Active</span>
              </div>
              <h2 className="text-[22px] font-bold tracking-tight text-neutral-900 dark:text-white">
                Detect. Monitor. Prevent.
              </h2>
              <p className="mt-1.5 max-w-lg text-[13px] leading-relaxed text-neutral-600 dark:text-neutral-400">
                Keep your sensitive data safe across all channels with real-time monitoring and intelligent policy enforcement.
              </p>
              <div className="mt-4 flex flex-wrap gap-2.5">
                <button
                  type="button"
                  disabled={!orgId || FIXTURE_MODE}
                  onClick={() => setScanOpen(true)}
                  title={FIXTURE_MODE ? "Scanning requires a configured Supabase account" : undefined}
                  className="flex items-center gap-2 rounded-xl bg-neutral-950 px-4 py-2 text-[13px] font-medium text-white shadow-xs transition-all hover:bg-neutral-800 hover:shadow-md active:scale-[0.98] disabled:opacity-50 disabled:pointer-events-none cursor-pointer"
                >
                  <ScanSearch className="size-3.5" />
                  <span>Run New Scan</span>
                  <ArrowRight className="size-3" />
                </button>
                <Link
                  to="/events"
                  className="flex items-center gap-2 rounded-xl border border-black/[0.08] dark:border-white/[0.12] bg-white/80 dark:bg-white/[0.08] backdrop-blur-md px-4 py-2 text-[13px] font-medium text-neutral-800 dark:text-neutral-200 shadow-xs transition-all hover:bg-white hover:text-black dark:hover:bg-white/[0.15] hover:shadow-sm active:scale-[0.98]"
                >
                  <FileText className="size-3.5 text-neutral-600 dark:text-neutral-400" />
                  <span>View Findings</span>
                </Link>
              </div>
            </div>

            {/* Hero illustration */}
            <div className="relative flex shrink-0 items-center justify-center sm:w-auto">
              <div
                className="pointer-events-none absolute inset-0 -m-6 rounded-full blur-md"
                style={{
                  background:
                    "radial-gradient(circle, rgba(16, 21, 28, 0.26) 0%, rgba(38, 46, 58, 0.14) 45%, rgba(65, 75, 90, 0.04) 65%, transparent 75%)",
                }}
              />
              <img
                src={serverSecurityArtwork}
                alt="Servers protected by a shield and lock"
                className="relative z-10 block h-36 w-auto sm:h-40 md:h-44 object-contain drop-shadow-[0_12px_24px_rgba(0,0,0,0.18)]"
              />
            </div>
          </div>
        </div>

        {/* ── KPI cards ────────────────────────────────────────────────────── */}
        <div className="grid gap-3 grid-cols-2 sm:grid-cols-3 xl:grid-cols-5">
          {kpis.map((kpi) => (
            <GlassCard key={kpi.label} className="p-4">
              <div className="flex items-start justify-between">
                <div
                  className="flex size-8 items-center justify-center rounded-lg"
                  style={{ background: "var(--muted)" }}
                >
                  <kpi.icon className="size-4" style={{ color: "var(--muted-foreground)" }} />
                </div>
                <TrendBadge pct={kpi.pct} inverted={kpi.inverted} />
              </div>
              {events.isLoading ? (
                <div className="mt-3 space-y-2">
                  <SkeletonLine w="w-16" h="h-6" />
                  <SkeletonLine w="w-20" h="h-3" />
                </div>
              ) : (
                <>
                  <p
                    className="mt-2.5 font-mono text-2xl font-bold tabular-nums"
                    style={{ color: "var(--foreground)" }}
                  >
                    {kpi.value.toLocaleString()}
                  </p>
                  <p className="mt-0.5 text-[11px] font-medium" style={{ color: "var(--muted-foreground)" }}>
                    {kpi.label}
                  </p>
                  <p className="text-[10px]" style={{ color: "var(--muted-foreground)", opacity: 0.7 }}>
                    vs previous {range} days
                  </p>
                  {/* Mini trend bars */}
                  <div className="mt-2">
                    <MiniSparkBars data={kpi.spark} color="var(--foreground)" />
                  </div>
                </>
              )}
            </GlassCard>
          ))}
        </div>

        {/* ── Charts row ───────────────────────────────────────────────────── */}
        <div className="grid gap-4 lg:grid-cols-3">
          {/* Findings Trend */}
          <GlassCard className="p-5 lg:col-span-2" hoverable={false}>
            <div className="flex items-start justify-between mb-4">
              <div>
                <h2 className="text-[13px] font-semibold" style={{ color: "var(--foreground)" }}>
                  {FIXTURE_MODE ? "Findings Trend" : "Event Trend"}
                </h2>
                <p className="mt-0.5 text-[11px]" style={{ color: "var(--muted-foreground)" }}>
                  {FIXTURE_MODE ? "Daily findings by severity" : "Daily event volume"}
                </p>
              </div>
              <div className="flex items-center gap-1">
                {([7, 30] as const).map((r) => (
                  <button
                    key={r}
                    onClick={() => setRange(r)}
                    className="rounded-lg px-2 py-1 text-[11px] font-medium transition-colors"
                    style={
                      range === r
                        ? {
                            background: "var(--foreground)",
                            color: "var(--background)",
                          }
                        : {
                            color: "var(--muted-foreground)",
                          }
                    }
                  >
                    {r}d
                  </button>
                ))}
              </div>
            </div>

            {/* Legend */}
            <div className="flex flex-wrap gap-3 mb-3">
              {FIXTURE_MODE
                ? (["critical", "high", "medium", "low"] as const).map((severity) => (
                    <div key={severity} className="flex items-center gap-1.5 text-[11px]" style={{ color: "var(--muted-foreground)" }}>
                      <span className="size-2 rounded-sm" style={{ background: CHART_COLORS[severity] }} />
                      {severity.charAt(0).toUpperCase() + severity.slice(1)}
                    </div>
                  ))
                : (
                    <div className="flex items-center gap-1.5 text-[11px]" style={{ color: "var(--muted-foreground)" }}>
                      <span className="size-2 rounded-sm" style={{ background: "var(--foreground)" }} />
                      Events
                    </div>
                  )}
            </div>

            <div className="h-56">
              {events.isLoading ? (
                <div className="flex h-full items-center justify-center">
                  <RefreshCw className="size-4 animate-spin" style={{ color: "var(--muted-foreground)" }} />
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart
                    data={FIXTURE_MODE ? MOCK_TREND : dailyTrend}
                  >
                    <defs>
                      <linearGradient id="gradCritical" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="oklch(0.20 0 0)" stopOpacity={0.3} />
                        <stop offset="100%" stopColor="oklch(0.20 0 0)" stopOpacity={0.02} />
                      </linearGradient>
                      <linearGradient id="gradHigh" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="oklch(0.38 0 0)" stopOpacity={0.25} />
                        <stop offset="100%" stopColor="oklch(0.38 0 0)" stopOpacity={0.02} />
                      </linearGradient>
                      <linearGradient id="gradMedium" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="oklch(0.58 0 0)" stopOpacity={0.2} />
                        <stop offset="100%" stopColor="oklch(0.58 0 0)" stopOpacity={0.02} />
                      </linearGradient>
                      <linearGradient id="gradLow" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="oklch(0.78 0 0)" stopOpacity={0.15} />
                        <stop offset="100%" stopColor="oklch(0.78 0 0)" stopOpacity={0.02} />
                      </linearGradient>
                      <linearGradient id="gradSingle" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="var(--foreground)" stopOpacity={0.2} />
                        <stop offset="100%" stopColor="var(--foreground)" stopOpacity={0.02} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid vertical={false} stroke="var(--border)" strokeDasharray="4 4" />
                    <XAxis
                      dataKey="date"
                      tickLine={false}
                      axisLine={false}
                      fontSize={10}
                      stroke="var(--muted-foreground)"
                    />
                    <YAxis
                      tickLine={false}
                      axisLine={false}
                      fontSize={10}
                      width={28}
                      stroke="var(--muted-foreground)"
                      allowDecimals={false}
                    />
                    <Tooltip
                      contentStyle={{
                        background: "var(--popover)",
                        border: "1px solid var(--border)",
                        borderRadius: 10,
                        fontSize: 11,
                        boxShadow: "0 4px 16px oklch(0 0 0 / 0.08)",
                        color: "var(--foreground)",
                      }}
                    />
                    {FIXTURE_MODE
                      ? (["low", "medium", "high", "critical"] as const).map((severity) => (
                          <Area
                            key={severity}
                            type="monotone"
                            dataKey={severity}
                            stackId="a"
                            stroke={CHART_COLORS[severity]}
                            strokeWidth={1.5}
                            fill={`url(#grad${severity.charAt(0).toUpperCase() + severity.slice(1)})`}
                          />
                        ))
                      : (
                          <Area
                            type="monotone"
                            dataKey="count"
                            stroke="var(--foreground)"
                            strokeWidth={1.5}
                            fill="url(#gradSingle)"
                          />
                        )}
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </div>
          </GlassCard>

          {/* Data Types Distribution */}
          <GlassCard className="p-5" hoverable={false}>
            <div className="flex items-start justify-between mb-3">
              <div>
                <h2 className="text-[13px] font-semibold" style={{ color: "var(--foreground)" }}>
                  Data Types Distribution
                </h2>
                <p className="mt-0.5 text-[11px]" style={{ color: "var(--muted-foreground)" }}>
                  Last {range} days
                </p>
              </div>
            </div>

            <div className="flex justify-center relative">
              <ResponsiveContainer width={150} height={150}>
                <PieChart>
                  <Pie
                    data={typeDistribution}
                    cx="50%"
                    cy="50%"
                    innerRadius={46}
                    outerRadius={68}
                    paddingAngle={2}
                    dataKey="value"
                    strokeWidth={0}
                  >
                    {typeDistribution.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: "var(--popover)",
                      border: "1px solid var(--border)",
                      borderRadius: 8,
                      fontSize: 11,
                      color: "var(--foreground)",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
              {/* Center label */}
              <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                <div className="text-center">
                  <p className="text-lg font-bold tabular-nums" style={{ color: "var(--foreground)" }}>
                    {donutTotal}
                  </p>
                  <p className="text-[9px] font-medium" style={{ color: "var(--muted-foreground)" }}>
                    Total
                  </p>
                </div>
              </div>
            </div>

            <div className="mt-3 space-y-1.5">
              {typeDistribution.map((item) => (
                <div key={item.name} className="flex items-center gap-2 text-[11px]">
                  <span className="size-2.5 shrink-0 rounded-[3px]" style={{ background: item.color }} />
                  <span className="flex-1" style={{ color: "var(--muted-foreground)" }}>
                    {item.name}
                  </span>
                  <span className="font-semibold tabular-nums" style={{ color: "var(--foreground)" }}>
                    {FIXTURE_MODE
                      ? item.value
                      : Math.round((item.value / Math.max(totalFindings, 1)) * 100)}
                    %
                  </span>
                </div>
              ))}
              {!typeDistribution.length && (
                <p className="text-center text-[11px] text-muted-foreground">No findings in this date range.</p>
              )}
            </div>
          </GlassCard>
        </div>

        {/* ── Channel Activity + Channel Status ────────────────────────────── */}
        <div className="grid gap-4 lg:grid-cols-2">
          {/* Channel Activity */}
          <GlassCard className="p-5" hoverable={false}>
            <div className="flex items-start justify-between mb-4">
              <div>
                <h2 className="text-[13px] font-semibold" style={{ color: "var(--foreground)" }}>
                  Channel Activity
                </h2>
                <p className="mt-0.5 text-[11px]" style={{ color: "var(--muted-foreground)" }}>
                  Events detected per channel
                </p>
              </div>
              <button
                type="button"
                onClick={() => setRange((value) => value === 7 ? 30 : 7)}
                className="text-[11px] rounded-lg border px-2 py-1 font-medium transition-colors hover:bg-accent/50"
                style={{
                  color: "var(--muted-foreground)",
                  borderColor: "var(--border)",
                }}
              >
                Last {range} Days
              </button>
            </div>

            <div className="space-y-2.5">
              {channelActivity.map((ch) => (
                <div key={ch.label} className="flex items-center gap-3">
                  <div
                    className="flex size-8 shrink-0 items-center justify-center rounded-lg border shadow-2xs overflow-hidden"
                    style={{
                      background: "#ffffff",
                      borderColor: "var(--border)",
                    }}
                  >
                    <ChannelIcon name={ch.label} fallback={ch.icon} className="size-6 object-contain" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[11px] font-medium" style={{ color: "var(--foreground)" }}>
                        {ch.label}
                      </span>
                      <div className="flex items-center gap-2">
                        <span className="text-[11px] tabular-nums font-semibold" style={{ color: "var(--foreground)" }}>
                          {ch.events.toLocaleString()}
                        </span>
                        <span className="text-[10px]" style={{ color: "var(--muted-foreground)" }}>
                          {ch.pct}%
                        </span>
                      </div>
                    </div>
                    <div
                      className="h-1 rounded-full overflow-hidden"
                      style={{ background: "var(--muted)" }}
                    >
                      <div
                        className="h-full rounded-full transition-all"
                        style={{
                          width: `${ch.pct}%`,
                          background: "var(--foreground)",
                          opacity: 0.6,
                        }}
                      />
                    </div>
                  </div>
                </div>
              ))}
              {!channelActivity.length && (
                <p className="text-center text-[11px] text-muted-foreground">No channel activity in this date range.</p>
              )}
            </div>
          </GlassCard>

          {/* Channel Status */}
          <GlassCard className="p-5" hoverable={false}>
            <div className="flex items-start justify-between mb-4">
              <div>
                <h2 className="text-[13px] font-semibold" style={{ color: "var(--foreground)" }}>
                  Channel Status
                </h2>
                <p className="mt-0.5 text-[11px]" style={{ color: "var(--muted-foreground)" }}>
                  Integration connection health
                </p>
              </div>
              <button
                type="button"
                disabled
                title="Channel management is not available yet"
                className="flex items-center gap-1 text-[11px] font-medium cursor-not-allowed opacity-50"
                style={{ color: "var(--muted-foreground)" }}
              >
                View All
                <ExternalLink className="size-2.5" />
              </button>
            </div>

            <div className="space-y-1.5">
              {channels.isLoading ? (
                Array.from({ length: 4 }).map((_, i) => (
                  <div key={i} className="flex items-center gap-3 rounded-xl p-2.5">
                    <SkeletonLine w="w-8" h="h-8" />
                    <div className="flex-1 space-y-1.5">
                      <SkeletonLine w="w-20" h="h-3" />
                      <SkeletonLine w="w-14" h="h-2.5" />
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
                      className="flex items-center gap-3 rounded-xl p-2.5 transition-colors hover:bg-accent/30"
                      style={{ border: "1px solid var(--border)" }}
                    >
                      <div
                        className="flex size-8 shrink-0 items-center justify-center rounded-lg border shadow-2xs overflow-hidden"
                        style={{
                          background: "#ffffff",
                          borderColor: "var(--border)",
                        }}
                      >
                        <ChannelIcon name={ch.key} fallback={ch.icon} className="size-6 object-contain" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-[11px] font-semibold" style={{ color: "var(--foreground)" }}>
                          {ch.label}
                        </p>
                        <p className="text-[10px]" style={{ color: "var(--muted-foreground)" }}>
                          {connectedAt
                            ? `Synced ${FIXTURE_MODE ? ch.lastSync : new Date(connectedAt).toLocaleString()}`
                            : "Not connected"}
                        </p>
                      </div>
                      <div className="flex items-center gap-1.5">
                        {connected ? (
                          <span
                            className="flex items-center gap-1 rounded-full px-2 py-0.5 text-[9px] font-semibold"
                            style={{
                              background: "oklch(0.54 0.17 155 / 0.10)",
                              color: "oklch(0.38 0.17 155)",
                            }}
                          >
                            <Wifi className="size-2" />
                            Connected
                          </span>
                        ) : (
                          <span
                            className="flex items-center gap-1 rounded-full px-2 py-0.5 text-[9px] font-semibold"
                            style={{
                              background: "oklch(0.55 0.22 25 / 0.08)",
                              color: "oklch(0.48 0.22 25)",
                            }}
                          >
                            <WifiOff className="size-2" />
                            Connect
                          </span>
                        )}
                        <ChevronRight className="size-3" style={{ color: "var(--muted-foreground)" }} />
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </GlassCard>
        </div>

        {/* ── Recent Findings ──────────────────────────────────────────────── */}
        <GlassCard className="p-5" hoverable={false}>
          <div className="flex items-start justify-between mb-4">
            <div>
              <h2 className="text-[13px] font-semibold" style={{ color: "var(--foreground)" }}>
                Recent Findings
              </h2>
              <p className="mt-0.5 text-[11px]" style={{ color: "var(--muted-foreground)" }}>
                Latest policy violations detected across channels
              </p>
            </div>
            <Link
              to="/events"
              className="flex items-center gap-1 text-[11px] font-medium transition-colors hover:opacity-70"
              style={{ color: "var(--muted-foreground)" }}
            >
              View All
              <ExternalLink className="size-2.5" />
            </Link>
          </div>

          {/* Desktop table */}
          <div className="hidden sm:block overflow-x-auto">
            <table className="w-full text-[11px]">
              <thead>
                <tr style={{ borderBottom: "1px solid var(--border)" }}>
                  {["Severity", "Data Type", "Title", "Source", "User", "Time", "Action"].map((h) => (
                    <th
                      key={h}
                      className="pb-2.5 pr-4 text-left font-semibold first:pl-0 last:pr-0"
                      style={{ color: "var(--muted-foreground)" }}
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y" style={{ borderColor: "var(--border)" }}>
                {events.isLoading ? (
                  <tr>
                    <td colSpan={7} className="py-8 text-center text-muted-foreground text-[11px]">Loading findings...</td>
                  </tr>
                ) : displayedFindings.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-8 text-center text-muted-foreground text-[11px]">No findings in this date range.</td>
                  </tr>
                ) : displayedFindings.map((finding) => (
                  <tr
                    key={finding.id}
                    className="group transition-colors"
                    style={{ cursor: "default" }}
                    onMouseEnter={(e) => e.currentTarget.style.background = "var(--accent)"}
                    onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}
                  >
                    <td className="py-2.5 pr-4">
                      <FindingSeverity severity={finding.severity} />
                    </td>
                    <td className="py-2.5 pr-4">
                      <ClassificationChip classification={FIXTURE_MODE ? finding.dataType : null} />
                    </td>
                    <td
                      className="py-2.5 pr-4 max-w-[180px] truncate font-medium"
                      style={{ color: "var(--foreground)" }}
                    >
                      {finding.title}
                    </td>
                    <td className="py-2.5 pr-4" style={{ color: "var(--muted-foreground)" }}>
                      {finding.source}
                    </td>
                    <td className="py-2.5 pr-4 font-mono" style={{ color: "var(--muted-foreground)" }}>
                      {finding.user.replace(/@.*/, "@…")}
                    </td>
                    <td className="py-2.5 pr-4" style={{ color: "var(--muted-foreground)" }}>
                      {finding.time}
                    </td>
                    <td className="py-2.5">
                      <Link
                        to="/events"
                        className="flex items-center gap-1 rounded-lg border px-2 py-0.5 text-[10px] font-medium opacity-0 group-hover:opacity-100 transition-opacity"
                        style={{
                          color: "var(--foreground)",
                          borderColor: "var(--border)",
                        }}
                      >
                        Review
                        <ArrowRight className="size-2.5" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Mobile list */}
          <div className="sm:hidden space-y-2">
            {displayedFindings.map((finding) => (
              <Link
                key={finding.id}
                to="/events"
                aria-label={`View details for ${finding.title}`}
                className="rounded-xl border p-3 block transition-colors hover:bg-accent/30"
                style={{ borderColor: "var(--border)" }}
              >
                <div className="flex items-start justify-between gap-2">
                  <FindingSeverity severity={finding.severity} />
                  <span className="text-[10px]" style={{ color: "var(--muted-foreground)" }}>
                    {finding.time}
                  </span>
                </div>
                <p className="mt-1.5 text-[11px] font-medium" style={{ color: "var(--foreground)" }}>
                  {finding.title}
                </p>
                <div className="mt-1 flex items-center gap-2">
                  <ClassificationChip classification={FIXTURE_MODE ? finding.dataType : null} />
                  <span className="text-[10px]" style={{ color: "var(--muted-foreground)" }}>
                    {finding.source}
                  </span>
                </div>
              </Link>
            ))}
            {!events.isLoading && !displayedFindings.length && (
              <p className="py-8 text-center text-[11px] text-muted-foreground">No findings in this date range.</p>
            )}
          </div>
        </GlassCard>

        {/* ── Events by decision (preserved from original) ─────────────────── */}
        {!FIXTURE_MODE && (overview?.total_events ?? 0) > 0 && (
          <GlassCard className="p-5" hoverable={false}>
            <h2 className="text-[13px] font-semibold mb-1" style={{ color: "var(--foreground)" }}>
              Event Volume
            </h2>
            <p className="text-[11px] mb-4" style={{ color: "var(--muted-foreground)" }}>
              Daily volume — last {range} days
            </p>
            <div className="h-48">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={dailyTrend}>
                  <defs>
                    <linearGradient id="gradVolume" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="var(--foreground)" stopOpacity={0.15} />
                      <stop offset="100%" stopColor="var(--foreground)" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid vertical={false} stroke="var(--border)" strokeDasharray="4 4" />
                  <XAxis dataKey="date" tickLine={false} axisLine={false} fontSize={10} stroke="var(--muted-foreground)" />
                  <YAxis tickLine={false} axisLine={false} fontSize={10} width={28} stroke="var(--muted-foreground)" allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      background: "var(--popover)",
                      border: "1px solid var(--border)",
                      borderRadius: 10,
                      fontSize: 11,
                      color: "var(--foreground)",
                    }}
                  />
                  <Area type="monotone" dataKey="count" stroke="var(--foreground)" strokeWidth={1.5} fill="url(#gradVolume)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </GlassCard>
        )}

        {/* Bottom padding */}
        <div className="h-3" />
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
