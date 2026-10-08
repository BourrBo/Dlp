import { createFileRoute, Outlet, useNavigate, useRouterState } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { ArrowDown, ArrowUp, Search } from "lucide-react";

import { AppShell } from "@/components/app-shell";
import { SeverityBadge } from "@/components/severity-badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { INCIDENT_FIXTURES, type Incident } from "@/lib/fixtures/incidents";
import type { FindingStatus } from "@/lib/fixtures/findings";
import { supabase } from "@/integrations/supabase/client";
import { API_BASE_URL, FIXTURE_MODE } from "@/lib/env";

export const Route = createFileRoute("/_authenticated/incidents")({
  head: () => ({
    meta: [
      { title: "Incidents — DLP Console" },
      { name: "description", content: "Review and manage DLP incidents." },
    ],
  }),
  component: IncidentsPage,
});

type SortKey = "severity" | "status" | "first_seen" | "last_seen";
type SortState = { key: SortKey; direction: "asc" | "desc" };

const STATUS_OPTIONS: FindingStatus[] = ["open", "triaged", "fixed", "accepted", "false_positive"];
const INCIDENT_STATUSES = new Set<string>(STATUS_OPTIONS);
const SEVERITY_ORDER: Record<string, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

function normalizeIncident(value: unknown): Incident {
  if (!value || typeof value !== "object") {
    throw new Error("The incidents API returned an invalid incident.");
  }

  const row = value as Record<string, unknown>;
  const requiredFields = [
    "id",
    "org_id",
    "number",
    "title",
    "severity",
    "source",
    "data_type",
    "first_seen",
    "last_seen",
    "created_at",
    "updated_at",
  ];
  if (
    requiredFields.some((field) => typeof row[field] !== "string") ||
    typeof row.status !== "string" ||
    !INCIDENT_STATUSES.has(row.status) ||
    (row.assignee !== null && typeof row.assignee !== "string") ||
    (row.policy_id !== null && typeof row.policy_id !== "string")
  ) {
    throw new Error("The incidents API returned an invalid incident.");
  }

  return {
    id: row.id as string,
    org_id: row.org_id as string,
    number: row.number as string,
    title: row.title as string,
    severity: row.severity as string,
    status: row.status as FindingStatus,
    assignee: row.assignee as string | null,
    source: row.source as string,
    policy_id: row.policy_id as string | null,
    data_type: row.data_type as string,
    first_seen: row.first_seen as string,
    last_seen: row.last_seen as string,
    created_at: row.created_at as string,
    updated_at: row.updated_at as string,
  };
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function IncidentsPage() {
  const navigate = useNavigate();
  const showingIncidentDetail = useRouterState({
    select: (state) =>
      state.matches.some((match) => match.routeId === "/_authenticated/incidents/$incidentId"),
  });
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("all");
  const [severity, setSeverity] = useState("all");
  const [sort, setSort] = useState<SortState>({
    key: "first_seen",
    direction: "desc",
  });

  useEffect(() => {
    let active = true;

    async function loadIncidents() {
      setLoading(true);
      setError(null);
      try {
        if (FIXTURE_MODE) {
          if (active) setIncidents(INCIDENT_FIXTURES);
          return;
        }

        const { data, error: sessionError } = await supabase.auth.getSession();
        if (sessionError) throw sessionError;
        const accessToken = data.session?.access_token;
        if (!accessToken) throw new Error("Your session has expired. Sign in and try again.");

        const response = await fetch(
          `${API_BASE_URL.replace(/\/+$/, "")}/api/v1/incidents`,
          { headers: { Authorization: `Bearer ${accessToken}` } },
        );
        if (!response.ok) {
          let message = `Request failed (${response.status}).`;
          try {
            const body: unknown = await response.json();
            if (
              body &&
              typeof body === "object" &&
              "detail" in body &&
              typeof body.detail === "string"
            ) {
              message = body.detail;
            }
          } catch {
            // Keep the HTTP status message when the response has no JSON body.
          }
          throw new Error(message);
        }

        const body: unknown = await response.json();
        if (!Array.isArray(body)) {
          throw new Error("The incidents API returned an invalid response.");
        }
        const records = body.map(normalizeIncident);
        if (active) setIncidents(records);
      } catch (loadError) {
        if (active) {
          setError(
            loadError instanceof Error ? loadError.message : "Unable to load incidents.",
          );
        }
      } finally {
        if (active) setLoading(false);
      }
    }

    void loadIncidents();
    return () => {
      active = false;
    };
  }, [reloadToken]);

  const filteredIncidents = useMemo(() => {
    const query = search.trim().toLowerCase();
    const matches = incidents.filter((incident) => {
      const matchesQuery =
        query === "" ||
        [
          incident.number,
          incident.title,
          incident.source,
          incident.data_type,
          incident.assignee ?? "",
        ].some((value) => value.toLowerCase().includes(query));
      return (
        matchesQuery &&
        (status === "all" || incident.status === status) &&
        (severity === "all" || incident.severity === severity)
      );
    });

    return matches.sort((left, right) => {
      const comparison =
        sort.key === "severity"
          ? (SEVERITY_ORDER[left.severity] ?? -1) - (SEVERITY_ORDER[right.severity] ?? -1)
          : String(left[sort.key]).localeCompare(String(right[sort.key]));
      return sort.direction === "asc" ? comparison : -comparison;
    });
  }, [incidents, search, severity, sort, status]);

  function toggleSort(key: SortKey) {
    setSort((current) => ({
      key,
      direction: current.key === key && current.direction === "asc" ? "desc" : "asc",
    }));
  }

  function renderSortHeader(label: string, key: SortKey) {
    const active = sort.key === key;
    const SortIcon = sort.direction === "asc" ? ArrowUp : ArrowDown;
    return (
      <button
        type="button"
        onClick={() => toggleSort(key)}
        className="inline-flex items-center gap-1 font-medium text-muted-foreground hover:text-foreground"
        aria-label={`Sort by ${label}${active ? ` (${sort.direction})` : ""}`}
      >
        {label}
        {active && <SortIcon className="size-3.5" aria-hidden="true" />}
      </button>
    );
  }

  if (showingIncidentDetail) return <Outlet />;

  return (
    <AppShell>
      <main className="space-y-6 px-6 py-6" style={{ minHeight: "calc(100vh - 56px)" }}>
        <header>
          <h1 className="text-2xl font-bold" style={{ color: "oklch(0.15 0.015 250)" }}>
            Incidents
          </h1>
          <p className="mt-1 text-sm" style={{ color: "oklch(0.52 0.018 250)" }}>
            Review and manage detected data protection incidents.
          </p>
        </header>

        <section
          className="space-y-3 rounded-2xl border p-4 backdrop-blur-xl sm:p-5"
          aria-label="Incident search and filters"
          style={{
            background: "oklch(0.97 0 0 / 0.78)",
            borderColor: "oklch(1 0 0 / 0.56)",
            boxShadow: "0 4px 12px oklch(0 0 0 / 0.045), 0 10px 28px oklch(0 0 0 / 0.025)",
          }}
        >
          <div className="relative">
            <Search
              className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
              aria-hidden="true"
            />
            <Input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search incidents..."
              aria-label="Search incidents"
              className="h-10 border-white/70 bg-white/60 pl-9"
            />
          </div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            <label>
              <span className="sr-only">Filter by status</span>
              <select
                aria-label="Filter by status"
                value={status}
                onChange={(event) => setStatus(event.target.value)}
                className="h-9 w-full rounded-md border border-input bg-white/60 px-3 text-xs text-foreground outline-none focus-visible:ring-1 focus-visible:ring-ring"
              >
                <option value="all">All statuses</option>
                {STATUS_OPTIONS.map((value) => (
                  <option key={value} value={value}>
                    {value.replace(/_/g, " ")}
                  </option>
                ))}
              </select>
            </label>
            <label>
              <span className="sr-only">Filter by severity</span>
              <select
                aria-label="Filter by severity"
                value={severity}
                onChange={(event) => setSeverity(event.target.value)}
                className="h-9 w-full rounded-md border border-input bg-white/60 px-3 text-xs text-foreground outline-none focus-visible:ring-1 focus-visible:ring-ring"
              >
                <option value="all">All severities</option>
                {["critical", "high", "medium", "low"].map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </label>
          </div>
        </section>

        <section
          className="overflow-hidden rounded-2xl border backdrop-blur-xl"
          aria-label="Incident list"
          style={{
            background: "oklch(0.97 0 0 / 0.78)",
            borderColor: "oklch(1 0 0 / 0.56)",
            boxShadow: "0 4px 12px oklch(0 0 0 / 0.045), 0 10px 28px oklch(0 0 0 / 0.025)",
          }}
        >
          <div className="border-b px-5 py-4" style={{ borderColor: "oklch(0.90 0.006 250)" }}>
            <h2 className="text-sm font-semibold">Incident queue</h2>
            <p className="mt-0.5 text-xs text-muted-foreground" aria-live="polite">
              Showing {filteredIncidents.length} of {incidents.length} incidents
            </p>
          </div>
          {loading ? (
            <p className="p-8 text-center text-sm text-muted-foreground" role="status">
              Loading incidents...
            </p>
          ) : error ? (
            <div className="space-y-3 p-8 text-center" role="alert">
              <p className="text-sm text-destructive">Unable to load incidents: {error}</p>
              <button
                type="button"
                onClick={() => setReloadToken((token) => token + 1)}
                className="text-sm font-medium underline"
              >
                Retry
              </button>
            </div>
          ) : filteredIncidents.length === 0 ? (
            <p className="p-8 text-center text-sm text-muted-foreground">
              No incidents match your search or filters.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Number</TableHead>
                  <TableHead>Title</TableHead>
                  <TableHead>{renderSortHeader("Severity", "severity")}</TableHead>
                  <TableHead>{renderSortHeader("Status", "status")}</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Data type</TableHead>
                  <TableHead>Assignee</TableHead>
                  <TableHead>{renderSortHeader("First seen", "first_seen")}</TableHead>
                  <TableHead>{renderSortHeader("Last seen", "last_seen")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredIncidents.map((incident) => (
                  <TableRow
                    key={incident.id}
                    className="cursor-pointer"
                    tabIndex={0}
                    role="link"
                    aria-label={`Open incident ${incident.number}: ${incident.title}`}
                    onClick={() =>
                      void navigate({
                        to: "/incidents/$incidentId",
                        params: { incidentId: incident.id },
                      })
                    }
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        void navigate({
                          to: "/incidents/$incidentId",
                          params: { incidentId: incident.id },
                        });
                      }
                    }}
                  >
                    <TableCell className="font-mono text-xs font-semibold">
                      {incident.number}
                    </TableCell>
                    <TableCell className="min-w-56 font-medium">{incident.title}</TableCell>
                    <TableCell>
                      <SeverityBadge severity={incident.severity} />
                    </TableCell>
                    <TableCell className="capitalize">
                      {incident.status.replace(/_/g, " ")}
                    </TableCell>
                    <TableCell>{incident.source}</TableCell>
                    <TableCell>{incident.data_type.replace(/_/g, " ")}</TableCell>
                    <TableCell>{incident.assignee ?? "Unassigned"}</TableCell>
                    <TableCell className="whitespace-nowrap text-xs">
                      {formatDate(incident.first_seen)}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-xs">
                      {formatDate(incident.last_seen)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </section>
      </main>
    </AppShell>
  );
}
