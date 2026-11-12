import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { formatDateTime } from "@/lib/dlp";
import { getPlatformStatus, platformFetch } from "@/lib/platform-api";

export const Route = createFileRoute("/_authenticated/platform")({
  head: () => ({ meta: [{ title: "Platform — DLP Console" }] }),
  component: PlatformPage,
});

type Row = Record<string, unknown>;

const SECTIONS = [
  { id: "policies", label: "Policies", path: "/policies", idKey: "policy_id", columns: ["name", "action", "enabled", "priority", "version", "updated_at"] },
  { id: "destinations", label: "Destinations", path: "/destinations", idKey: "destination_id", columns: ["destination_class", "kind", "pattern"] },
  { id: "exceptions", label: "Exceptions", path: "/exceptions", idKey: "exception_id", columns: ["reason", "enabled", "approver_id", "expires_at", "created_at"] },
  { id: "approvals", label: "Approvals", path: "/approvals", idKey: "approval_id", columns: ["action", "status", "requested_by", "justification", "expires_at", "created_at"] },
  { id: "connectors", label: "Connectors", path: "/connectors", idKey: "id", columns: [] },
  { id: "audit", label: "Audit log", path: "/audit/events", idKey: "event_id", columns: ["occurred_at", "action", "outcome", "resource_type", "actor_type", "actor_role"] },
] as const;

function cell(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "string" && /^\d{4}-\d{2}-\d{2}T/.test(value)) return formatDateTime(value);
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function Section({ section }: { section: (typeof SECTIONS)[number] }) {
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: ["platform", section.id],
    queryFn: async () => {
      const data = await platformFetch<Row[] | { items?: Row[] }>(section.path);
      return Array.isArray(data) ? data : (data.items ?? []);
    },
    retry: false,
  });
  const decide = useMutation({
    mutationFn: ({ id, verb }: { id: string; verb: "approve" | "reject" }) =>
      platformFetch<Row>(`/approvals/${id}/${verb}`, { method: "POST", body: JSON.stringify({}) }),
    onSuccess: () => {
      toast.success("Decision recorded");
      void queryClient.invalidateQueries({ queryKey: ["platform", "approvals"] });
    },
    onError: (error: Error) => toast.error(error.message),
  });

  if (query.isError) {
    return (
      <div role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-700">
        {query.error instanceof Error ? query.error.message : "Could not load this section."}
      </div>
    );
  }
  const rows = query.data ?? [];
  // Connectors vary by provider, so show the first few non-internal fields of what the API returns.
  const columns: readonly string[] =
    section.columns.length > 0
      ? section.columns
      : Object.keys(rows[0] ?? {})
          .filter((key) => key !== "organization_id" && key !== "id")
          .slice(0, 6);
  return (
    <div className="rounded-lg border border-border bg-card">
      <Table>
        <TableHeader>
          <TableRow>
            {columns.map((column) => (
              <TableHead key={column} className="capitalize">{column.replace(/_/g, " ")}</TableHead>
            ))}
            {section.id === "approvals" && <TableHead className="w-40" />}
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((row, index) => (
            <TableRow key={String(row[section.idKey] ?? index)}>
              {columns.map((column) => (
                <TableCell key={column} className="max-w-64 truncate text-xs">{cell(row[column])}</TableCell>
              ))}
              {section.id === "approvals" && (
                <TableCell>
                  {row["status"] === "pending" && (
                    <div className="flex gap-1">
                      <Button size="sm" variant="outline" disabled={decide.isPending} onClick={() => decide.mutate({ id: String(row["approval_id"]), verb: "approve" })}>Approve</Button>
                      <Button size="sm" variant="ghost" disabled={decide.isPending} onClick={() => decide.mutate({ id: String(row["approval_id"]), verb: "reject" })}>Reject</Button>
                    </div>
                  )}
                </TableCell>
              )}
            </TableRow>
          ))}
          {query.isSuccess && rows.length === 0 && (
            <TableRow>
              <TableCell colSpan={columns.length + 1} className="py-10 text-center text-sm text-muted-foreground">
                Nothing here yet.
              </TableCell>
            </TableRow>
          )}
          {query.isLoading && (
            <TableRow>
              <TableCell colSpan={columns.length + 1} className="py-10 text-center text-sm text-muted-foreground">Loading…</TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </div>
  );
}

function PlatformPage() {
  const [tab, setTab] = useState<string>(SECTIONS[0].id);
  const status = useQuery({ queryKey: ["platform", "status"], queryFn: getPlatformStatus, retry: false });

  return (
    <AppShell
      title="Platform"
      description="Enterprise policy, approvals, connectors and audit trail."
    >
      {status.isSuccess && !status.data.enabled ? (
        <div role="status" className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-900">
          The platform service is not enabled on this deployment. Set <code>PLATFORM_DATABASE_URL</code> on the backend to turn it on.
        </div>
      ) : (
        <Tabs value={tab} onValueChange={setTab}>
          <TabsList>
            {SECTIONS.map((section) => (
              <TabsTrigger key={section.id} value={section.id}>{section.label}</TabsTrigger>
            ))}
          </TabsList>
          {SECTIONS.map((section) => (
            <TabsContent key={section.id} value={section.id} className="mt-4">
              {tab === section.id && <Section section={section} />}
            </TabsContent>
          ))}
        </Tabs>
      )}
    </AppShell>
  );
}
