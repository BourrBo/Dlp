import { createFileRoute, Link } from "@tanstack/react-router";
import { useEffect, useState, type FormEvent } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { SeverityBadge } from "@/components/severity-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import type { FindingStatus } from "@/lib/fixtures/findings";
import {
  INCIDENT_EVENT_FIXTURES,
  INCIDENT_FIXTURES,
  type IncidentEvent,
  type Incident,
} from "@/lib/fixtures/incidents";

export const Route = createFileRoute("/_authenticated/incidents/$incidentId")({
  component: IncidentDetailPage,
});

const STATUS_OPTIONS: FindingStatus[] = ["open", "triaged", "fixed", "accepted", "false_positive"];

function formatDate(value: string) {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function IncidentDetailPage() {
  const { incidentId } = Route.useParams();
  const [incident, setIncident] = useState<Incident | null>(null);
  const [events, setEvents] = useState<IncidentEvent[]>([]);
  const [assignee, setAssignee] = useState("");
  const [comment, setComment] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fixture = INCIDENT_FIXTURES.find((item) => item.id === incidentId) ?? null;
    setIncident(fixture);
    setAssignee(fixture?.assignee ?? "");
    setEvents(INCIDENT_EVENT_FIXTURES.filter((event) => event.incident_id === incidentId));
    setLoading(false);
  }, [incidentId]);

  function appendEvent(eventType: string, eventComment: string) {
    if (!incident) return;
    const createdAt = new Date().toISOString();
    const event: IncidentEvent = {
      id: crypto.randomUUID(),
      incident_id: incident.id,
      org_id: incident.org_id,
      event_type: eventType,
      actor: "You",
      comment: eventComment,
      created_at: createdAt,
    };
    setEvents((current) =>
      [...current, event].sort((a, b) => a.created_at.localeCompare(b.created_at)),
    );
    setIncident((current) => (current ? { ...current, updated_at: createdAt } : current));
  }

  function changeStatus(status: FindingStatus) {
    if (!incident || incident.status === status) return;
    setIncident((current) => (current ? { ...current, status } : current));
    appendEvent("status_changed", `Status changed to ${status.replace(/_/g, " ")}.`);
    toast.success("Incident status updated");
  }

  function saveAssignee(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!incident) return;
    const nextAssignee = assignee.trim();
    if ((incident.assignee ?? "") === nextAssignee) {
      return;
    }
    setIncident((current) => (current ? { ...current, assignee: nextAssignee || null } : current));
    appendEvent("assigned", nextAssignee ? `Assigned to ${nextAssignee}.` : "Incident unassigned.");
    toast.success(nextAssignee ? "Incident assigned" : "Incident unassigned");
  }

  function addComment(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const text = comment.trim();
    if (!text) {
      toast.error("Enter a comment before adding it.");
      return;
    }
    appendEvent("comment_added", text);
    setComment("");
    toast.success("Comment added to timeline");
  }

  const sortedEvents = events
    .slice()
    .sort((left, right) => left.created_at.localeCompare(right.created_at));

  return (
    <AppShell>
      <main className="space-y-6 px-6 py-6">
        <Link to="/incidents" className="text-sm font-medium text-primary hover:underline">
          Back to incidents
        </Link>

        {loading ? (
          <p className="py-8 text-center text-sm text-muted-foreground" role="status">
            Loading incident...
          </p>
        ) : !incident ? (
          <section className="space-y-2 py-12 text-center" role="status">
            <h1 className="text-2xl font-bold">Incident not found</h1>
            <p className="text-sm text-muted-foreground">
              No incident exists with ID {incidentId}.
            </p>
          </section>
        ) : (
          <>
            <header className="space-y-2">
              <p className="font-mono text-sm font-semibold text-muted-foreground">
                {incident.number}
              </p>
              <h1 className="text-2xl font-bold">{incident.title}</h1>
              <div className="flex flex-wrap items-center gap-3">
                <SeverityBadge severity={incident.severity} />
                <span className="rounded-full border px-2.5 py-1 text-xs capitalize">
                  {incident.status.replace(/_/g, " ")}
                </span>
              </div>
            </header>

            <Card>
              <CardHeader>
                <CardTitle>Manage incident</CardTitle>
              </CardHeader>
              <CardContent className="grid gap-6 sm:grid-cols-2">
                <label className="space-y-2">
                  <span className="text-sm font-medium">Status</span>
                  <select
                    aria-label="Incident status"
                    value={incident.status}
                    onChange={(event) => {
                      const selected = STATUS_OPTIONS.find(
                        (status) => status === event.target.value,
                      );
                      if (selected) changeStatus(selected);
                    }}
                    className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
                  >
                    {STATUS_OPTIONS.map((status) => (
                      <option key={status} value={status}>
                        {status.replace(/_/g, " ")}
                      </option>
                    ))}
                  </select>
                </label>
                <form className="space-y-2" onSubmit={saveAssignee}>
                  <label htmlFor="incident-assignee" className="text-sm font-medium">
                    Assignee
                  </label>
                  <div className="flex gap-2">
                    <Input
                      id="incident-assignee"
                      value={assignee}
                      onChange={(event) => setAssignee(event.target.value)}
                      placeholder="Name or leave blank to unassign"
                    />
                    <Button type="submit">Save</Button>
                  </div>
                </form>
                <form className="space-y-2 sm:col-span-2" onSubmit={addComment}>
                  <label htmlFor="incident-comment" className="text-sm font-medium">
                    Add comment
                  </label>
                  <Textarea
                    id="incident-comment"
                    value={comment}
                    onChange={(event) => setComment(event.target.value)}
                    placeholder="Write a timeline comment..."
                    rows={3}
                  />
                  <Button type="submit">Add comment</Button>
                </form>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Incident details</CardTitle>
              </CardHeader>
              <CardContent>
                <dl className="grid gap-x-6 gap-y-5 sm:grid-cols-2 lg:grid-cols-3">
                  <Detail label="Source" value={incident.source} />
                  <Detail label="Data type" value={incident.data_type.replace(/_/g, " ")} />
                  <Detail label="Assignee" value={incident.assignee ?? "Unassigned"} />
                  <Detail label="Policy ID" value={incident.policy_id ?? "None"} />
                  <Detail label="First seen" value={formatDate(incident.first_seen)} />
                  <Detail label="Last seen" value={formatDate(incident.last_seen)} />
                  <Detail label="Created" value={formatDate(incident.created_at)} />
                  <Detail label="Updated" value={formatDate(incident.updated_at)} />
                </dl>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Linked findings</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground">
                  No findings are linked to this incident in the available fixtures.
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Timeline</CardTitle>
              </CardHeader>
              <CardContent>
                {sortedEvents.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    No timeline events are available for this incident.
                  </p>
                ) : (
                  <ol className="space-y-5">
                    {sortedEvents.map((event) => (
                      <li key={event.id} className="border-l-2 border-border pl-4">
                        <div className="flex flex-wrap items-baseline justify-between gap-2">
                          <p className="text-sm font-semibold capitalize">
                            {event.event_type.replace(/_/g, " ")}
                          </p>
                          <time
                            className="text-xs text-muted-foreground"
                            dateTime={event.created_at}
                          >
                            {formatDate(event.created_at)}
                          </time>
                        </div>
                        <p className="mt-1 text-sm text-muted-foreground">
                          {event.actor ?? "Unknown actor"}
                        </p>
                        <p className="mt-1 text-sm">{event.comment ?? "No comment."}</p>
                      </li>
                    ))}
                  </ol>
                )}
              </CardContent>
            </Card>
          </>
        )}
      </main>
    </AppShell>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs font-medium text-muted-foreground">{label}</dt>
      <dd className="mt-1 break-words text-sm">{value}</dd>
    </div>
  );
}
