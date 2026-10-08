import { createFileRoute, Link } from "@tanstack/react-router";
import { useEffect, useState } from "react";

import { AppShell } from "@/components/app-shell";
import { SeverityBadge } from "@/components/severity-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  INCIDENT_EVENT_FIXTURES,
  INCIDENT_FIXTURES,
  type Incident,
} from "@/lib/fixtures/incidents";

export const Route = createFileRoute("/_authenticated/incidents/$incidentId")({
  component: IncidentDetailPage,
});

function formatDate(value: string) {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function IncidentDetailPage() {
  const { incidentId } = Route.useParams();
  const [incident, setIncident] = useState<Incident | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fixture = INCIDENT_FIXTURES.find((item) => item.id === incidentId) ?? null;
    setIncident(fixture);
    setLoading(false);
  }, [incidentId]);

  const events = INCIDENT_EVENT_FIXTURES.filter((event) => event.incident_id === incidentId)
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
                {events.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    No timeline events are available for this incident.
                  </p>
                ) : (
                  <ol className="space-y-5">
                    {events.map((event) => (
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
