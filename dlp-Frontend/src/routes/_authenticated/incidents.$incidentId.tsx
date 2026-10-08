import { createFileRoute, Link } from "@tanstack/react-router";

import { AppShell } from "@/components/app-shell";

export const Route = createFileRoute("/_authenticated/incidents/$incidentId")({
  component: IncidentDetailPlaceholder,
});

function IncidentDetailPlaceholder() {
  const { incidentId } = Route.useParams();

  return (
    <AppShell>
      <main className="space-y-4 px-6 py-6">
        <Link to="/incidents" className="text-sm font-medium text-primary hover:underline">
          Back to incidents
        </Link>
        <h1 className="text-2xl font-bold">Incident details coming soon</h1>
        <p className="text-sm text-muted-foreground">Incident ID: {incidentId}</p>
      </main>
    </AppShell>
  );
}
