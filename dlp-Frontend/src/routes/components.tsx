import { createFileRoute } from "@tanstack/react-router";

import { ClassificationChip } from "@/components/classification-chip";
import { ConfidenceBar } from "@/components/confidence-bar";
import { CopyButton } from "@/components/copy-button";
import { MaskedValue } from "@/components/masked-value";
import { SeverityBadge } from "@/components/severity-badge";

export const Route = createFileRoute("/components")({
  ssr: false,
  component: ComponentsPage,
});

function ComponentsPage() {
  return (
    <main className="min-h-screen bg-background p-8 text-foreground">
      <div className="mx-auto max-w-5xl space-y-8">
        <header className="space-y-2">
          <p className="text-sm font-medium uppercase tracking-[0.2em] text-muted-foreground">P4</p>
          <h1 className="text-3xl font-semibold tracking-tight">Shared component showcase</h1>
        </header>

        <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <div className="rounded-lg border border-border bg-card p-4 shadow-sm">
            <p className="mb-3 text-sm font-medium text-muted-foreground">SeverityBadge</p>
            <div className="flex flex-wrap gap-2">
              <SeverityBadge severity="low" />
              <SeverityBadge severity="medium" />
              <SeverityBadge severity="high" />
              <SeverityBadge severity="critical" />
            </div>
          </div>

          <div className="rounded-lg border border-border bg-card p-4 shadow-sm">
            <p className="mb-3 text-sm font-medium text-muted-foreground">ClassificationChip</p>
            <div className="flex flex-wrap gap-2">
              <ClassificationChip classification="pii" />
              <ClassificationChip classification="pci" />
              <ClassificationChip classification="phi" />
              <ClassificationChip classification="credentials" />
              <ClassificationChip classification="source_code" />
            </div>
          </div>

          <div className="rounded-lg border border-border bg-card p-4 shadow-sm">
            <p className="mb-3 text-sm font-medium text-muted-foreground">ConfidenceBar</p>
            <div className="space-y-3">
              <ConfidenceBar confidence={0.25} />
              <ConfidenceBar confidence={0.65} />
              <ConfidenceBar confidence={0.95} />
            </div>
          </div>

          <div className="rounded-lg border border-border bg-card p-4 shadow-sm">
            <p className="mb-3 text-sm font-medium text-muted-foreground">MaskedValue</p>
            <div className="space-y-2">
              <MaskedValue value="4111 2222 3333 4444" />
              <MaskedValue value="jane.doe@example.com" />
            </div>
          </div>
        </section>

        <section className="rounded-lg border border-border bg-card p-4 shadow-sm">
          <p className="mb-3 text-sm font-medium text-muted-foreground">CopyButton</p>
          <CopyButton value="example-report-id-42" label="Copy sample" />
        </section>
      </div>
    </main>
  );
}