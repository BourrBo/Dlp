import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/components")({
  ssr: false,
  component: ComponentsPage,
});

function ComponentsPage() {
  return (
    <main className="min-h-screen bg-background p-8 text-foreground">
      <h1 className="text-2xl font-semibold">Component showcase</h1>
      <p className="mt-2 text-muted-foreground">
        Shared P4 components will appear here.
      </p>
    </main>
  );
}