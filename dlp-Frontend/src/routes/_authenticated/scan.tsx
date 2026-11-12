import { createFileRoute } from "@tanstack/react-router";

import { ScanPage } from "@/features/scan/page";

export const Route = createFileRoute("/_authenticated/scan")({
  head: () => ({ meta: [{ title: "Scan a file — DLP Console" }] }),
  component: ScanPage,
});
