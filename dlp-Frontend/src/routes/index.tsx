import { createFileRoute, redirect } from "@tanstack/react-router";
import { FIXTURE_MODE } from "@/lib/env";
import { supabase } from "@/integrations/supabase/client";

export const Route = createFileRoute("/")({
  ssr: false,
  head: () => ({
    meta: [
      { title: "DLP — Data Loss Prevention Console" },
      {
        name: "description",
        content: "Monitor, classify and control sensitive data leaving your organization across every channel.",
      },
      { property: "og:title", content: "DLP — Data Loss Prevention Console" },
      {
        property: "og:description",
        content: "Monitor, classify and control sensitive data leaving your organization across every channel.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  beforeLoad: async () => {
    if (FIXTURE_MODE) throw redirect({ to: "/dashboard" });
    const { data } = await supabase.auth.getSession();
    throw redirect({ to: data.session ? "/dashboard" : "/auth" });
  },
  component: () => null,
});
