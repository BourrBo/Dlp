import { createFileRoute, redirect } from "@tanstack/react-router";
import { FIXTURE_MODE } from "@/lib/env";
import { supabase } from "@/integrations/supabase/client";
import { LandingPage } from "@/components/landing-page";

export const Route = createFileRoute("/")({
  ssr: false,
  head: () => ({
    meta: [
      { title: "SecureFlow DLP — Data Loss Prevention" },
      {
        name: "description",
        content:
          "Intelligent data loss prevention that monitors, classifies, and protects sensitive information across every channel.",
      },
      { property: "og:title", content: "SecureFlow DLP — Data Loss Prevention" },
      {
        property: "og:description",
        content:
          "Monitor, classify and control sensitive data leaving your organization across every channel.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  beforeLoad: async () => {
    if (FIXTURE_MODE) return;
    const { data } = await supabase.auth.getSession();
    if (data.session) throw redirect({ to: "/dashboard" });
  },
  component: LandingPage,
});
