import { createFileRoute, Outlet, redirect } from "@tanstack/react-router";
import { FIXTURE_MODE } from "@/lib/env";

export const Route = createFileRoute("/_authenticated")({
  ssr: false,
  beforeLoad: async () => {
    // In fixture mode (no Supabase credentials), bypass auth entirely.
    if (FIXTURE_MODE) {
      return { user: { id: "fixture", email: "ashish@corp.com" } };
    }

    try {
      const { supabase } = await import("@/integrations/supabase/client");
      const { data, error } = await supabase.auth.getUser();
      if (error || !data.user) throw redirect({ to: "/auth" });
      return { user: data.user };
    } catch (err) {
      // If Supabase client throws (e.g. missing env vars), redirect to auth.
      if (err && typeof err === "object" && "to" in err) throw err; // re-throw redirect
      throw redirect({ to: "/auth" });
    }
  },
  component: () => <Outlet />,
});
