import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";
import { checkDlpSecret, json } from "@/lib/dlp-backend-auth.server";

const Query = z.object({
  org_id: z.string().uuid(),
  data_type: z.string().min(1).max(64),
  channel: z.string().min(1).max(64),
});

export const Route = createFileRoute("/api/public/dlp-get-policy")({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const denied = checkDlpSecret(request);
        if (denied) return denied;
        const params = Object.fromEntries(new URL(request.url).searchParams);
        const parsed = Query.safeParse(params);
        if (!parsed.success) return json({ error: parsed.error.flatten() }, 400);
        const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
        const { data, error } = await supabaseAdmin
          .from("dlp_policies")
          .select("*")
          .eq("org_id", parsed.data.org_id)
          .eq("data_type", parsed.data.data_type)
          .eq("channel", parsed.data.channel)
          .limit(1)
          .maybeSingle();
        if (error) return json({ error: error.message }, 400);
        return json(data ?? null);
      },
    },
  },
});
