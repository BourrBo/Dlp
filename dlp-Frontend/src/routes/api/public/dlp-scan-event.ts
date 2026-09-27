import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";
import { checkDlpSecret, json } from "@/lib/dlp-backend-auth.server";

const Body = z.object({
  org_id: z.string().uuid(),
  user_id: z.string().uuid().nullable().default(null),
  channel: z.string().min(1).max(64),
  data_type: z.string().min(1).max(64),
  confidence: z.number().min(0).max(1),
  destination: z.string().max(2048).nullable().default(null),
  decision: z.enum(["allow", "warn", "block", "log"]),
  snippet: z.string().max(10000).nullable().default(null),
});

export const Route = createFileRoute("/api/public/dlp-scan-event")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const denied = checkDlpSecret(request);
        if (denied) return denied;
        let raw: unknown;
        try {
          raw = await request.json();
        } catch {
          return json({ error: "Invalid JSON" }, 400);
        }
        const parsed = Body.safeParse(raw);
        if (!parsed.success) return json({ error: parsed.error.flatten() }, 400);
        const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
        const { data, error } = await supabaseAdmin
          .from("dlp_events")
          .insert(parsed.data)
          .select()
          .single();
        if (error) return json({ error: error.message }, 400);
        return json(data, 201);
      },
    },
  },
});
