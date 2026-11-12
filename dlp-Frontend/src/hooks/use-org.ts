import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { FIXTURE_MODE } from "@/lib/env";

/**
 * Resolves (and provisions on first use) the organization for the signed-in
 * user. Every DLP table is scoped by this org id.
 */
export function useOrg() {
  return useQuery({
    queryKey: ["org-id"],
    queryFn: async () => {
      if (FIXTURE_MODE) return "org-fixture-123";
      const { data, error } = await supabase.rpc("ensure_org");
      if (error) throw error;
      return data as unknown as string;
    },
    staleTime: Infinity,
    retry: 1,
  });
}
