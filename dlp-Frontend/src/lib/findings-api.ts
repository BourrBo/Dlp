import { supabase } from "@/integrations/supabase/client";
import { API_BASE_URL, FIXTURE_MODE } from "@/lib/env";
import { FINDING_FIXTURES, type FindingFixture, type FindingStatus } from "@/lib/fixtures/findings";

export type FindingRecord = FindingFixture & {
  owner: string;
  notes: string;
  masked_evidence: string | null;
  location: string | null;
};

type ApiFinding = {
  id: string;
  severity: string;
  classification: string | null;
  data_type: string;
  status: FindingStatus;
  source: string;
  detector: string | null;
  confidence: number;
  created_at: string;
  owner: string | null;
  notes: string | null;
  masked_evidence: string | null;
  location: string | null;
};

const SEVERITIES = ["low", "medium", "high", "critical"] as const;

function toRecord(row: ApiFinding): FindingRecord {
  const severity = SEVERITIES.find((value) => value === row.severity.toLowerCase()) ?? "low";
  return {
    id: row.id,
    severity,
    classification: row.classification ?? "other",
    data_type: row.data_type,
    status: row.status,
    source: row.source,
    detector: row.detector ?? row.data_type,
    confidence: row.confidence,
    created_at: row.created_at,
    owner: row.owner ?? "",
    notes: row.notes ?? "",
    masked_evidence: row.masked_evidence,
    location: row.location,
  };
}

async function authorizedFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const { data, error } = await supabase.auth.getSession();
  if (error) throw error;
  const token = data.session?.access_token;
  if (!token) throw new Error("Your session has expired. Sign in and try again.");
  const response = await fetch(`${API_BASE_URL.replace(/\/+$/, "")}${path}`, {
    ...init,
    headers: { ...(init.headers ?? {}), Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
  });
  if (!response.ok) {
    let message = `Request failed (${response.status}).`;
    try {
      const body: unknown = await response.json();
      if (body && typeof body === "object" && "detail" in body && typeof body.detail === "string") {
        message = body.detail;
      }
    } catch {
      // keep the status message
    }
    throw new Error(message);
  }
  return response;
}

export async function loadFindings(): Promise<FindingRecord[]> {
  if (FIXTURE_MODE) {
    return FINDING_FIXTURES.map((f) => ({ ...f, owner: "", notes: "", masked_evidence: null, location: null }));
  }
  const response = await authorizedFetch("/api/v1/findings?limit=500");
  return ((await response.json()) as ApiFinding[]).map(toRecord);
}

export async function updateFinding(
  id: string,
  changes: Partial<{ status: FindingStatus; owner: string; notes: string }>,
): Promise<void> {
  if (FIXTURE_MODE) return;
  await authorizedFetch(`/api/v1/findings/${id}`, { method: "PATCH", body: JSON.stringify(changes) });
}
