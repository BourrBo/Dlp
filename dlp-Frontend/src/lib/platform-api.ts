import { supabase } from "@/integrations/supabase/client";
import { API_BASE_URL } from "@/lib/env";

const base = () => API_BASE_URL.replace(/\/+$/, "");

async function token(): Promise<string> {
  const { data, error } = await supabase.auth.getSession();
  if (error) throw error;
  const value = data.session?.access_token;
  if (!value) throw new Error("Your session has expired. Sign in and try again.");
  return value;
}

async function request(url: string, init: RequestInit = {}): Promise<Response> {
  const response = await fetch(url, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init.headers ?? {}), Authorization: `Bearer ${await token()}` },
  });
  if (!response.ok) {
    let message = `Request failed (${response.status}).`;
    try {
      const body: unknown = await response.json();
      if (body && typeof body === "object" && "detail" in body) {
        const detail = (body as { detail: unknown }).detail;
        if (typeof detail === "string") message = detail;
        else if (detail && typeof detail === "object" && "message" in detail) message = String((detail as { message: unknown }).message);
      }
    } catch {
      // keep the status message
    }
    throw new Error(message);
  }
  return response;
}

export type PlatformStatus = { enabled: boolean; base_path: string | null };

export async function getPlatformStatus(): Promise<PlatformStatus> {
  return (await request(`${base()}/api/platform/status`)).json() as Promise<PlatformStatus>;
}

let linked: Promise<void> | null = null;

/** Make the signed-in user a platform member of their organization (idempotent). */
export function ensurePlatformLinked(): Promise<void> {
  if (!linked) {
    linked = request(`${base()}/api/platform/link`, { method: "POST" })
      .then(() => undefined)
      .catch((error: unknown) => {
        linked = null;
        throw error;
      });
  }
  return linked;
}

export async function platformFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  await ensurePlatformLinked();
  const response = await request(`${base()}/platform${path}`, init);
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export type ApiKeyMetadata = {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
};
export type CreatedApiKey = ApiKeyMetadata & { key: string };

export const listApiKeys = () => platformFetch<ApiKeyMetadata[]>("/api-keys");
export const createApiKey = (name: string, scopes: string[]) =>
  platformFetch<CreatedApiKey>("/api-keys", { method: "POST", body: JSON.stringify({ name, scopes }) });
export const revokeApiKey = (id: string) => platformFetch<void>(`/api-keys/${id}`, { method: "DELETE" });
