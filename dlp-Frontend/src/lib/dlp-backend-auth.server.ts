import { createHash, timingSafeEqual } from "crypto";

/** Returns a 401/500 Response if the x-dlp-secret header is invalid, else null. */
export function checkDlpSecret(request: Request): Response | null {
  const expected = process.env["DLP_BACKEND_SECRET"];
  if (!expected) return json({ error: "Server not configured" }, 500);
  const provided = request.headers.get("x-dlp-secret") ?? "";
  const d = (v: string) => createHash("sha256").update(v, "utf8").digest();
  if (!provided || !timingSafeEqual(d(provided), d(expected))) {
    return json({ error: "Unauthorized" }, 401);
  }
  return null;
}

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}
