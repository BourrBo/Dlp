// Fixture mode is a local-development aid only; production builds ignore it.
export const FIXTURE_MODE = import.meta.env.DEV && import.meta.env["VITE_FIXTURE_MODE"] === "true";

export const API_BASE_URL: string =
  import.meta.env["VITE_DLP_BACKEND_URL"] ?? import.meta.env["VITE_API_BASE_URL"] ?? "http://localhost:8000";
