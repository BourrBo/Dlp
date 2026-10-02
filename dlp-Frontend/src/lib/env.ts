export const FIXTURE_MODE = import.meta.env["VITE_FIXTURE_MODE"] === "true";

export const API_BASE_URL: string = import.meta.env["VITE_API_BASE_URL"] ?? "http://localhost:8000";
