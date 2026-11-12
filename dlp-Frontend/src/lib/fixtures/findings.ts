export type FindingStatus = "open" | "triaged" | "fixed" | "accepted" | "false_positive";

export type FindingFixture = {
  id: string;
  severity: "low" | "medium" | "high" | "critical";
  classification: string;
  data_type: string;
  status: FindingStatus;
  source: string;
  detector: string;
  confidence: number;
  created_at: string;
};

export const FINDING_FIXTURES: FindingFixture[] = [
  { id: "finding-01", severity: "critical", classification: "credentials", data_type: "api_key", status: "open", source: "Browser", detector: "Secret scanner", confidence: 0.98, created_at: "2026-10-06T09:42:00.000Z" },
  { id: "finding-02", severity: "high", classification: "personal information", data_type: "national_id", status: "triaged", source: "Google Drive", detector: "Pattern detector", confidence: 0.91, created_at: "2026-10-06T08:26:00.000Z" },
  { id: "finding-03", severity: "medium", classification: "financial data", data_type: "credit_card", status: "open", source: "Email", detector: "Payment card detector", confidence: 0.78, created_at: "2026-10-05T16:14:00.000Z" },
  { id: "finding-04", severity: "low", classification: "personal information", data_type: "email_pii", status: "accepted", source: "API", detector: "PII detector", confidence: 0.63, created_at: "2026-10-04T12:03:00.000Z" },
  { id: "finding-05", severity: "high", classification: "credentials", data_type: "api_key", status: "fixed", source: "Slack", detector: "Secret scanner", confidence: 0.89, created_at: "2026-10-03T17:35:00.000Z" },
  { id: "finding-06", severity: "medium", classification: "health information", data_type: "custom", status: "triaged", source: "Google Drive", detector: "Custom rule detector", confidence: 0.74, created_at: "2026-10-02T14:20:00.000Z" },
  { id: "finding-07", severity: "critical", classification: "financial data", data_type: "credit_card", status: "open", source: "Email", detector: "Payment card detector", confidence: 0.97, created_at: "2026-10-01T10:08:00.000Z" },
  { id: "finding-08", severity: "low", classification: "personal information", data_type: "person_name", status: "false_positive", source: "Browser", detector: "NER detector", confidence: 0.56, created_at: "2026-09-29T19:11:00.000Z" },
  { id: "finding-09", severity: "high", classification: "personal information", data_type: "phone_number", status: "open", source: "API", detector: "PII detector", confidence: 0.86, created_at: "2026-09-28T08:50:00.000Z" },
  { id: "finding-10", severity: "medium", classification: "confidential documents", data_type: "document_match", status: "fixed", source: "Google Drive", detector: "Fingerprint detector", confidence: 0.82, created_at: "2026-09-26T15:42:00.000Z" },
  { id: "finding-11", severity: "critical", classification: "credentials", data_type: "api_key", status: "triaged", source: "Slack", detector: "Secret scanner", confidence: 0.99, created_at: "2026-09-24T11:27:00.000Z" },
  { id: "finding-12", severity: "low", classification: "personal information", data_type: "address", status: "accepted", source: "Email", detector: "NER detector", confidence: 0.61, created_at: "2026-09-21T13:05:00.000Z" },
  { id: "finding-13", severity: "high", classification: "health information", data_type: "custom", status: "open", source: "API", detector: "Custom rule detector", confidence: 0.88, created_at: "2026-09-18T09:16:00.000Z" },
  { id: "finding-14", severity: "medium", classification: "financial data", data_type: "credit_card", status: "false_positive", source: "Browser", detector: "Payment card detector", confidence: 0.69, created_at: "2026-09-14T16:38:00.000Z" },
  { id: "finding-15", severity: "critical", classification: "confidential documents", data_type: "document_match", status: "fixed", source: "Google Drive", detector: "Fingerprint detector", confidence: 0.95, created_at: "2026-09-10T07:54:00.000Z" },
];
