import type { FindingStatus } from "./findings";

export type Incident = {
  id: string;
  org_id: string;
  number: string;
  title: string;
  severity: string;
  status: FindingStatus;
  assignee: string | null;
  source: string;
  policy_id: string | null;
  data_type: string;
  first_seen: string;
  last_seen: string;
  created_at: string;
  updated_at: string;
};

export type IncidentEvent = {
  id: string;
  incident_id: string;
  org_id: string;
  event_type: string;
  actor: string | null;
  comment: string | null;
  created_at: string;
};

const ORG_ID = "a8e42f10-7c31-4bd2-9a65-1f0c8e23b741";

export const INCIDENT_FIXTURES: Incident[] = [
  {
    id: "10000000-0000-4000-8000-000000000001",
    org_id: ORG_ID,
    number: "INC-0001",
    title: "Credential sharing detected in browser upload",
    severity: "critical",
    status: "open",
    assignee: "Morgan Lee",
    source: "Browser",
    policy_id: "20000000-0000-4000-8000-000000000001",
    data_type: "api_key",
    first_seen: "2026-10-07T09:12:00.000Z",
    last_seen: "2026-10-07T09:18:00.000Z",
    created_at: "2026-10-07T09:18:00.000Z",
    updated_at: "2026-10-07T09:18:00.000Z",
  },
  {
    id: "10000000-0000-4000-8000-000000000002",
    org_id: ORG_ID,
    number: "INC-0002",
    title: "Personal information shared to external storage",
    severity: "high",
    status: "triaged",
    assignee: "Jamie Patel",
    source: "Google Drive",
    policy_id: "20000000-0000-4000-8000-000000000002",
    data_type: "national_id",
    first_seen: "2026-10-06T13:40:00.000Z",
    last_seen: "2026-10-06T14:05:00.000Z",
    created_at: "2026-10-06T14:05:00.000Z",
    updated_at: "2026-10-06T15:22:00.000Z",
  },
  {
    id: "10000000-0000-4000-8000-000000000003",
    org_id: ORG_ID,
    number: "INC-0003",
    title: "Payment data detected in outbound email",
    severity: "medium",
    status: "fixed",
    assignee: "Alex Rivera",
    source: "Email",
    policy_id: "20000000-0000-4000-8000-000000000003",
    data_type: "credit_card",
    first_seen: "2026-10-04T10:31:00.000Z",
    last_seen: "2026-10-04T10:31:00.000Z",
    created_at: "2026-10-04T10:31:00.000Z",
    updated_at: "2026-10-04T11:02:00.000Z",
  },
  {
    id: "10000000-0000-4000-8000-000000000004",
    org_id: ORG_ID,
    number: "INC-0004",
    title: "Unapproved document sharing from cloud storage",
    severity: "high",
    status: "accepted",
    assignee: null,
    source: "Google Drive",
    policy_id: "20000000-0000-4000-8000-000000000004",
    data_type: "document_match",
    first_seen: "2026-10-02T16:20:00.000Z",
    last_seen: "2026-10-03T08:15:00.000Z",
    created_at: "2026-10-03T08:15:00.000Z",
    updated_at: "2026-10-03T12:45:00.000Z",
  },
  {
    id: "10000000-0000-4000-8000-000000000005",
    org_id: ORG_ID,
    number: "INC-0005",
    title: "False positive from internal contact information",
    severity: "low",
    status: "false_positive",
    assignee: "Taylor Chen",
    source: "API",
    policy_id: null,
    data_type: "email_pii",
    first_seen: "2026-09-30T07:55:00.000Z",
    last_seen: "2026-09-30T07:55:00.000Z",
    created_at: "2026-09-30T07:55:00.000Z",
    updated_at: "2026-09-30T09:10:00.000Z",
  },
];

export const INCIDENT_EVENT_FIXTURES: IncidentEvent[] = [
  {
    id: "30000000-0000-4000-8000-000000000001",
    incident_id: INCIDENT_FIXTURES[0].id,
    org_id: ORG_ID,
    event_type: "created",
    actor: "Policy Engine",
    comment: "Incident created after a policy match.",
    created_at: "2026-10-07T09:18:00.000Z",
  },
  {
    id: "30000000-0000-4000-8000-000000000002",
    incident_id: INCIDENT_FIXTURES[0].id,
    org_id: ORG_ID,
    event_type: "assigned",
    actor: "Morgan Lee",
    comment: "Assigned for investigation.",
    created_at: "2026-10-07T09:24:00.000Z",
  },
  {
    id: "30000000-0000-4000-8000-000000000003",
    incident_id: INCIDENT_FIXTURES[1].id,
    org_id: ORG_ID,
    event_type: "created",
    actor: "Policy Engine",
    comment: "Incident created after a policy match.",
    created_at: "2026-10-06T14:05:00.000Z",
  },
  {
    id: "30000000-0000-4000-8000-000000000004",
    incident_id: INCIDENT_FIXTURES[1].id,
    org_id: ORG_ID,
    event_type: "status_changed",
    actor: "Jamie Patel",
    comment: "Moved to triage for review.",
    created_at: "2026-10-06T15:22:00.000Z",
  },
  {
    id: "30000000-0000-4000-8000-000000000005",
    incident_id: INCIDENT_FIXTURES[2].id,
    org_id: ORG_ID,
    event_type: "created",
    actor: "Policy Engine",
    comment: "Incident created after a policy match.",
    created_at: "2026-10-04T10:31:00.000Z",
  },
  {
    id: "30000000-0000-4000-8000-000000000006",
    incident_id: INCIDENT_FIXTURES[2].id,
    org_id: ORG_ID,
    event_type: "status_changed",
    actor: "Alex Rivera",
    comment: "Resolved with the approved remediation.",
    created_at: "2026-10-04T11:02:00.000Z",
  },
  {
    id: "30000000-0000-4000-8000-000000000007",
    incident_id: INCIDENT_FIXTURES[3].id,
    org_id: ORG_ID,
    event_type: "created",
    actor: "Policy Engine",
    comment: "Incident created after a policy match.",
    created_at: "2026-10-03T08:15:00.000Z",
  },
  {
    id: "30000000-0000-4000-8000-000000000008",
    incident_id: INCIDENT_FIXTURES[3].id,
    org_id: ORG_ID,
    event_type: "status_changed",
    actor: "Security Admin",
    comment: "Accepted as an approved business exception.",
    created_at: "2026-10-03T12:45:00.000Z",
  },
  {
    id: "30000000-0000-4000-8000-000000000009",
    incident_id: INCIDENT_FIXTURES[4].id,
    org_id: ORG_ID,
    event_type: "created",
    actor: "Policy Engine",
    comment: "Incident created after a policy match.",
    created_at: "2026-09-30T07:55:00.000Z",
  },
  {
    id: "30000000-0000-4000-8000-000000000010",
    incident_id: INCIDENT_FIXTURES[4].id,
    org_id: ORG_ID,
    event_type: "status_changed",
    actor: "Taylor Chen",
    comment: "Marked as a false positive after review.",
    created_at: "2026-09-30T09:10:00.000Z",
  },
];
