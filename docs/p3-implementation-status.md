# P3 implementation status

This file tracks the P3 stream from the 36-week roadmap. Work is sequenced by
its week plan and depends on the shared API/security contracts owned by P2, the
detector package owned by P1, and UI/packaging handoffs owned by P4.

## Current programme position

- Roadmap W1 starts Monday 12 October 2026.
- Implemented slices: W1-8 ingestion, W9-14 browser-extension core, W15-21
  GitHub/repository/history-scanning building blocks, and the first W22-25
  offline CLI/SARIF slice. The dashboard's scan routes now use P4's Supabase
  bearer-token and membership checks. The browser extension still needs P2's
  scoped API-key verification contract; GitHub install/webhook consumption and
  finding-to-incident handoff remain incomplete.
- Scan routes reject missing/invalid bearer tokens and verify organization
  membership. The background worker runs after authorized jobs are queued.
  Multipart bodies are capped before parsing, pending queues are bounded, and
  a dedicated scan-job encryption key with rotation support is available.
- W1-2 deliverables: import-boundary check; text, CSV, JSON, XML, PDF, and
  DOCX extraction with locations; bounded upload and parser timeout; file-scan
  UI v0; synthetic fixture coverage; ingestion documentation.
- Shared dependency: dashboard scans use the existing scan endpoint and verified
  Supabase user principal. API-key principals for the browser extension still
  depend on P2's scoped key storage/verification contract.

## Phase tracker

| Roadmap block | Weeks | Status | Exit evidence |
| --- | --- | --- | --- |
| Ingestion foundation and first upload slice | W1-2 | Complete | Import check and fixtures; PDF/DOCX locations; upload-to-scan UI/API |
| XLSX, PPTX and OCR | W3-4 | Implementation complete; Hindi language pack verified | Streaming workbook locations and slide notes; adaptive English/Hindi OCR with grayscale autocontrast; all 68 backend tests pass in the Docker image, including the real image-only PDF OCR smoke test; `tesseract --list-langs` reports `eng`, `hin`, and `osd` |
| Archive safety | W5-6 | Complete | In-memory ZIP/TAR/GZ extraction; traversal, link, expansion, nesting, duplicate and case-collision checks; unit tests and Docker smoke check |
| Async scans and full file UI | W7-8 | Implementation complete; retest after auth merge | Encrypted upload queue; queued work survives restart; running jobs become interrupted with partial results retained and source upload erased; deterministic event IDs; global, per-organization, per-user and queued-byte caps; multipart body cap before parsing. |
| Browser protection core | W9-11 | In progress; scoped API-key auth and browser matrix pending | Managed-key worker, allowlisted AI destinations, paste/drop/file/form hooks, narrow package builder; thirteen Node tests passed before the P4 auth merge. Folder drops follow fail-closed/fail-open policy; popup toggle uses the managed setting. The current backend accepts user JWTs, not extension API keys. |
| Browser extension completion | W12-14 | Partial; P2 API-key, upload/override APIs and browser runtime tests pending | Chrome, Edge, and Firefox manifests and source ZIPs build; binary files stream through the background worker to durable scan jobs; local dev ZIPs and enterprise guide exist. Mocked transfer/config tests passed before the auth merge; live authenticated API and audited justification need P2 endpoints. |
| GitHub App security and install lifecycle | W15-17 | Signature-verified intake implemented; install lifecycle and P2 handoffs pending | RS256 App JWT creation, raw-body SHA-256 webhook verification, least-privilege installation-token exchange; durable metadata-only webhook queue with replay dedupe, 2 MiB body cap, 10,000 pending-item cap, and restart recovery; fifteen GitHub security/webhook tests pass locally and in Docker |
| Repository onboarding and working-tree scans | W18-19 | Core scanner implemented; authenticated route, real shallow-clone smoke test, and P2/P4 handoffs pending | Header-based GitHub token configuration; .dlpignore and standard exclusions; process-isolated extraction; file/byte/time limits; Windows-aware cleanup; commit SHA and partial-result metadata; seven synthetic/mocked service tests |
| Git history and push-triggered incidents | W20-21 | Added-line history scanner implemented; API consumer, full-history fetch, P1 fingerprints, and P4 handoff pending | Synthetic tests verify deleted-secret detection, line/commit/author provenance, blob dedupe, resume cursor, force-push restart, `.dlpignore`, and LFS skipping. Shallow checkout is explicitly partial; exact-blob-in-HEAD is not yet finding-level status |
| CLI, pre-commit, SARIF, Action, PR checks, VS Code | W22-25 | CLI/SARIF starter implemented; integrations pending | Offline CLI uses existing extractors/detector; built-in regex and NER are local-only; SARIF excludes match text and carries source locations for offset-aware detectors. The pre-merge Windows backend suite passed 82 tests (3 Linux/Docker-only checks skipped); extension suite passed 13 tests. Current merge verification is tracked in `TEAMMATE-MERGE-STATUS.md`. |
| Endpoint agent and fleet | W26-33 | Not started | Enrollment, heartbeat, watched folders, offline queue, USB/quarantine and hardening |
| Release documentation and hardening | W34-36 | Not started | Clean-machine walkthrough, no open S1/S2 issues |

## Scope boundaries and known handoffs

- P1 owns detector accuracy, stable offline detector package v1, and mail/chat
  connectors. P3 consumes these contracts and does not replace them.
- P2 owns the full API-key and platform contract. It is now merged: `dlp-backend/dlp_platform`
  is mounted at `/platform`, its `dlp_...` API keys authenticate scan routes
  (`get_scan_principal`), and its pipeline runs the root extractors and detectors.
  See `INTEGRATION.md`.
- P4 owns the shared component kit, incidents, device UI, packaging/signing,
  monitoring, CI operations, and release coordination.
- Gmail, Drive, Slack/Teams, SIEM/ticketing, network proxy, and general Docker
  operations are outside P3 ownership in the new team plan.
