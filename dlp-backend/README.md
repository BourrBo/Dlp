# DLP backend

FastAPI service for text scanning, policy evaluation, event logging, and the
standalone ingestion extractors. The backend connects directly to the
configured Supabase project's Data API; it does not call Lovable-hosted routes.

## Local setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Set `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, and `SUPABASE_SERVICE_ROLE_KEY` in `.env`. The service key is
server-only, must not be committed, and must never be passed to the dashboard
build. The publishable key and verified user access token are used for RLS-scoped
membership and incident requests. See the
repository root README for the supported Docker Compose setup.

## Scan API

- `GET /health` returns service status.
- `POST /api/scan` runs detection, policy evaluation, and event persistence after bearer-token and organization-membership verification.
- `POST /scans` scans a bounded synchronous file upload after the same authorization checks.
- `/scan-jobs` submits, lists, polls, and cancels encrypted asynchronous file
  scan jobs; user ownership is taken from the verified bearer token.
- `/api/overview` and `/api/v1/incidents` provide authenticated dashboard APIs.

The submitted organization must be a membership of the verified Supabase user;
the backend replaces any body `user_id` with the authenticated user ID. The
async queue has global, per-organization, per-user, and
pending-byte caps; a full queue returns HTTP 429 with `Retry-After`.

Set `SCAN_JOBS_ENCRYPTION_KEY` to a generated Fernet key for new deployments:

```powershell
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Keep it stable while jobs are queued. For rotation, put the prior key in
`SCAN_JOBS_PREVIOUS_ENCRYPTION_KEYS` (comma-separated during multi-step
rotations) and remove it only after old pending jobs have drained. The old
service-role-derived key is supported as a migration fallback for existing
local queues; do not rely on it for new production deployments.

## P3 ingestion work

The isolated `app/extractors/` module supports text/source files, CSV, JSON,
XML, PDF, DOCX, XLSX, PPTX, and bounded ZIP/TAR/GZIP archives. It yields text
chunks with source locations, enforces input and parser limits, and returns
explicit skip reasons. OCR is available for image-only PDFs when Tesseract and
the language data are installed. See [`docs/ingestion.md`](docs/ingestion.md)
for supported formats and limits. The offline CLI is available with
`python -m app.cli_scan PATH --sarif results.sarif`.

Inspect sample files locally:

```powershell
python scripts/inspect_extractors.py path\to\sample.txt path\to\samples\
```

See [`docs/ingestion.md`](docs/ingestion.md) for supported formats, limits,
locations, and current exclusions.

## Optional teammate integrations

- `pip install -r requirements-person-b.txt` and
  `python -m spacy download en_core_web_sm` enables Presidio NER.
- `pip install -r requirements-ssdeep.txt` enables fuzzy document matching
  when the operating system also has its native `libfuzzy` dependency.
- `pip install -r requirements-integrations.txt` installs the Gmail/Drive
  service helper libraries. The ZIP's OAuth routes are intentionally not
  enabled until user authentication and encrypted token storage are added.
- Set `SLACK_WEBHOOK_URL` to send alerts for WARN/BLOCK scan decisions.
- `/api/classifications` rule-registration endpoints require a separate
  `DLP_ADMIN_API_KEY` sent as `X-DLP-Admin-Key`. They return 503 when unset.

## Security boundary

The dashboard scan routes require a verified Supabase access token and check
membership using a publishable-key client subject to RLS. Event and policy writes
use the server-only key after that check. The browser extension still sends a
managed DLP API key, which is not yet accepted by the user-token authentication
contract; do not expose the extension to users until scoped API-key verification
and principal resolution are integrated.
