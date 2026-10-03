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

Set `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` in `.env`. The key is
server-only, must not be committed, and must never be passed to the dashboard
build. For the dashboard, configure only the Supabase publishable key. See the
repository root README for the supported Docker Compose setup.

## Scan API

- `GET /health` returns service status.
- `POST /api/scan` runs detection, policy evaluation, and event persistence.

The current synchronous endpoint accepts text. File and archive scanning APIs
are not wired yet.

## P3 ingestion work

The isolated `app/extractors/` module currently supports text/source files,
CSV, JSON, and XML. It yields bounded overlapping text chunks with file and
format-specific locations. It enforces the 25 MiB input limit and returns
explicit skip reasons for unsupported or malformed files. PDF/Office, ZIP,
async jobs, GitHub scanning, and the CLI package remain follow-up milestones.

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

The extension currently supplies `org_id` and `user_id` in scan requests. The
backend's service key bypasses RLS, so this prototype is not ready for an
internet-facing multi-tenant deployment until P2's authenticated principal and
tenant authorization work replaces client-supplied identity.
