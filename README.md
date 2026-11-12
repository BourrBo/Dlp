# DLP Guardian

Lovable-independent dashboard, FastAPI scan service, and browser extension. Lovable may continue to edit the frontend through its GitHub integration, but the running application does not call Lovable services.

## Docker quick start

Requirements: Docker Desktop or Docker Engine with the Compose plugin, and a Supabase project controlled by your organization.

1. Create a Supabase project and apply these SQL files in order in its SQL Editor: [`0000_create_dlp_schema.sql`](dlp-Frontend/drizzle/migrations/0000_create_dlp_schema.sql), [`002_person_b.sql`](dlp-backend/app/schemas/sql/002_person_b.sql), [`003_p4_findings.sql`](dlp-backend/app/schemas/sql/003_p4_findings.sql), [`004_p4_incidents.sql`](dlp-backend/app/schemas/sql/004_p4_incidents.sql), and [`005_allowlist.sql`](dlp-backend/app/schemas/sql/005_allowlist.sql). Skip files already applied to that project.
2. In Supabase Auth settings, set the site URL to `http://localhost:3001`, add `http://localhost:3001/**` as a redirect URL, and enable Google OAuth if you want Google sign-in.
3. Copy `.env.example` to `.env`. Set `PLATFORM_DB_PASSWORD` to a long random value, and set `SUPABASE_JWT_SECRET` (or `SUPABASE_JWKS_URL`) so `/platform` accepts dashboard sign-ins. Set `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, and `SUPABASE_SERVICE_ROLE_KEY` from that project. Keep the service role/secret key private; it is only passed to the backend container. The scan and file-job routes verify a Supabase bearer token and organization membership in every environment.
4. Build and start the app:

   ```sh
   docker compose up --build -d
   ```

5. Open [http://localhost:3001](http://localhost:3001). The backend health endpoint is [http://localhost:8000/health](http://localhost:8000/health).

To stop the app, run `docker compose down`. The Supabase project remains hosted separately and retains its database and authentication data.

### File scan (P3 W1-8 slice)

After signing into the dashboard, open **Scan a file** in the sidebar. Uploads
up to 25 MiB support text/code, CSV, JSON, XML, PDF, DOCX, XLSX, PPTX, and
ZIP/TAR/GZ archives. PDF pages without selectable text use Tesseract OCR;
archives are scanned in memory with path, link, and expansion checks.

Scans run as durable background jobs. The dashboard shows progress, retains
recent results across page reloads, and supports cancellation. Job metadata and
masked results live in the `dlp-job-data` Docker volume. Queued upload bytes are
encrypted using `SCAN_JOBS_ENCRYPTION_KEY`, then erased at a terminal state.
Generate it with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` and keep it stable. During rotation, retain the old key in `SCAN_JOBS_PREVIOUS_ENCRYPTION_KEYS` until queued work drains. A legacy service-role-derived key remains readable for existing local queues. The SQLite volume is local to one Docker host and the worker is not horizontally scalable.
### Platform, API keys and clients

The compose stack also starts `platform-db` (PostgreSQL) and mounts the enterprise platform at `/platform`
(API keys, policies, destinations, exceptions, approvals, connectors, vault, SSO/SCIM, audit, public API).
Migrations run automatically when the backend container starts. See [docs/INTEGRATION.md](docs/INTEGRATION.md).

1. Sign in to the dashboard as an organization owner/admin and open **API keys**. Create a key; it is shown once.
2. Give that `dlp_...` key to the Chrome extension (managed policy `apiKey`), `dlp sync-allowlist --api-key`, the endpoint agent, or CI.
   Keys are scoped to `scan:request`, bound to one organization, and work only on scan routes.
3. People without a key can sign in from the extension settings with their dashboard account instead.

Run the test suites with `cd dlp-backend && pytest` (`APP_ENV=unit-test DATABASE_URL=sqlite:///./t.db` for the platform tests),
`cd dlp-extension && node --test tests/*.test.js`, `cd dlp-cli && pytest`, `cd dlp-agent && pytest`, `cd dlp-vscode && npm test`.


Compose binds both exposed ports to `127.0.0.1` by default. Set
`BACKEND_BIND_ADDRESS` or `DASHBOARD_BIND_ADDRESS` to a network interface only
when the deployment has an appropriate TLS reverse proxy, secrets management,
and network policy.

## Services

| Service | Purpose | Port |
| --- | --- | --- |
| `dashboard` | TanStack Start dashboard container (host port 3001; container port 3000) | 3001 |
| `backend` | FastAPI detection, policy evaluation, file jobs, authenticated overview and incident APIs | 8000 |
| Supabase | Company-managed Postgres, Auth, RLS, and Data API | configured externally |

The frontend uses the publishable key and user sessions, protected by the database RLS policies. The backend uses `SUPABASE_SERVICE_ROLE_KEY` to read policies and write redacted events. Never put the server key in frontend source, a `VITE_*` variable, or a public image.

The frontend image embeds the Supabase URL and publishable key during its build. Rebuild the dashboard image after changing either value. The server-only key is injected at container runtime and is not built into the image.

## Local development

Start the backend from `dlp-backend/` with its `.env` configured from the same variables, then start the frontend from `dlp-Frontend/` using Bun:

```sh
uvicorn main:app --reload
bun install
bun run dev
```

For the frontend, set `VITE_SUPABASE_URL` and `VITE_SUPABASE_PUBLISHABLE_KEY` in its local environment. `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY` are also needed by its server-side auth middleware.

## Current scope and deployment notes

- Detection includes regex, org-scoped custom rules, and hashed EDM; Presidio/NER and ssdeep fingerprints are optional installs.
- Gmail and Drive helper services are present, but their OAuth/webhook routes remain disabled until tenant authorization and encrypted token storage are implemented. Slack WARN/BLOCK alerts are available when `SLACK_WEBHOOK_URL` is configured.
- This Compose setup expects a separately provisioned Supabase project. It does not bundle local Supabase, email delivery, or Google OAuth credentials.
- `/api/scan`, `/scans`, `/scan-jobs`, `/api/overview`, and `/api/v1/incidents` require a valid Supabase access token and verify organization membership. The extension still needs the scoped, revocable API-key contract. Incident creation from scan findings and automatic finding persistence are not yet wired, so the incident UI can be empty until that workflow is added.
- Teammate source integration boundaries and remaining work are tracked in [`docs/TEAMMATE-MERGE-STATUS.md`](docs/TEAMMATE-MERGE-STATUS.md). The P2 platform is vendored in `dlp-backend/dlp_platform`, mounted at `/platform`, and runs in the compose stack with its own `platform-db` (see [`docs/INTEGRATION.md`](docs/INTEGRATION.md)).

See [`docs/p3-implementation-status.md`](docs/p3-implementation-status.md), [`docs/extension.md`](docs/extension.md), [`dlp-backend/README.md`](dlp-backend/README.md), and [`dlp-Frontend/README.md`](dlp-Frontend/README.md) for component-specific details.
