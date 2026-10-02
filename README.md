# DLP Guardian

Lovable-independent dashboard, FastAPI scan service, and browser extension. Lovable may continue to edit the frontend through its GitHub integration, but the running application does not call Lovable services.

## Docker quick start

Requirements: Docker Desktop or Docker Engine with the Compose plugin, and a Supabase project controlled by your organization.

1. Create a Supabase project and apply [`dlp-Frontend/drizzle/migrations/0000_create_dlp_schema.sql`](dlp-Frontend/drizzle/migrations/0000_create_dlp_schema.sql) in its SQL editor. Apply [`dlp-backend/app/schemas/sql/002_person_b.sql`](dlp-backend/app/schemas/sql/002_person_b.sql) afterward for classification-rule indexes and constraints.
2. In Supabase Auth settings, set the site URL to `http://localhost:3000`, add `http://localhost:3000/**` as a redirect URL, and enable Google OAuth if you want Google sign-in.
3. Copy `.env.example` to `.env`. Set `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, and `SUPABASE_SERVICE_ROLE_KEY` from that project. Keep the service role/secret key private; it is only passed to the backend container.
4. Build and start the app:

   ```sh
   docker compose up --build -d
   ```

5. Open [http://localhost:3000](http://localhost:3000). The backend health endpoint is [http://localhost:8000/health](http://localhost:8000/health).

To stop the app, run `docker compose down`. The Supabase project remains hosted separately and retains its database and authentication data.

## Services

| Service | Purpose | Port |
| --- | --- | --- |
| `dashboard` | TanStack Start dashboard container | 3000 |
| `backend` | FastAPI detection, policy evaluation, and event logging | 8000 |
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
- Before internet-facing or multi-customer deployment, review scan endpoint authentication and tenant authorization. The current extension scan request includes organization and user IDs supplied by the client.

See [`dlp-backend/README.md`](dlp-backend/README.md) and [`dlp-Frontend/README.md`](dlp-Frontend/README.md) for component-specific details.
