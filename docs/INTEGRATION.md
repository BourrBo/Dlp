# How the pieces fit together

| Piece | Owner | Where | Talks to |
|---|---|---|---|
| Scan API, extractors, detection, policy, incidents | P3/P4 | `dlp-backend/app` | Supabase REST |
| Secret Guard engine (secrets, entropy, Indian identifiers) | P1 | `dlp-backend/secretguard` | called by `detection_service` |
| Enterprise platform (keys, policy, connectors, vault, SSO/SCIM, audit) | P2 | `dlp-backend/dlp_platform`, mounted at `/platform` | its own PostgreSQL (`platform-db`) |
| Dashboard | P4 | `dlp-Frontend` | `/api/*`, `/platform/*` |
| Chrome extension | P3/P4 | `dlp-extension` | `/api/scan`, `/scan-jobs` |
| CLI, pre-commit, GitHub Action, VS Code, endpoint agent | P3 | `dlp-cli`, `action.yml`, `dlp-vscode`, `dlp-agent` | `/api/v1/allowlist`, `/agent/*` |

## Identity

* Dashboard users sign in with Supabase. The backend verifies the bearer token and organization membership.
* `POST /api/platform/link` copies the user's organization and role into the platform database (same UUIDs). The dashboard does this automatically before using `/platform`.
* Machines use `dlp_<prefix>.<secret>` API keys minted at `/platform/api-keys`. `get_scan_principal` accepts them on scan routes only; dashboard-data routes accept Supabase sessions only. `org_id` may be omitted in scan requests and is taken from the key.

## Detection and findings

`/api/scan` runs built-in rules, Secret Guard, organization custom rules, exact-data and fingerprint matching, then the policy engine. Every finding is stored (masked evidence only) in `dlp_findings`; block/warn decisions open or update an incident. `/platform/scan` uses the same detectors through `app/platform_bridge/pipeline.py`.

## Known limits

* The platform scan path does not apply organization-specific custom detectors (custom regex, EDM, fingerprints); `/api/scan` does.
* Two policy systems exist: the main `dlp_policies` table (used by `/api/scan`) and platform policies, destinations and exceptions (`/platform`).
* In production the platform needs a shared rate-limit store; compose runs `valkey` and sets `RATE_LIMIT_BACKEND=valkey`. Without it, platform pages that rate-limit return HTTP 500.
* Platform migrations run automatically at backend start. They need Supabase's `authenticated` role and `auth.jwt()`, which `dlp-backend/platform_db/init/01-supabase-auth-compat.sql` creates the first time the `platform-db` volume is made. If you change that script or see `role "authenticated" does not exist`, reset the platform database with `docker compose down -v` (this removes only platform data).
* One upstream platform test (`test_postgres_lifecycle_http_routes_authenticate_scoped_sessions_and_exports`) is intermittent; it fails about half the time when run alone and is not caused by the merge.
* Supabase and the platform database must be separate: platform table names (`organizations`, `members`, `events`) would clash with the Supabase `public` schema.
