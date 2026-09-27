# DLP Backend

FastAPI backend for the DLP project. Companion to `DLP_Technical_Architecture.docx`.

## Architecture note (updated)

This backend does **not** connect to Supabase directly. Lovable Cloud
projects don't expose their service-role key outside Lovable's own UI, so
instead this service calls two secured routes built into the Lovable
dashboard app itself:

- `POST /api/public/dlp-scan-event` — writes a row to `dlp_events`
- `GET /api/public/dlp-get-policy` — reads the matching `dlp_policies` row

Both are gated by a shared secret (`DLP_BACKEND_SECRET`) sent as the
`x-dlp-secret` header. See `app/database.py`.

The dashboard's own pages (event feed, policy editor, exceptions) still
read/write Supabase directly under the signed-in user's own RLS — that
path is unrelated to this backend and is the more correct pattern for a
UI anyway. `app/routers/events.py` and `app/routers/policy.py` are kept
as empty stubs for that reason; don't build new dashboard-facing CRUD
into this service.

## Setup (local, no Docker)

```
python -m venv venv
.\venv\Scripts\Activate.ps1      # Windows
pip install -r requirements.txt
cp .env.example .env
```

Fill in `.env`:
- `DLP_CONSOLE_BASE_URL` — the Lovable app's URL (preview or published)
- `DLP_BACKEND_SECRET` — a value you generate yourself (e.g. `openssl rand -hex 32`), saved in the Lovable project's **Project Settings → Secrets** under the same name

```
uvicorn main:app --reload
```

## Setup (Docker)

```
docker compose up --build
```

This sidesteps the Python-3.14/Rust-compile issue some dependencies hit
on Windows — the image builds on Linux where prebuilt wheels exist.

Either way, `GET /health` should return `{"status": "ok"}`.

## Test the full pipeline

```
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "org_id": "00000000-0000-0000-0000-000000000000",
    "user_id": "00000000-0000-0000-0000-000000000000",
    "channel": "browser",
    "destination": "personalmail@gmail.com",
    "content": "here is my card 4111 1111 1111 1111"
  }'
```

Check the Lovable dashboard's Event feed — the resulting row should show
up there, since both this backend and the dashboard read/write the same
Supabase project (the Lovable-managed one), just through different paths.

## Module ownership (matches the team plan in the architecture doc)

| Path | Owner | Status |
|---|---|---|
| `app/services/policy_engine.py`, `app/database.py`, deployment | You (lead) | Working v1 |
| `app/services/detection_service.py` | Person B | Working regex baseline — extend with Presidio/EDM/fingerprinting |
| `app/routers/channels.py` | Person C | Stubs only — Gmail/Drive OAuth + webhooks |
| Chrome extension | Person B | Built — see `dlp-extension/` |
| Dashboard | You + whoever's free | Built on Lovable — reads/writes Supabase directly under RLS |

## Notes

- `Finding.matched_snippet` is redacted before it's ever returned or persisted — don't remove `_redact()`.
- `/api/scan` is the only endpoint channels should call; don't duplicate detection/policy logic inside `channels.py` handlers.
- If `DLP_CONSOLE_BASE_URL` or `DLP_BACKEND_SECRET` are unset, `/api/scan` will raise a clear `RuntimeError` rather than failing silently.
