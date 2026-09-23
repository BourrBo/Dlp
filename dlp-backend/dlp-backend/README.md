# DLP Backend

FastAPI backend for the DLP project. Companion to `DLP_Technical_Architecture.docx`.

## Setup

```
pip install -r requirements.txt
cp .env.example .env   # fill in Supabase project credentials
```

Run the SQL in `app/schemas/sql/001_init.sql` in your Supabase project's SQL editor
before starting the app (it assumes an `org_members(org_id, user_id)` table already
exists for RLS — create one first if this is a fresh project).

```
uvicorn main:app --reload
```

`GET /health` should return `{"status": "ok"}`. `POST /api/scan` is wired
end-to-end (regex detection -> policy engine -> event persisted) so you can
test the full pipeline immediately, even before any channel is built:

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

## Module ownership (matches the team plan in the architecture doc)

| Path | Owner | Status |
|---|---|---|
| `app/services/policy_engine.py`, `app/routers/policy.py`, `app/schemas/sql/`, deployment | You (lead) | Working v1 |
| `app/services/detection_service.py` | Person B | Working regex baseline — extend with Presidio/EDM/fingerprinting |
| `app/routers/channels.py` | Person C | Stubs only — Gmail/Drive OAuth + webhooks |
| Chrome extension | Person B | Not started — new `extension/` folder |
| Dashboard | You + whoever's free | Not started — separate Vite/Lovable project, same pattern as SecureFlow's frontend |

## Notes

- `Finding.matched_snippet` is redacted before it's ever returned or persisted — don't remove `_redact()`.
- `/api/scan` is the only endpoint channels should call; don't duplicate detection/policy logic inside `channels.py` handlers.
