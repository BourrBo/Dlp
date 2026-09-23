"""
Channel integrations — Person C's module.

Stubs only. Follow the SecureFlow OAuth pattern (authorize -> callback ->
store token in dlp_channels.config_json) for both Gmail and Drive. The
webhook handlers should build a ScanRequest per attachment/shared file and
POST it to /api/scan — don't duplicate detection/policy logic here.
"""

from fastapi import APIRouter

router = APIRouter(prefix="/api/channels", tags=["channels"])


@router.get("/gmail/authorize")
def gmail_authorize():
    # TODO(Person C): build Google OAuth URL (gmail.readonly + gmail.send scopes),
    # return {"authorize_url": ...} for the dashboard to redirect to.
    raise NotImplementedError


@router.get("/gmail/callback")
def gmail_callback(code: str):
    # TODO(Person C): exchange code for tokens, store in dlp_channels,
    # register a Gmail watch() on the user's mailbox.
    raise NotImplementedError


@router.post("/gmail/webhook")
def gmail_webhook():
    # TODO(Person C): Pub/Sub push notification handler. Fetch the new
    # message, extract attachment text, build a ScanRequest(channel=EMAIL),
    # POST to /api/scan.
    raise NotImplementedError


@router.get("/drive/authorize")
def drive_authorize():
    raise NotImplementedError


@router.post("/drive/webhook")
def drive_webhook():
    # TODO(Person C): Drive push notification handler for file share events.
    # Build a ScanRequest(channel=CLOUD_STORAGE), POST to /api/scan.
    raise NotImplementedError
