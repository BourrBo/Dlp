import base64
import httpx

from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials

from app.config import get_settings
from app.database import get_supabase


def create_gmail_service(
    access_token: str,
    refresh_token: str,
    client_id: str,
    client_secret: str,
):
    import httplib2
    from google_auth_httplib2 import AuthorizedHttp

    credentials = Credentials(
        token=access_token,
        refresh_token=refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=client_id,
        client_secret=client_secret,
        scopes=[
            "https://www.googleapis.com/auth/gmail.readonly",
        ],
    )

    http = AuthorizedHttp(credentials, http=httplib2.Http())

    return build(
        "gmail",
        "v1",
        http=http,
    )


def list_recent_messages(service, max_results: int = 10):
    response = (
        service.users()
        .messages()
        .list(
            userId="me",
            maxResults=max_results,
        )
        .execute()
    )

    return response.get("messages", [])


def get_gmail_connection(org_id: str):
    supabase = get_supabase()

    result = (
        supabase.table("dlp_channels")
        .select("config")
        .eq("org_id", org_id)
        .eq("channel_type", "gmail")
        .order("connected_at", desc=True)
        .limit(1)
        .execute()
    )

    if not result.data:
        raise ValueError("No Gmail connection found for this organization")

    return result.data[0]["config"]


def get_gmail_service(org_id: str):
    config = get_gmail_connection(org_id)

    settings = get_settings()

    return create_gmail_service(
        access_token=config["access_token"],
        refresh_token=config["refresh_token"],
        client_id=settings.google_oauth_client_id,
        client_secret=settings.google_oauth_client_secret,
    )


def get_message(service, message_id: str):
    message = (
        service.users()
        .messages()
        .get(
            userId="me",
            id=message_id,
            format="full",
        )
        .execute()
    )

    headers = message.get("payload", {}).get("headers", [])

    subject = ""
    sender = ""
    recipients = []

    for header in headers:
        name = header["name"].lower()
        value = header["value"]

        if name == "subject":
            subject = value
        elif name == "from":
            sender = value
        elif name in ("to", "cc", "bcc"):
            recipients.append(value)

    body = extract_body(message.get("payload", {}))

    return {
        "id": message_id,
        "subject": subject,
        "sender": sender,
        "recipients": recipients,
        "body": body,
    }


def extract_body(payload):
    body_data = payload.get("body", {}).get("data")

    if body_data:
        return base64.urlsafe_b64decode(body_data).decode(
            "utf-8",
            errors="replace",
        )

    for part in payload.get("parts", []):
        result = extract_body(part)

        if result:
            return result

    return ""


def scan_gmail_message(
    service,
    message_id: str,
    org_id: str,
    user_id: str,
):
    message = get_message(service, message_id)

    response = httpx.post(
        f"{get_settings().dlp_backend_base_url.rstrip('/')}/api/scan",
        json={
            "content": message["body"],
            "channel": "email",
            "destination": message["sender"],
            "org_id": org_id,
            "user_id": user_id,
        },
        timeout=30.0,
    )

    response.raise_for_status()

    return {
        "message": message,
        "scan_result": response.json(),
    }


def list_history(service, start_history_id: str):
    response = (
        service.users()
        .history()
        .list(
            userId="me",
            startHistoryId=start_history_id,
            historyTypes=["messageAdded"],
        )
        .execute()
    )

    return response
