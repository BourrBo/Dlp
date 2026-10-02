import io

from pypdf import PdfReader
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

from app.database import get_supabase

def get_drive_connection(org_id: str):
    supabase = get_supabase()

    response = (
        supabase.table("dlp_channels")
        .select("*")
        .eq("org_id", org_id)
        .eq("channel_type", "drive")
        .order("connected_at", desc=True)
        .limit(1)
        .execute()
    )

    rows = response.data or []

    if not rows:
        raise ValueError("Google Drive is not connected")

    return rows[0]

def get_drive_service(org_id: str):
    connection = get_drive_connection(org_id)

    config = connection["config"]

    credentials = Credentials(
        token=config["access_token"],
        refresh_token=config.get("refresh_token"),
        token_uri="https://oauth2.googleapis.com/token",
        client_id=__import__("app.config", fromlist=["get_settings"]).get_settings().google_oauth_client_id,
        client_secret=__import__("app.config", fromlist=["get_settings"]).get_settings().google_oauth_client_secret,
        scopes=config.get("scopes"),
    )

    return build(
        "drive",
        "v3",
        credentials=credentials,
    )


def get_file_permissions(org_id: str, file_id: str):
    service = get_drive_service(org_id)

    response = (
        service.permissions()
        .list(
            fileId=file_id,
            fields="permissions(id,type,role,emailAddress,displayName)",
        )
        .execute()
    )

    permissions = response.get("permissions", [])

    external_permissions = [
        permission
        for permission in permissions
        if permission.get("type") in ["user", "group"]
        and permission.get("role") != "owner"
    ]

    return {
        "permissions": permissions,
        "external_permissions": external_permissions,
        "has_external_share": len(external_permissions) > 0,
    }


def get_file_content(org_id: str, file_id: str):
    service = get_drive_service(org_id)

    metadata = (
        service.files()
        .get(
            fileId=file_id,
            fields="id,name,mimeType",
        )
        .execute()
    )

    mime_type = metadata.get("mimeType")

    if mime_type == "application/vnd.google-apps.document":
        response = service.files().export(
            fileId=file_id,
            mimeType="text/plain",
        ).execute()

        content = response.decode("utf-8", errors="replace")

    elif mime_type == "application/pdf":
        response = service.files().get_media(
            fileId=file_id
        ).execute()

        reader = PdfReader(io.BytesIO(response))

        content = "\n".join(
            page.extract_text() or ""
            for page in reader.pages
        )

    else:
        content = ""

    return {
        "file_id": file_id,
        "name": metadata.get("name"),
        "mime_type": mime_type,
        "content": content,
    }
