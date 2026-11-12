"""P07 executor for the narrow set of supported Google Drive actions."""

import json
from uuid import UUID

from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from dlp_platform.actions.interfaces import ActionExecutionResult
from dlp_platform.connectors.google_drive import (
    GoogleDriveAPI,
    GoogleOAuthClient,
    GoogleOAuthSettings,
    GoogleTransport,
    ProviderFailure,
)
from dlp_platform.connectors.models import ShareRevocation
from dlp_platform.contracts.common import PolicyAction
from dlp_platform.tables import DLP_CONNECTORS
from dlp_platform.vault.config import VaultConfigurationError
from dlp_platform.vault.models import SecretType
from dlp_platform.vault.service import SecretVault


class GoogleDriveActionExecutor:
    """Execute only a P07-authorized share revocation through P09 credentials."""

    def __init__(self, database_url: str) -> None:
        self.engine = create_engine(database_url, pool_pre_ping=True)

    def execute(
        self, idempotency_key: str, action: PolicyAction, safe_metadata: dict[str, str]
    ) -> ActionExecutionResult:
        del idempotency_key
        try:
            action = PolicyAction(action)
        except ValueError:
            return ActionExecutionResult("failed", "unsupported_connector_action")
        if action is PolicyAction.QUARANTINE:
            return ActionExecutionResult("failed", "quarantine_not_configured")
        if action is not PolicyAction.REVOKE_SHARE:
            return ActionExecutionResult("failed", "unsupported_connector_action")
        try:
            organization_id = UUID(safe_metadata["organization_id"])
            connector_id = UUID(safe_metadata["connector_id"])
            object_id = safe_metadata["drive_object_id"]
            permission_id = safe_metadata["permission_id"]
            if (
                safe_metadata.get("provider") != "google_drive"
                or not 1 <= len(object_id) <= 1024
                or not 1 <= len(permission_id) <= 1024
            ):
                raise ValueError
            with Session(self.engine) as session:
                session.execute(text("SET LOCAL ROLE authenticated"))
                session.execute(
                    text("SELECT set_config('request.jwt.claims', :claims, true)"),
                    {
                        "claims": json.dumps(
                            {
                                "role": "authenticated",
                                "aud": "authenticated",
                                "org_id": str(organization_id),
                                "app_role": "owner",
                            }
                        )
                    },
                )
                secret_id = session.execute(
                    select(DLP_CONNECTORS.c.credential_secret_id).where(
                        DLP_CONNECTORS.c.id == str(connector_id),
                        DLP_CONNECTORS.c.org_id == str(organization_id),
                        DLP_CONNECTORS.c.provider == "google_drive",
                        DLP_CONNECTORS.c.status == "connected",
                    )
                ).scalar_one_or_none()
                if secret_id is None:
                    return ActionExecutionResult("failed", "connector_unavailable")
                vault = SecretVault.from_environment()
                refresh_token = vault.get_for_trusted_service(
                    session,
                    organization_id,
                    UUID(str(secret_id)),
                    allowed_types=frozenset({SecretType.REFRESH_TOKEN}),
                ).get_secret_value()
            settings = GoogleOAuthSettings.from_environment()
            token = GoogleOAuthClient(settings, GoogleTransport()).refresh(refresh_token)
            access_token = token.get("access_token")
            if not isinstance(access_token, str):
                return ActionExecutionResult("failed", "malformed_provider_response")
            result = GoogleDriveAPI(access_token).revoke_share(
                ShareRevocation(object_id=object_id, permission_id=permission_id)
            )
            return ActionExecutionResult(
                "succeeded" if result.succeeded else "failed", result.outcome
            )
        except (KeyError, ValueError, ProviderFailure, VaultConfigurationError):
            return ActionExecutionResult("failed", "connector_action_failed")
        except Exception:
            return ActionExecutionResult("failed", "connector_action_failed")
