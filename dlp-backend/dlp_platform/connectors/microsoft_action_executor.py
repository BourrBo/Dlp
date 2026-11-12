"""P07 executor for Microsoft sharing revocation via the P09 Vault."""

import json
from uuid import UUID

from pydantic import SecretStr
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from dlp_platform.actions.interfaces import ActionExecutionResult, ActionExecutor
from dlp_platform.auth.roles import ROLE_PERMISSIONS
from dlp_platform.connectors.microsoft_graph import (
    MicrosoftGraphAPI,
    MicrosoftHTTPTransport,
    MicrosoftOAuthClient,
    MicrosoftOAuthSettings,
    MicrosoftProviderFailure,
)
from dlp_platform.connectors.models import ShareRevocation
from dlp_platform.contracts.common import ActorType, AuthMethod, PolicyAction, Role
from dlp_platform.contracts.principal import Principal
from dlp_platform.tables import DLP_CONNECTOR_STATE, DLP_CONNECTORS
from dlp_platform.vault.config import VaultConfigurationError
from dlp_platform.vault.models import SecretType
from dlp_platform.vault.service import SecretVault, VaultOperationFailed


class MicrosoftGraphActionExecutor:
    """Execute only approved Microsoft share revocations; unknown actions fail closed."""

    def __init__(self, database_url: str) -> None:
        self.engine = create_engine(database_url, pool_pre_ping=True)

    @staticmethod
    def _claims(session: Session, organization_id: UUID) -> None:
        if session.bind is not None and session.bind.dialect.name == "postgresql":
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

    @staticmethod
    def _system_principal(organization_id: UUID) -> Principal:
        return Principal(
            organization_id=organization_id,
            subject_id="service:microsoft-connector-token-refresh",
            actor_type=ActorType.SERVICE,
            role=Role.OWNER,
            scopes=tuple(sorted(permission.value for permission in ROLE_PERMISSIONS[Role.OWNER])),
            auth_method=AuthMethod.INTERNAL,
        )

    def execute(
        self, idempotency_key: str, action: PolicyAction, safe_metadata: dict[str, str]
    ) -> ActionExecutionResult:
        del idempotency_key
        try:
            if PolicyAction(action) is not PolicyAction.REVOKE_SHARE:
                return ActionExecutionResult("failed", "unsupported_connector_action")
            provider = safe_metadata["provider"]
            if provider not in {"microsoft_onedrive", "microsoft_sharepoint"}:
                return ActionExecutionResult("failed", "unsupported_connector_provider")
            organization_id = UUID(safe_metadata["organization_id"])
            connector_id = UUID(safe_metadata["connector_id"])
            drive_id, object_id, permission_id = (
                safe_metadata["drive_id"],
                safe_metadata["drive_object_id"],
                safe_metadata["permission_id"],
            )
            if any(
                not value or len(value) > 1024 for value in (drive_id, object_id, permission_id)
            ):
                return ActionExecutionResult("failed", "invalid_action_target")
            with Session(self.engine) as session:
                self._claims(session, organization_id)
                row = (
                    session.execute(
                        select(
                            DLP_CONNECTORS.c.credential_secret_id,
                            DLP_CONNECTORS.c.config_json,
                            DLP_CONNECTOR_STATE.c.state_json,
                        )
                        .where(
                            DLP_CONNECTORS.c.id == str(connector_id),
                            DLP_CONNECTORS.c.org_id == str(organization_id),
                            DLP_CONNECTORS.c.provider == provider,
                            DLP_CONNECTORS.c.status == "connected",
                        )
                        .join(
                            DLP_CONNECTOR_STATE,
                            (DLP_CONNECTOR_STATE.c.connector_id == DLP_CONNECTORS.c.id)
                            & (DLP_CONNECTOR_STATE.c.org_id == DLP_CONNECTORS.c.org_id),
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is None or row["credential_secret_id"] is None:
                    return ActionExecutionResult("failed", "connector_unavailable")
                config = row["config_json"]
                tenant_id = config.get("microsoft_tenant_id") if isinstance(config, dict) else None
                if not isinstance(tenant_id, str):
                    return ActionExecutionResult("failed", "connector_unavailable")
                connector_state = row["state_json"]
                configured_drive = (
                    connector_state.get("drive_id")
                    if provider == "microsoft_onedrive" and isinstance(connector_state, dict)
                    else config.get("sharepoint_drive_id")
                    if isinstance(config, dict)
                    else None
                )
                configured_site = (
                    config.get("sharepoint_site_id") if isinstance(config, dict) else None
                )
                if configured_drive != drive_id or (
                    provider == "microsoft_sharepoint"
                    and configured_site != safe_metadata.get("site_id")
                ):
                    return ActionExecutionResult("failed", "connector_action_target_mismatch")
                secret_id = UUID(str(row["credential_secret_id"]))
                vault = SecretVault.from_environment()
                refresh_token = vault.get_for_trusted_service(
                    session,
                    organization_id,
                    secret_id,
                    allowed_types=frozenset({SecretType.REFRESH_TOKEN}),
                ).get_secret_value()
            settings = MicrosoftOAuthSettings.from_environment()
            oauth = MicrosoftOAuthClient(settings, MicrosoftHTTPTransport())
            token = oauth.refresh(refresh_token, tenant_id)
            access_token = token.get("access_token")
            new_refresh = token.get("refresh_token")
            if not isinstance(access_token, str):
                return ActionExecutionResult("failed", "malformed_provider_response")
            api = MicrosoftGraphAPI(access_token, tenant_id)
            if api.organization_tenant_id() != str(UUID(tenant_id)):
                return ActionExecutionResult("failed", "tenant_mismatch")
            if isinstance(new_refresh, str) and new_refresh and new_refresh != refresh_token:
                with Session(self.engine) as session:
                    self._claims(session, organization_id)
                    vault.set(
                        session,
                        self._system_principal(organization_id),
                        name=f"microsoft-drive-{connector_id}",
                        secret_type=SecretType.REFRESH_TOKEN,
                        value=SecretStr(new_refresh),
                        expires_at=None,
                        secret_id=secret_id,
                    )
            outcome = api.revoke_share(
                ShareRevocation(
                    drive_id=drive_id,
                    object_id=object_id,
                    permission_id=permission_id,
                )
            )
            return ActionExecutionResult(
                "succeeded" if outcome.succeeded else "failed", outcome.outcome
            )
        except (KeyError, ValueError, MicrosoftProviderFailure, VaultConfigurationError):
            return ActionExecutionResult("failed", "connector_action_failed")
        except (VaultOperationFailed, Exception):
            return ActionExecutionResult("failed", "connector_action_failed")


class ConnectorActionExecutor:
    """Dispatch the existing P07 action interface to its registered providers."""

    def __init__(self, database_url: str) -> None:
        from dlp_platform.connectors.action_executor import GoogleDriveActionExecutor

        self._executors: dict[str, ActionExecutor] = {
            "google_drive": GoogleDriveActionExecutor(database_url),
            "microsoft_onedrive": MicrosoftGraphActionExecutor(database_url),
            "microsoft_sharepoint": MicrosoftGraphActionExecutor(database_url),
        }

    def execute(
        self, idempotency_key: str, action: PolicyAction, safe_metadata: dict[str, str]
    ) -> ActionExecutionResult:
        executor = self._executors.get(safe_metadata.get("provider", ""))
        if executor is None:
            return ActionExecutionResult("failed", "unsupported_connector_provider")
        return executor.execute(idempotency_key, action, safe_metadata)
