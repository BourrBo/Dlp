"""Allow Microsoft Graph connectors while preserving P16 tenant/RLS schema."""

from collections.abc import Sequence

from alembic import op
from sqlalchemy import text

revision: str = "0016_microsoft_connectors"
down_revision: str | None = "0015_oauth_transactions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_CONNECTORS = "'google_drive','microsoft_onedrive','microsoft_sharepoint'"
_OAUTH_PROVIDERS = "'google_drive','microsoft_graph'"
_AUDIT_ACTIONS = (
    "'auth.authorization_denied','auth.api_key_created','auth.api_key_revoked',"
    "'policy.created','policy.updated','policy.deleted','policy.rolled_back',"
    "'exception.created','exception.updated','exception.deleted',"
    "'suppression.created','suppression.updated','suppression.deleted',"
    "'destination.created','destination.updated','destination.deleted',"
    "'approval.requested','approval.approved','approval.rejected','approval.cancelled',"
    "'approval.expired','action.requested','action.executed','secret.created',"
    "'secret.updated','secret.deleted','secret.rotated','sso.configuration_created',"
    "'sso.configuration_updated','sso.configuration_enabled','sso.configuration_disabled',"
    "'sso.login_started','sso.login_success','sso.login_failed',"
    "'sso.identity_mapping_created','sso.configuration_deleted',"
    "'scim.credential_created','scim.credential_revoked','scim.user_provisioned',"
    "'scim.user_updated','scim.user_deactivated','scim.group_created','scim.group_updated',"
    "'scim.group_deleted','scim.membership_changed','identity.session_established',"
    "'identity.session_revoked','identity.sessions_revoked','identity.organization_switched',"
    "'identity.ip_allowlist_enabled','identity.ip_allowlist_disabled',"
    "'identity.ip_allowlist_entry_added','identity.ip_allowlist_entry_removed',"
    "'identity.ip_allowlist_blocked','retention.policy_updated','retention.batch_completed',"
    "'retention.batch_failed','legal_hold.created','legal_hold.released',"
    "'organization.deletion_requested','organization.deletion_confirmed',"
    "'organization.deletion_started','organization.deletion_blocked',"
    "'organization.deletion_failed','organization.deletion_completed',"
    "'subject.export_requested','subject.export_completed','subject.export_failed',"
    "'connector.created','connector.oauth_completed','connector.connected',"
    "'connector.disconnected','connector.reauth_required','connector.sync_failed',"
    "'connector.exposure_detected','connector.share_revoked','connector.share_revoke_requested',"
    "'connector.share_revoke_failed','connector.quarantine_requested',"
    "'connector.quarantine_completed','connector.quarantine_failed',"
    "'connector.microsoft_library_selected'"
)
_OLD_AUDIT_ACTIONS = _AUDIT_ACTIONS.rsplit(",'connector.microsoft_library_selected'", 1)[0]


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("P17 Microsoft connectors require PostgreSQL RLS")
    op.drop_constraint("ck_dlp_connectors_provider", "dlp_connectors", type_="check")
    op.create_check_constraint(
        "ck_dlp_connectors_provider", "dlp_connectors", f"provider IN ({_CONNECTORS})"
    )
    op.drop_constraint("ck_audit_events_action", "audit_events", type_="check")
    op.create_check_constraint(
        "ck_audit_events_action", "audit_events", f"action IN ({_AUDIT_ACTIONS})"
    )
    op.drop_constraint("ck_dlp_connector_state_provider", "dlp_connector_state", type_="check")
    op.create_check_constraint(
        "ck_dlp_connector_state_provider", "dlp_connector_state", f"provider IN ({_CONNECTORS})"
    )
    op.drop_constraint(
        "ck_dlp_oauth_transactions_provider", "dlp_oauth_transactions", type_="check"
    )
    op.create_check_constraint(
        "ck_dlp_oauth_transactions_provider",
        "dlp_oauth_transactions",
        f"provider IN ({_OAUTH_PROVIDERS})",
    )


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("P17 Microsoft connector downgrade requires PostgreSQL RLS")
    microsoft_rows = (
        op.get_bind()
        .execute(
            text(
                "SELECT count(*) FROM dlp_connectors "
                "WHERE provider IN ('microsoft_onedrive','microsoft_sharepoint')"
            )
        )
        .scalar_one()
    )
    if microsoft_rows:
        raise RuntimeError("Cannot downgrade while Microsoft connectors exist")
    oauth_rows = (
        op.get_bind()
        .execute(
            text("SELECT count(*) FROM dlp_oauth_transactions WHERE provider='microsoft_graph'")
        )
        .scalar_one()
    )
    if oauth_rows:
        raise RuntimeError("Cannot downgrade while Microsoft OAuth transactions exist")
    microsoft_audit_rows = (
        op.get_bind()
        .execute(
            text(
                "SELECT count(*) FROM audit_events "
                "WHERE action='connector.microsoft_library_selected'"
            )
        )
        .scalar_one()
    )
    if microsoft_audit_rows:
        raise RuntimeError("Cannot downgrade while Microsoft library audit events exist")
    op.drop_constraint("ck_audit_events_action", "audit_events", type_="check")
    op.create_check_constraint(
        "ck_audit_events_action", "audit_events", f"action IN ({_OLD_AUDIT_ACTIONS})"
    )
    op.drop_constraint(
        "ck_dlp_oauth_transactions_provider", "dlp_oauth_transactions", type_="check"
    )
    op.create_check_constraint(
        "ck_dlp_oauth_transactions_provider",
        "dlp_oauth_transactions",
        "provider IN ('google_drive')",
    )
    op.drop_constraint("ck_dlp_connector_state_provider", "dlp_connector_state", type_="check")
    op.create_check_constraint(
        "ck_dlp_connector_state_provider",
        "dlp_connector_state",
        "provider IN ('google_drive')",
    )
    op.drop_constraint("ck_dlp_connectors_provider", "dlp_connectors", type_="check")
    op.create_check_constraint(
        "ck_dlp_connectors_provider", "dlp_connectors", "provider IN ('google_drive')"
    )
