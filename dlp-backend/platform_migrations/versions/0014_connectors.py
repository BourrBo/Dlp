"""Add tenant-isolated connector registry and checkpoint state (P16)."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0014_connectors"
down_revision: str | None = "0013_data_lifecycle"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ACTIONS = (
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
    "'subject.export_requested','subject.export_completed','subject.export_failed'"
)
_P16 = (
    "'connector.created','connector.oauth_completed','connector.connected',"
    "'connector.disconnected','connector.reauth_required','connector.sync_failed',"
    "'connector.exposure_detected','connector.share_revoked','connector.share_revoke_requested',"
    "'connector.share_revoke_failed','connector.quarantine_requested',"
    "'connector.quarantine_completed','connector.quarantine_failed'"
)


def _set_actions(actions: str) -> None:
    op.drop_constraint("ck_audit_events_action", "audit_events", type_="check")
    op.create_check_constraint("ck_audit_events_action", "audit_events", f"action IN ({actions})")


def _secure(table: str) -> None:
    op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
    op.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO authenticated"))
    tenant = "org_id = (auth.jwt() ->> 'org_id')"
    op.execute(
        sa.text(
            f"CREATE POLICY tenant_{table} ON {table} FOR ALL TO authenticated "
            f"USING ({tenant}) WITH CHECK ({tenant})"
        )
    )


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("P16 connector migration requires PostgreSQL RLS")
    op.create_table(
        "dlp_connectors",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("credential_secret_id", sa.String(36), nullable=True),
        sa.Column("config_json", sa.JSON().with_variant(JSONB(), "postgresql"), nullable=False),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("id", "org_id", name="uq_dlp_connectors_id_org"),
        sa.CheckConstraint("provider IN ('google_drive')", name="ck_dlp_connectors_provider"),
        sa.CheckConstraint(
            "status IN ('disconnected','connecting','connected','degraded',"
            "'reauth_required','error','disconnecting')",
            name="ck_dlp_connectors_status",
        ),
        sa.CheckConstraint("length(name) BETWEEN 1 AND 120", name="ck_dlp_connectors_name"),
    )
    op.create_index("ix_dlp_connectors_org_provider", "dlp_connectors", ["org_id", "provider"])
    op.create_table(
        "dlp_connector_state",
        sa.Column("connector_id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("checkpoint", sa.String(2048), nullable=True),
        sa.Column("state_json", sa.JSON().with_variant(JSONB(), "postgresql"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["connector_id", "org_id"],
            ["dlp_connectors.id", "dlp_connectors.org_id"],
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "length(coalesce(checkpoint, '')) <= 2048", name="ck_dlp_connector_state_checkpoint"
        ),
        sa.CheckConstraint("provider IN ('google_drive')", name="ck_dlp_connector_state_provider"),
    )
    for table in ("dlp_connectors", "dlp_connector_state"):
        _secure(table)
    _set_actions(f"{_ACTIONS},{_P16}")


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("P16 connector migration downgrade requires PostgreSQL RLS")
    op.drop_table("dlp_connector_state")
    op.drop_index("ix_dlp_connectors_org_provider", table_name="dlp_connectors")
    op.drop_table("dlp_connectors")
    # Keep names valid for immutable audit history, following the P14 convention.
    _set_actions(f"{_ACTIONS},{_P16}")
