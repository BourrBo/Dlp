"""Add tenant-scoped SSO providers, identities, and one-use login transactions."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0010_sso"
down_revision: str | None = "0009_audit_log"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_AUDIT_ACTIONS = (
    "'auth.authorization_denied','auth.api_key_created','auth.api_key_revoked',"
    "'policy.created','policy.updated','policy.deleted','policy.rolled_back',"
    "'exception.created','exception.updated','exception.deleted',"
    "'suppression.created','suppression.updated','suppression.deleted',"
    "'destination.created','destination.updated','destination.deleted',"
    "'approval.requested','approval.approved','approval.rejected','approval.cancelled',"
    "'approval.expired','action.requested','action.executed','secret.created',"
    "'secret.updated','secret.deleted','secret.rotated'"
)
_SSO_AUDIT_ACTIONS = (
    "'sso.configuration_created','sso.configuration_updated','sso.configuration_enabled',"
    "'sso.configuration_disabled','sso.login_started','sso.login_success',"
    "'sso.login_failed','sso.identity_mapping_created','sso.configuration_deleted'"
)
_SCIM_AUDIT_ACTIONS = (
    "'scim.credential_created','scim.credential_revoked','scim.user_provisioned',"
    "'scim.user_updated','scim.user_deactivated','scim.group_created','scim.group_updated',"
    "'scim.group_deleted','scim.membership_changed'"
)


def _restore_audit_action_check(actions: str) -> None:
    op.drop_constraint("ck_audit_events_action", "audit_events", type_="check")
    op.create_check_constraint("ck_audit_events_action", "audit_events", f"action IN ({actions})")


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("P11 SSO migration requires PostgreSQL RLS")

    op.add_column("members", sa.Column("email", sa.String(320), nullable=True))
    op.create_index(
        "uq_members_org_email_ci",
        "members",
        ["organization_id", sa.text("lower(email)")],
        unique=True,
        postgresql_where=sa.text("email IS NOT NULL"),
    )
    op.create_unique_constraint(
        "uq_dlp_vault_secrets_id_org", "dlp_vault_secrets", ["id", "org_id"]
    )

    op.create_table(
        "dlp_sso_configs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("protocol", sa.String(8), nullable=False),
        sa.Column("issuer", sa.String(2048), nullable=False),
        sa.Column("client_id", sa.String(512), nullable=True),
        sa.Column("secret_ref", sa.String(36), nullable=True),
        sa.Column("certificate_ref", sa.String(36), nullable=True),
        sa.Column("settings", JSONB(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "protocol", name="uq_dlp_sso_configs_org_protocol"),
        sa.UniqueConstraint("id", "org_id", name="uq_dlp_sso_configs_id_org"),
        sa.ForeignKeyConstraint(
            ["created_by", "org_id"], ["members.id", "members.organization_id"]
        ),
        sa.ForeignKeyConstraint(
            ["secret_ref", "org_id"],
            ["dlp_vault_secrets.id", "dlp_vault_secrets.org_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["certificate_ref", "org_id"],
            ["dlp_vault_secrets.id", "dlp_vault_secrets.org_id"],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("protocol IN ('oidc','saml')", name="ck_dlp_sso_configs_protocol"),
        sa.CheckConstraint(
            "(protocol = 'oidc' AND client_id IS NOT NULL AND secret_ref IS NOT NULL) OR "
            "(protocol = 'saml' AND certificate_ref IS NOT NULL)",
            name="ck_dlp_sso_configs_protocol_refs",
        ),
        sa.CheckConstraint("jsonb_typeof(settings) = 'object'", name="ck_dlp_sso_settings_object"),
    )
    op.create_index("ix_dlp_sso_configs_org", "dlp_sso_configs", ["org_id"])

    op.create_table(
        "dlp_sso_identities",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("config_id", sa.String(36), nullable=False),
        sa.Column("member_id", sa.String(36), nullable=False),
        sa.Column("issuer", sa.String(2048), nullable=False),
        sa.Column("subject", sa.String(512), nullable=False),
        sa.Column("email", sa.String(320), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["config_id", "org_id"],
            ["dlp_sso_configs.id", "dlp_sso_configs.org_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["member_id", "org_id"],
            ["members.id", "members.organization_id"],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("org_id", "config_id", "issuer", "subject", name="uq_dlp_sso_identity"),
        sa.UniqueConstraint("org_id", "member_id", "config_id", name="uq_dlp_sso_member_config"),
    )
    op.create_index("ix_dlp_sso_identities_org", "dlp_sso_identities", ["org_id"])
    op.create_index("ix_dlp_sso_identities_member", "dlp_sso_identities", ["org_id", "member_id"])

    op.create_table(
        "dlp_sso_transactions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("config_id", sa.String(36), nullable=False),
        sa.Column("protocol", sa.String(8), nullable=False),
        sa.Column("state_hash", sa.String(64), nullable=False),
        sa.Column("nonce_hash", sa.String(64), nullable=False),
        sa.Column("request_id", sa.String(256), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["config_id", "org_id"],
            ["dlp_sso_configs.id", "dlp_sso_configs.org_id"],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("state_hash", name="uq_dlp_sso_transaction_state"),
        sa.CheckConstraint("protocol IN ('oidc','saml')", name="ck_dlp_sso_transaction_protocol"),
    )
    op.create_index("ix_dlp_sso_transactions_expiry", "dlp_sso_transactions", ["expires_at"])

    op.create_table(
        "dlp_sso_replays",
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("config_id", sa.String(36), nullable=False),
        sa.Column("assertion_id", sa.String(256), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["config_id", "org_id"],
            ["dlp_sso_configs.id", "dlp_sso_configs.org_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("org_id", "assertion_id"),
    )
    op.create_index("ix_dlp_sso_replays_expiry", "dlp_sso_replays", ["expires_at"])

    for table in ("dlp_sso_configs", "dlp_sso_identities"):
        op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        op.execute(sa.text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
        op.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO authenticated"))
        op.execute(
            sa.text(
                f"CREATE POLICY tenant_{table}_admin ON {table} FOR ALL TO authenticated "
                "USING (org_id = (auth.jwt() ->> 'org_id') AND "
                "(auth.jwt() ->> 'app_role') IN ('owner','admin')) "
                "WITH CHECK (org_id = (auth.jwt() ->> 'org_id') AND "
                "(auth.jwt() ->> 'app_role') IN ('owner','admin'))"
            )
        )
    for table in ("dlp_sso_transactions", "dlp_sso_replays"):
        op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        op.execute(sa.text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))

    _restore_audit_action_check(f"{_AUDIT_ACTIONS},{_SSO_AUDIT_ACTIONS}")


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("P11 SSO migration downgrade requires PostgreSQL")
    # Audit entries survive feature rollback, so retain accepted historical action values.
    _restore_audit_action_check(
        f"{_AUDIT_ACTIONS},{_SSO_AUDIT_ACTIONS},{_SCIM_AUDIT_ACTIONS}"
    )
    op.drop_table("dlp_sso_replays")
    op.drop_index("ix_dlp_sso_transactions_expiry", table_name="dlp_sso_transactions")
    op.drop_table("dlp_sso_transactions")
    op.drop_index("ix_dlp_sso_identities_member", table_name="dlp_sso_identities")
    op.drop_index("ix_dlp_sso_identities_org", table_name="dlp_sso_identities")
    op.drop_table("dlp_sso_identities")
    op.drop_index("ix_dlp_sso_configs_org", table_name="dlp_sso_configs")
    op.drop_table("dlp_sso_configs")
    op.drop_index("uq_members_org_email_ci", table_name="members")
    op.drop_constraint("uq_dlp_vault_secrets_id_org", "dlp_vault_secrets", type_="unique")
    op.drop_column("members", "email")
