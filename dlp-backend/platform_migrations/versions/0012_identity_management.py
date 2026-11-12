"""Add revocable JWT sessions, tenant IP allowlists, and membership discovery."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import CIDR

revision: str = "0012_identity_management"
down_revision: str | None = "0011_scim"
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
    "'scim.group_deleted','scim.membership_changed'"
)
_IDENTITY_ACTIONS = (
    "'identity.session_established','identity.session_revoked','identity.sessions_revoked',"
    "'identity.organization_switched','identity.ip_allowlist_enabled',"
    "'identity.ip_allowlist_disabled','identity.ip_allowlist_entry_added',"
    "'identity.ip_allowlist_entry_removed','identity.ip_allowlist_blocked'"
)


def _audit_actions(actions: str) -> None:
    op.drop_constraint("ck_audit_events_action", "audit_events", type_="check")
    op.create_check_constraint(
        "ck_audit_events_action", "audit_events", f"action IN ({actions})"
    )


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("P13 identity migration requires PostgreSQL RLS")

    op.create_table(
        "dlp_app_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("member_id", sa.String(36), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("auth_method", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_ip", sa.String(64), nullable=True),
        sa.Column("user_agent", sa.String(512), nullable=True),
        sa.ForeignKeyConstraint(
            ["member_id", "org_id"], ["members.id", "members.organization_id"],
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "auth_method IN ('jwt','sso')", name="ck_dlp_app_sessions_auth_method"
        ),
    )
    op.create_index(
        "ix_dlp_app_sessions_org_member", "dlp_app_sessions", ["org_id", "member_id"]
    )
    op.execute(sa.text("ALTER TABLE dlp_app_sessions ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE dlp_app_sessions FORCE ROW LEVEL SECURITY"))
    op.execute(sa.text("GRANT SELECT, UPDATE ON dlp_app_sessions TO authenticated"))
    op.execute(
        sa.text(
            "CREATE POLICY identity_member_sessions ON dlp_app_sessions FOR SELECT "
            "TO authenticated USING (EXISTS (SELECT 1 FROM members m "
            "WHERE org_id = (auth.jwt() ->> 'org_id') "
            "AND m.id = member_id AND m.organization_id = org_id "
            "AND m.auth_subject_id = (auth.jwt() ->> 'sub')))"
        )
    )
    op.execute(
        sa.text(
            "CREATE POLICY identity_member_sessions_update ON dlp_app_sessions FOR UPDATE "
            "TO authenticated USING (EXISTS (SELECT 1 FROM members m "
            "WHERE org_id = (auth.jwt() ->> 'org_id') "
            "AND m.id = member_id AND m.organization_id = org_id "
            "AND m.auth_subject_id = (auth.jwt() ->> 'sub'))) "
            "WITH CHECK (EXISTS (SELECT 1 FROM members m "
            "WHERE m.id = member_id AND m.organization_id = org_id "
            "AND m.auth_subject_id = (auth.jwt() ->> 'sub') AND m.active))"
        )
    )

    op.create_table(
        "dlp_ip_allowlist_settings",
        sa.Column(
            "org_id",
            sa.String(36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("updated_by", sa.String(36), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["updated_by", "org_id"], ["members.id", "members.organization_id"]
        ),
    )
    op.execute(sa.text("ALTER TABLE dlp_ip_allowlist_settings ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE dlp_ip_allowlist_settings FORCE ROW LEVEL SECURITY"))
    op.execute(
        sa.text(
            "GRANT SELECT, INSERT, UPDATE, DELETE "
            "ON dlp_ip_allowlist_settings TO authenticated"
        )
    )
    op.execute(
        sa.text(
            "CREATE POLICY identity_ip_admin ON dlp_ip_allowlist_settings FOR ALL "
            "TO authenticated USING (org_id = (auth.jwt() ->> 'org_id') "
            "AND (auth.jwt() ->> 'app_role') IN ('owner','admin')) "
            "WITH CHECK (org_id = (auth.jwt() ->> 'org_id') "
            "AND (auth.jwt() ->> 'app_role') IN ('owner','admin'))"
        )
    )

    op.create_table(
        "dlp_ip_allowlist_entries",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("network", CIDR(), nullable=False),
        sa.Column("label", sa.String(120), nullable=False),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["org_id"], ["dlp_ip_allowlist_settings.org_id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["created_by", "org_id"], ["members.id", "members.organization_id"]
        ),
        sa.UniqueConstraint("org_id", "network", name="uq_dlp_ip_allowlist_network"),
    )
    op.create_index("ix_dlp_ip_allowlist_entries_org", "dlp_ip_allowlist_entries", ["org_id"])
    op.execute(sa.text("ALTER TABLE dlp_ip_allowlist_entries ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE dlp_ip_allowlist_entries FORCE ROW LEVEL SECURITY"))
    op.execute(
        sa.text("GRANT SELECT, INSERT, UPDATE, DELETE ON dlp_ip_allowlist_entries TO authenticated")
    )
    op.execute(
        sa.text(
            "CREATE POLICY identity_ip_admin ON dlp_ip_allowlist_entries FOR ALL "
            "TO authenticated USING (org_id = (auth.jwt() ->> 'org_id') "
            "AND (auth.jwt() ->> 'app_role') IN ('owner','admin')) "
            "WITH CHECK (org_id = (auth.jwt() ->> 'org_id') "
            "AND (auth.jwt() ->> 'app_role') IN ('owner','admin'))"
        )
    )

    # Users may discover only their own active or inactive memberships across tenants.
    op.execute(
        sa.text(
            "CREATE POLICY member_self_membership_select ON members FOR SELECT TO authenticated "
            "USING (auth_subject_id = (auth.jwt() ->> 'sub'))"
        )
    )
    op.execute(
        sa.text(
            "CREATE POLICY organization_self_membership_select ON organizations "
            "FOR SELECT TO authenticated USING (EXISTS (SELECT 1 FROM members m "
            "WHERE m.organization_id = organizations.id "
            "AND m.auth_subject_id = (auth.jwt() ->> 'sub')))"
        )
    )
    _audit_actions(f"{_ACTIONS},{_IDENTITY_ACTIONS}")


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("P13 identity migration downgrade requires PostgreSQL")
    # Preserve action values for append-only historical audit rows.
    _audit_actions(f"{_ACTIONS},{_IDENTITY_ACTIONS}")
    op.execute(sa.text("DROP POLICY organization_self_membership_select ON organizations"))
    op.execute(sa.text("DROP POLICY member_self_membership_select ON members"))
    op.drop_index("ix_dlp_ip_allowlist_entries_org", table_name="dlp_ip_allowlist_entries")
    op.drop_table("dlp_ip_allowlist_entries")
    op.drop_table("dlp_ip_allowlist_settings")
    op.drop_index("ix_dlp_app_sessions_org_member", table_name="dlp_app_sessions")
    op.drop_table("dlp_app_sessions")
