"""Add tenant-scoped SCIM credentials, user mappings, groups, and lifecycle state."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011_scim"
down_revision: str | None = "0010_sso"
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
    "'sso.identity_mapping_created','sso.configuration_deleted'"
)
_SCIM_ACTIONS = (
    "'scim.credential_created','scim.credential_revoked','scim.user_provisioned',"
    "'scim.user_updated','scim.user_deactivated','scim.group_created','scim.group_updated',"
    "'scim.group_deleted','scim.membership_changed'"
)


def _audit_actions(actions: str) -> None:
    op.drop_constraint("ck_audit_events_action", "audit_events", type_="check")
    op.create_check_constraint(
        "ck_audit_events_action", "audit_events", f"action IN ({actions})"
    )


def _tenant_rls(table: str) -> None:
    op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
    op.execute(
        sa.text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO authenticated")
    )
    op.execute(
        sa.text(
            f"CREATE POLICY tenant_{table} ON {table} FOR ALL TO authenticated "
            "USING (org_id = (auth.jwt() ->> 'org_id') AND "
            "(auth.jwt() ->> 'app_role') IN ('scim','owner','admin')) "
            "WITH CHECK (org_id = (auth.jwt() ->> 'org_id') AND "
            "(auth.jwt() ->> 'app_role') IN ('scim','owner','admin'))"
        )
    )


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("P12 SCIM migration requires PostgreSQL RLS")
    op.add_column(
        "members",
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.execute(sa.text("GRANT INSERT, UPDATE ON members TO authenticated"))
    op.execute(
        sa.text(
            "CREATE POLICY tenant_members_scim_insert ON members FOR INSERT TO authenticated "
            "WITH CHECK (organization_id = (auth.jwt() ->> 'org_id') "
            "AND (auth.jwt() ->> 'app_role') = 'scim' AND role = 'viewer')"
        )
    )
    op.execute(
        sa.text(
            "CREATE POLICY tenant_members_scim_update ON members FOR UPDATE TO authenticated "
            "USING (organization_id = (auth.jwt() ->> 'org_id') "
            "AND (auth.jwt() ->> 'app_role') = 'scim') "
            "WITH CHECK (organization_id = (auth.jwt() ->> 'org_id') "
            "AND (auth.jwt() ->> 'app_role') = 'scim')"
        )
    )
    op.execute(
        sa.text(
            "CREATE FUNCTION protect_scim_member_identity() RETURNS trigger "
            "LANGUAGE plpgsql AS $$ BEGIN "
            "IF auth.jwt() ->> 'app_role' = 'scim' AND "
            "(NEW.id IS DISTINCT FROM OLD.id OR "
            "NEW.organization_id IS DISTINCT FROM OLD.organization_id OR "
            "NEW.auth_subject_id IS DISTINCT FROM OLD.auth_subject_id OR "
            "NEW.role IS DISTINCT FROM OLD.role) THEN "
            "RAISE EXCEPTION 'SCIM cannot modify protected member identity fields'; "
            "END IF; RETURN NEW; END; $$"
        )
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER members_scim_identity_guard BEFORE UPDATE ON members "
            "FOR EACH ROW EXECUTE FUNCTION protect_scim_member_identity()"
        )
    )
    op.create_table(
        "dlp_scim_credentials",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("prefix", sa.String(12), nullable=False, unique=True),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["created_by", "org_id"], ["members.id", "members.organization_id"]
        ),
        sa.UniqueConstraint("id", "org_id", name="uq_dlp_scim_credentials_id_org"),
    )
    op.create_index("ix_dlp_scim_credentials_org", "dlp_scim_credentials", ["org_id"])
    op.create_table(
        "dlp_scim_users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("member_id", sa.String(36), nullable=False),
        sa.Column("external_id", sa.String(512), nullable=True),
        sa.Column("user_name", sa.String(320), nullable=False),
        sa.Column("display_name", sa.String(256), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["member_id", "org_id"],
            ["members.id", "members.organization_id"],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("org_id", "member_id", name="uq_dlp_scim_users_member"),
        sa.CheckConstraint(
            "length(user_name) BETWEEN 1 AND 320", name="ck_dlp_scim_users_username"
        ),
    )
    op.create_index("ix_dlp_scim_users_org", "dlp_scim_users", ["org_id"])
    op.create_index(
        "uq_dlp_scim_users_username_ci",
        "dlp_scim_users",
        ["org_id", sa.text("lower(user_name)")],
        unique=True,
    )
    op.create_index(
        "uq_dlp_scim_users_external",
        "dlp_scim_users",
        ["org_id", "external_id"],
        unique=True,
        postgresql_where=sa.text("external_id IS NOT NULL"),
    )
    op.create_table(
        "dlp_scim_groups",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("external_id", sa.String(512), nullable=True),
        sa.Column("display_name", sa.String(256), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("id", "org_id", name="uq_dlp_scim_groups_id_org"),
        sa.CheckConstraint(
            "length(display_name) BETWEEN 1 AND 256", name="ck_dlp_scim_groups_name"
        ),
    )
    op.create_index("ix_dlp_scim_groups_org", "dlp_scim_groups", ["org_id"])
    op.create_index(
        "uq_dlp_scim_groups_name_ci",
        "dlp_scim_groups",
        ["org_id", sa.text("lower(display_name)")],
        unique=True,
    )
    op.create_index(
        "uq_dlp_scim_groups_external",
        "dlp_scim_groups",
        ["org_id", "external_id"],
        unique=True,
        postgresql_where=sa.text("external_id IS NOT NULL"),
    )
    op.create_table(
        "dlp_scim_group_members",
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("group_id", sa.String(36), nullable=False),
        sa.Column("member_id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["group_id", "org_id"],
            ["dlp_scim_groups.id", "dlp_scim_groups.org_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["member_id", "org_id"],
            ["members.id", "members.organization_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("org_id", "group_id", "member_id"),
    )
    op.create_index(
        "ix_dlp_scim_group_members_member",
        "dlp_scim_group_members",
        ["org_id", "member_id"],
    )
    for table in ("dlp_scim_users", "dlp_scim_groups", "dlp_scim_group_members"):
        _tenant_rls(table)

    op.execute(sa.text("ALTER TABLE dlp_scim_credentials ENABLE ROW LEVEL SECURITY"))
    op.execute(
        sa.text(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON dlp_scim_credentials TO authenticated"
        )
    )
    op.execute(
        sa.text(
            "CREATE POLICY tenant_dlp_scim_credentials_admin ON dlp_scim_credentials "
            "FOR ALL TO authenticated USING (org_id = (auth.jwt() ->> 'org_id') "
            "AND (auth.jwt() ->> 'app_role') IN ('owner','admin')) "
            "WITH CHECK (org_id = (auth.jwt() ->> 'org_id') "
            "AND (auth.jwt() ->> 'app_role') IN ('owner','admin'))"
        )
    )
    _audit_actions(f"{_ACTIONS},{_SCIM_ACTIONS}")


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("P12 SCIM migration downgrade requires PostgreSQL")
    # Audit entries survive feature rollback; retain both P11 and P12 action values.
    _audit_actions(f"{_ACTIONS},{_SCIM_ACTIONS}")
    op.execute(sa.text("DROP TRIGGER members_scim_identity_guard ON members"))
    op.execute(sa.text("DROP FUNCTION protect_scim_member_identity()"))
    op.execute(sa.text("DROP POLICY tenant_members_scim_update ON members"))
    op.execute(sa.text("DROP POLICY tenant_members_scim_insert ON members"))
    op.execute(sa.text("REVOKE INSERT, UPDATE ON members FROM authenticated"))
    op.drop_index(
        "ix_dlp_scim_group_members_member", table_name="dlp_scim_group_members"
    )
    op.drop_table("dlp_scim_group_members")
    op.drop_index("uq_dlp_scim_groups_external", table_name="dlp_scim_groups")
    op.drop_index("uq_dlp_scim_groups_name_ci", table_name="dlp_scim_groups")
    op.drop_index("ix_dlp_scim_groups_org", table_name="dlp_scim_groups")
    op.drop_table("dlp_scim_groups")
    op.drop_index("uq_dlp_scim_users_external", table_name="dlp_scim_users")
    op.drop_index("uq_dlp_scim_users_username_ci", table_name="dlp_scim_users")
    op.drop_index("ix_dlp_scim_users_org", table_name="dlp_scim_users")
    op.drop_table("dlp_scim_users")
    op.drop_index("ix_dlp_scim_credentials_org", table_name="dlp_scim_credentials")
    op.drop_table("dlp_scim_credentials")
    op.drop_column("members", "active")
