"""Add tenant-scoped retention, legal holds, and deletion workflow state."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013_data_lifecycle"
down_revision: str | None = "0012_identity_management"
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
    "'identity.ip_allowlist_blocked'"
)
_P14_ACTIONS = (
    "'retention.policy_updated','retention.batch_completed','retention.batch_failed',"
    "'legal_hold.created','legal_hold.released','organization.deletion_requested',"
    "'organization.deletion_confirmed','organization.deletion_started',"
    "'organization.deletion_blocked','organization.deletion_failed',"
    "'organization.deletion_completed','subject.export_requested','subject.export_completed',"
    "'subject.export_failed'"
)
_CATEGORIES = "'sessions','scan_records','sso_ephemera','revoked_credentials'"


def _set_audit_actions(actions: str) -> None:
    op.drop_constraint("ck_audit_events_action", "audit_events", type_="check")
    op.create_check_constraint("ck_audit_events_action", "audit_events", f"action IN ({actions})")


def _secure_tenant_table(table: str, *, writable: bool) -> None:
    op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
    privileges = "SELECT, INSERT, UPDATE" if writable else "SELECT"
    op.execute(sa.text(f"GRANT {privileges} ON {table} TO authenticated"))
    op.execute(
        sa.text(
            f"CREATE POLICY tenant_{table}_lifecycle_admin ON {table} "
            "FOR ALL TO authenticated USING (org_id = (auth.jwt() ->> 'org_id') "
            "AND (auth.jwt() ->> 'app_role') IN ('owner','admin')) "
            "WITH CHECK (org_id = (auth.jwt() ->> 'org_id') "
            "AND (auth.jwt() ->> 'app_role') IN ('owner','admin'))"
        )
    )


def _allow_lifecycle_policy_version_cleanup(enabled: bool) -> None:
    """Permit only the P14 transaction-scoped tenant purge through P06's immutable trigger."""
    if enabled:
        function_body = """
        BEGIN
            IF TG_OP = 'DELETE'
               AND current_setting('app.p14_lifecycle_cleanup', true) = 'on' THEN
                RETURN OLD;
            END IF;
            RAISE EXCEPTION 'policy versions are immutable';
        END;
        """
    else:
        function_body = """
        BEGIN
            RAISE EXCEPTION 'policy versions are immutable';
        END;
        """
    op.execute(
        sa.text(
            "CREATE OR REPLACE FUNCTION reject_dlp_policy_version_mutation() "
            "RETURNS trigger LANGUAGE plpgsql AS $$" + function_body + "$$"
        )
    )


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("P14 lifecycle migration requires PostgreSQL RLS")

    for table, columns, constraints in (
        (
            "dlp_retention_policies",
            [
                sa.Column("org_id", sa.String(36), nullable=False),
                sa.Column("category", sa.String(32), nullable=False),
                sa.Column("retention_days", sa.Integer(), nullable=False),
                sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
                sa.Column("effective_at", sa.DateTime(timezone=True), nullable=False),
                sa.Column("updated_by", sa.String(36), nullable=False),
                sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
                sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            ],
            [
                sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="RESTRICT"),
                sa.ForeignKeyConstraint(
                    ["updated_by", "org_id"],
                    ["members.id", "members.organization_id"],
                    ondelete="RESTRICT",
                ),
                sa.PrimaryKeyConstraint("org_id", "category"),
                sa.CheckConstraint(
                    f"category IN ({_CATEGORIES})", name="ck_dlp_retention_policies_category"
                ),
                sa.CheckConstraint(
                    "retention_days BETWEEN 1 AND 3650",
                    name="ck_dlp_retention_policies_days",
                ),
            ],
        ),
        (
            "dlp_legal_holds",
            [
                sa.Column("id", sa.String(36), primary_key=True),
                sa.Column("org_id", sa.String(36), nullable=False),
                sa.Column("name", sa.String(120), nullable=False),
                sa.Column("reason", sa.String(1000), nullable=False),
                sa.Column("scope_category", sa.String(32), nullable=True),
                sa.Column("status", sa.String(16), nullable=False, server_default="active"),
                sa.Column("created_by_member_id", sa.String(36), nullable=False),
                sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
                sa.Column("released_by_member_id", sa.String(36), nullable=True),
                sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
                sa.Column("release_reason", sa.String(1000), nullable=True),
            ],
            [
                sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="RESTRICT"),
                sa.CheckConstraint(
                    f"scope_category IS NULL OR scope_category IN ({_CATEGORIES})",
                    name="ck_dlp_legal_holds_scope",
                ),
                sa.CheckConstraint(
                    "status IN ('active','released')", name="ck_dlp_legal_holds_status"
                ),
                sa.CheckConstraint(
                    "length(btrim(name)) BETWEEN 1 AND 120",
                    name="ck_dlp_legal_holds_name",
                ),
                sa.CheckConstraint(
                    "length(btrim(reason)) BETWEEN 1 AND 1000",
                    name="ck_dlp_legal_holds_reason",
                ),
                sa.CheckConstraint(
                    "(status = 'active' AND released_at IS NULL "
                    "AND released_by_member_id IS NULL) OR "
                    "(status = 'released' AND released_at IS NOT NULL "
                    "AND released_by_member_id IS NOT NULL)",
                    name="ck_dlp_legal_holds_release_state",
                ),
            ],
        ),
        (
            "dlp_org_deletion_requests",
            [
                sa.Column("org_id", sa.String(36), primary_key=True),
                sa.Column("status", sa.String(32), nullable=False),
                sa.Column("requested_by_member_id", sa.String(36), nullable=False),
                sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
                sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
                sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
                sa.Column("current_table", sa.String(64), nullable=True),
                sa.Column("failure_code", sa.String(64), nullable=True),
                sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            ],
            [
                sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="RESTRICT"),
                sa.CheckConstraint(
                    "status IN ('requested','blocked_by_legal_hold','in_progress',"
                    "'failed','completed')",
                    name="ck_dlp_org_deletion_status",
                ),
            ],
        ),
        (
            "dlp_retention_runs",
            [
                sa.Column("id", sa.String(36), primary_key=True),
                sa.Column("org_id", sa.String(36), nullable=False),
                sa.Column("category", sa.String(32), nullable=False),
                sa.Column("status", sa.String(16), nullable=False),
                sa.Column("deleted_count", sa.Integer(), nullable=False, server_default="0"),
                sa.Column("failure_code", sa.String(64), nullable=True),
                sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
                sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            ],
            [
                sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="RESTRICT"),
                sa.CheckConstraint(
                    f"category IN ({_CATEGORIES})", name="ck_dlp_retention_runs_category"
                ),
                sa.CheckConstraint(
                    "status IN ('running','completed','failed')",
                    name="ck_dlp_retention_runs_status",
                ),
                sa.CheckConstraint("deleted_count >= 0", name="ck_dlp_retention_runs_count"),
            ],
        ),
    ):
        op.create_table(table, *columns, *constraints)

    op.create_index("ix_dlp_legal_holds_org_status", "dlp_legal_holds", ["org_id", "status"])
    op.create_index(
        "ix_dlp_retention_runs_org_started", "dlp_retention_runs", ["org_id", "started_at"]
    )
    for table in (
        "dlp_retention_policies",
        "dlp_legal_holds",
        "dlp_org_deletion_requests",
        "dlp_retention_runs",
    ):
        _secure_tenant_table(table, writable=table != "dlp_org_deletion_requests")
    _allow_lifecycle_policy_version_cleanup(True)
    _set_audit_actions(f"{_ACTIONS},{_P14_ACTIONS}")


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("P14 lifecycle migration downgrade requires PostgreSQL RLS")
    # The P10 audit table is append-only; keep P14 event names accepted after rollback.
    _allow_lifecycle_policy_version_cleanup(False)
    _set_audit_actions(f"{_ACTIONS},{_P14_ACTIONS}")
    op.drop_index("ix_dlp_retention_runs_org_started", table_name="dlp_retention_runs")
    op.drop_index("ix_dlp_legal_holds_org_status", table_name="dlp_legal_holds")
    op.drop_table("dlp_retention_runs")
    op.drop_table("dlp_org_deletion_requests")
    op.drop_table("dlp_legal_holds")
    op.drop_table("dlp_retention_policies")
