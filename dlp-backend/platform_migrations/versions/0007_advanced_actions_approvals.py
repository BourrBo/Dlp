"""Add tenant-scoped P07 actions and approval workflows."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0007_advanced_actions_approvals"
down_revision: str | None = "0006_exceptions_versions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("P07 migration requires PostgreSQL with Supabase auth.jwt() support")

    op.drop_constraint("ck_dlp_policies_action", "dlp_policies", type_="check")
    op.create_check_constraint(
        "ck_dlp_policies_action",
        "dlp_policies",
        "action IN ('allow','warn','block','log','redact','quarantine',"
        "'revoke_share','require_approval')",
    )

    op.create_table(
        "dlp_actions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("request_id", sa.String(36), nullable=False),
        sa.Column("policy_id", sa.String(36), nullable=True),
        sa.Column("policy_version", sa.Integer(), nullable=True),
        sa.Column("requested_by", sa.String(36), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("justification", sa.String(1000), nullable=False),
        sa.Column("metadata", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["requested_by", "org_id"],
            ["members.id", "members.organization_id"],
            ondelete="RESTRICT",
            name="fk_dlp_actions_requester_tenant",
        ),
        sa.ForeignKeyConstraint(
            ["policy_id", "org_id"],
            ["dlp_policies.id", "dlp_policies.org_id"],
            ondelete="RESTRICT",
            name="fk_dlp_actions_policy_tenant",
        ),
        sa.UniqueConstraint("org_id", "request_id", "action", name="uq_dlp_actions_idempotency"),
        sa.UniqueConstraint("id", "org_id", name="uq_dlp_actions_id_org"),
        sa.CheckConstraint(
            "action IN ('redact','quarantine','revoke_share','require_approval','user_override')",
            name="ck_dlp_actions_action",
        ),
        sa.CheckConstraint(
            "status IN ('pending_approval','approved','rejected','pending_executor',"
            "'executing','succeeded','failed','cancelled','expired')",
            name="ck_dlp_actions_status",
        ),
        sa.CheckConstraint(
            "metadata IS NOT NULL AND jsonb_typeof(metadata) = 'object'",
            name="ck_dlp_actions_metadata_object",
        ),
        sa.CheckConstraint(
            "policy_version IS NULL OR policy_version >= 1", name="ck_dlp_actions_policy_version"
        ),
    )
    op.create_index("ix_dlp_actions_org_created", "dlp_actions", ["org_id", "created_at"])
    op.create_index("ix_dlp_actions_org_status", "dlp_actions", ["org_id", "status"])

    op.create_table(
        "dlp_approvals",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("action_id", sa.String(36), nullable=False),
        sa.Column("requested_by", sa.String(36), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("justification", sa.String(1000), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_by", sa.String(36), nullable=True),
        sa.Column("decision_reason", sa.String(1000), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("escalated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["action_id", "org_id"],
            ["dlp_actions.id", "dlp_actions.org_id"],
            ondelete="CASCADE",
            name="fk_dlp_approvals_action_tenant",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by", "org_id"],
            ["members.id", "members.organization_id"],
            ondelete="RESTRICT",
            name="fk_dlp_approvals_requester_tenant",
        ),
        sa.ForeignKeyConstraint(
            ["decided_by", "org_id"],
            ["members.id", "members.organization_id"],
            ondelete="RESTRICT",
            name="fk_dlp_approvals_decider_tenant",
        ),
        sa.UniqueConstraint("action_id", name="uq_dlp_approvals_action"),
        sa.CheckConstraint(
            "status IN ('pending','approved','rejected','expired','escalated','cancelled')",
            name="ck_dlp_approvals_status",
        ),
        sa.CheckConstraint(
            "length(btrim(justification)) > 0", name="ck_dlp_approvals_justification"
        ),
    )
    op.create_index(
        "ix_dlp_approvals_org_status_created", "dlp_approvals", ["org_id", "status", "created_at"]
    )

    for table in ("dlp_actions", "dlp_approvals"):
        op.execute(text(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'))
        op.execute(text(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY'))
        op.execute(text(f'GRANT SELECT, INSERT, UPDATE ON TABLE "{table}" TO authenticated'))
        tenant = "org_id = (auth.jwt() ->> 'org_id')"
        op.execute(
            text(
                f"CREATE POLICY tenant_{table}_select ON {table} FOR SELECT TO authenticated "
                f"USING ({tenant})"
            )
        )
        op.execute(
            text(
                f"CREATE POLICY tenant_{table}_insert ON {table} FOR INSERT TO authenticated "
                f"WITH CHECK ({tenant})"
            )
        )
        op.execute(
            text(
                f"CREATE POLICY tenant_{table}_update ON {table} FOR UPDATE TO authenticated "
                f"USING ({tenant}) WITH CHECK ({tenant})"
            )
        )


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("P07 migration downgrade requires PostgreSQL")
    advanced = (
        op.get_bind()
        .execute(
            text(
                "SELECT count(*) FROM dlp_policies WHERE action IN "
                "('redact','quarantine','revoke_share','require_approval')"
            )
        )
        .scalar_one()
    )
    if advanced:
        raise RuntimeError("Cannot downgrade P07 while advanced-action policies exist")
    for table in ("dlp_approvals", "dlp_actions"):
        op.execute(text(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY'))
        op.execute(text(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY'))
        op.drop_table(table)
    op.drop_constraint("ck_dlp_policies_action", "dlp_policies", type_="check")
    op.create_check_constraint(
        "ck_dlp_policies_action",
        "dlp_policies",
        "action IN ('allow', 'warn', 'block', 'log')",
    )
