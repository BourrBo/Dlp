"""Add tenant-scoped policy and destination storage for P05."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0005_policy_engine_core"
down_revision: str | None = "0004_scan_idempotency"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        raise RuntimeError("P05 migration requires PostgreSQL with Supabase auth.jwt() support")
    op.create_table(
        "dlp_policies",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("conditions", JSONB(), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "created_by",
            sa.String(36),
            sa.ForeignKey("members.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint("priority >= 0", name="ck_dlp_policies_priority"),
        sa.CheckConstraint("version >= 1", name="ck_dlp_policies_version"),
        sa.CheckConstraint(
            "action IN ('allow', 'warn', 'block', 'log')", name="ck_dlp_policies_action"
        ),
        sa.CheckConstraint(
            "jsonb_typeof(conditions) = 'object'", name="ck_dlp_policies_conditions_object"
        ),
    )
    op.create_index("ix_dlp_policies_org_id", "dlp_policies", ["org_id"])
    op.create_index("ix_dlp_policies_org_priority", "dlp_policies", ["org_id", "priority"])
    op.create_table(
        "dlp_destinations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("class", sa.String(32), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("pattern", sa.String(255), nullable=False),
        sa.UniqueConstraint(
            "org_id", "kind", "pattern", name="uq_dlp_destinations_org_kind_pattern"
        ),
        sa.CheckConstraint(
            "class IN ('internal', 'public', 'personal', 'partner')",
            name="ck_dlp_destinations_class",
        ),
        sa.CheckConstraint(
            "kind IN ('domain', 'repo', 'email_domain')", name="ck_dlp_destinations_kind"
        ),
    )
    op.create_index("ix_dlp_destinations_org_id", "dlp_destinations", ["org_id"])
    for table in ("dlp_policies", "dlp_destinations"):
        op.execute(text(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'))
        op.execute(text(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY'))
        op.execute(
            text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "{table}" TO authenticated')
        )
        op.execute(
            f"""
            CREATE POLICY tenant_{table}_select ON {table} FOR SELECT TO authenticated
            USING (org_id = (auth.jwt() ->> 'org_id'))
            """
        )
        predicate = (
            "org_id = (auth.jwt() ->> 'org_id') "
            "AND (auth.jwt() ->> 'app_role') IN ('owner', 'admin')"
        )
        op.execute(
            f"CREATE POLICY tenant_{table}_insert ON {table} "
            f"FOR INSERT TO authenticated WITH CHECK ({predicate})"
        )
        op.execute(
            f"CREATE POLICY tenant_{table}_update ON {table} "
            f"FOR UPDATE TO authenticated USING ({predicate}) WITH CHECK ({predicate})"
        )
        op.execute(
            f"CREATE POLICY tenant_{table}_delete ON {table} "
            f"FOR DELETE TO authenticated USING ({predicate})"
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        raise RuntimeError("P05 migration downgrade requires PostgreSQL")
    for table in ("dlp_destinations", "dlp_policies"):
        op.execute(text(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY'))
        op.execute(text(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY'))
        op.drop_table(table)
