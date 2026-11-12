"""Persist tenant-scoped scan idempotency results and decisions."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0004_scan_idempotency"
down_revision: str | None = "0003_tenant_rls"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        raise RuntimeError("P04 migration requires PostgreSQL with Supabase auth.jwt() support")
    op.create_table(
        "dlp_scan_idempotency",
        sa.Column(
            "organization_id",
            sa.String(36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("request_id", sa.String(36), primary_key=True),
        sa.Column("input_hash", sa.String(64), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("result_json", sa.JSON().with_variant(JSONB(), "postgresql")),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint("state IN ('processing', 'complete')", name="ck_scan_idempotency_state"),
        sa.CheckConstraint(
            "(state = 'processing' AND result_json IS NULL) OR "
            "(state = 'complete' AND result_json IS NOT NULL)",
            name="ck_scan_idempotency_result_state",
        ),
    )
    op.create_index(
        "ix_scan_idempotency_org_created",
        "dlp_scan_idempotency",
        ["organization_id", "created_at"],
    )
    op.execute(text("ALTER TABLE dlp_scan_idempotency ENABLE ROW LEVEL SECURITY"))
    op.execute(text("ALTER TABLE dlp_scan_idempotency FORCE ROW LEVEL SECURITY"))
    op.execute(
        """
        CREATE POLICY tenant_scan_idempotency_select ON dlp_scan_idempotency
        FOR SELECT TO authenticated
        USING (organization_id = (auth.jwt() ->> 'org_id'))
        """
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        raise RuntimeError("P04 migration downgrade requires PostgreSQL")
    op.execute(text("DROP POLICY tenant_scan_idempotency_select ON dlp_scan_idempotency"))
    op.execute(text("ALTER TABLE dlp_scan_idempotency NO FORCE ROW LEVEL SECURITY"))
    op.execute(text("ALTER TABLE dlp_scan_idempotency DISABLE ROW LEVEL SECURITY"))
    op.drop_index("ix_scan_idempotency_org_created", table_name="dlp_scan_idempotency")
    op.drop_table("dlp_scan_idempotency")
