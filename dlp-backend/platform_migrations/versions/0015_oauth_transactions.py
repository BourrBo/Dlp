"""Persist short-lived tenant-bound OAuth state (P16)."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0015_oauth_transactions"
down_revision: str | None = "0014_connectors"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("P16 OAuth transaction migration requires PostgreSQL RLS")
    op.create_table(
        "dlp_oauth_transactions",
        sa.Column("state_hash", sa.String(64), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("principal_id", sa.String(256), nullable=False),
        sa.Column("binding_id", sa.String(64), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("member_id", sa.String(36), nullable=False),
        sa.Column("session_id", sa.String(36), nullable=False),
        sa.Column("scopes", sa.JSON().with_variant(JSONB(), "postgresql"), nullable=False),
        sa.Column("auth_method", sa.String(32), nullable=False),
        sa.Column("verifier", sa.String(128), nullable=False),
        sa.Column("redirect_uri", sa.String(2048), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("length(state_hash) = 64", name="ck_dlp_oauth_state_hash"),
        sa.CheckConstraint(
            "provider IN ('google_drive')", name="ck_dlp_oauth_transactions_provider"
        ),
    )
    op.execute(sa.text("ALTER TABLE dlp_oauth_transactions ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE dlp_oauth_transactions FORCE ROW LEVEL SECURITY"))
    op.execute(
        sa.text("GRANT SELECT, INSERT, UPDATE, DELETE ON dlp_oauth_transactions TO authenticated")
    )
    tenant = "org_id = (auth.jwt() ->> 'org_id')"
    op.execute(
        sa.text(
            "CREATE POLICY tenant_dlp_oauth_transactions ON dlp_oauth_transactions "
            f"FOR ALL TO authenticated USING ({tenant}) WITH CHECK ({tenant})"
        )
    )


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("P16 OAuth transaction migration downgrade requires PostgreSQL RLS")
    op.drop_table("dlp_oauth_transactions")
