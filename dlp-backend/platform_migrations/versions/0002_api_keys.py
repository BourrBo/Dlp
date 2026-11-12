"""Create organization-scoped API keys for P2 authentication."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_api_keys"
down_revision: str | None = "0001_baseline"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "dlp_api_keys",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("prefix", sa.String(12), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False),
        sa.Column(
            "created_by",
            sa.String(36),
            sa.ForeignKey("members.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_dlp_api_keys_prefix", "dlp_api_keys", ["prefix"], unique=True)
    op.create_index("ix_dlp_api_keys_org_id", "dlp_api_keys", ["org_id"])


def downgrade() -> None:
    op.drop_index("ix_dlp_api_keys_org_id", table_name="dlp_api_keys")
    op.drop_index("ix_dlp_api_keys_prefix", table_name="dlp_api_keys")
    op.drop_table("dlp_api_keys")
