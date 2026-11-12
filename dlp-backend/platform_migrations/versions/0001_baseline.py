"""Create the greenfield organizational baseline."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_baseline"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("settings_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_table(
        "members",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.String(36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("auth_subject_id", sa.String(256), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint(
            "organization_id", "auth_subject_id", name="uq_members_org_auth_subject"
        ),
    )
    op.create_index("ix_members_organization_id", "members", ["organization_id"])
    op.create_table(
        "channels",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.String(36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("channel_type", sa.String(64), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint(
            "organization_id", "channel_type", "name", name="uq_channels_org_type_name"
        ),
    )
    op.create_index("ix_channels_organization_id", "channels", ["organization_id"])
    op.create_table(
        "events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.String(36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("request_id", sa.String(36), nullable=False),
        sa.Column("scan_id", sa.String(36), nullable=False),
        sa.Column("channel", sa.String(64), nullable=False),
        sa.Column("destination", sa.String(2048), nullable=True),
        sa.Column("decision", sa.String(32), nullable=False),
        sa.Column("reason", sa.String(2048), nullable=False),
        sa.Column("finding_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "occurred_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint("organization_id", "request_id", name="uq_events_org_request"),
        sa.CheckConstraint("finding_count >= 0", name="ck_events_finding_count_nonnegative"),
    )
    op.create_index("ix_events_organization_id", "events", ["organization_id"])
    op.create_index("ix_events_org_occurred_at", "events", ["organization_id", "occurred_at"])


def downgrade() -> None:
    op.drop_index("ix_events_org_occurred_at", table_name="events")
    op.drop_index("ix_events_organization_id", table_name="events")
    op.drop_table("events")
    op.drop_index("ix_channels_organization_id", table_name="channels")
    op.drop_table("channels")
    op.drop_index("ix_members_organization_id", table_name="members")
    op.drop_table("members")
    op.drop_table("organizations")
