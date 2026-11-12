"""Create tenant-isolated append-only P10 audit events."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0009_audit_log"
down_revision: str | None = "0008_secret_vault"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError(
            "P10 audit migration requires PostgreSQL with Supabase auth.jwt() support"
        )
    op.create_table(
        "audit_events",
        sa.Column("event_id", sa.String(36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.String(36),
            sa.ForeignKey("organizations.id"),
            nullable=False,
        ),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_id", sa.String(256), nullable=False),
        sa.Column("actor_type", sa.String(32), nullable=False),
        sa.Column("auth_method", sa.String(32), nullable=False),
        sa.Column("actor_role", sa.String(32), nullable=False),
        sa.Column("action", sa.String(80), nullable=False),
        sa.Column("resource_type", sa.String(64), nullable=False),
        sa.Column("resource_id", sa.String(256), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("correlation_id", sa.String(36), nullable=True),
        sa.Column("source_ip", sa.String(64), nullable=True),
        sa.Column("user_agent", sa.String(512), nullable=True),
        sa.Column("event_metadata", sa.JSON().with_variant(JSONB(), "postgresql"), nullable=False),
        sa.Column("sequence_number", sa.BigInteger(), nullable=False),
        sa.Column("previous_hash", sa.String(64), nullable=False),
        sa.Column("event_hash", sa.String(64), nullable=False),
        sa.UniqueConstraint(
            "organization_id", "sequence_number", name="uq_audit_events_org_sequence"
        ),
        sa.CheckConstraint("sequence_number >= 1", name="ck_audit_events_sequence_positive"),
        sa.CheckConstraint(
            "outcome IN ('success','failure','denied')", name="ck_audit_events_outcome"
        ),
        sa.CheckConstraint("actor_type IN ('user','service')", name="ck_audit_events_actor_type"),
        sa.CheckConstraint(
            "auth_method IN ('jwt','api_key','sso','internal')",
            name="ck_audit_events_auth_method",
        ),
        sa.CheckConstraint(
            "actor_role IN ('owner','admin','analyst','viewer','auditor')",
            name="ck_audit_events_actor_role",
        ),
        sa.CheckConstraint(
            "action IN ('auth.authorization_denied','auth.api_key_created','auth.api_key_revoked',"
            "'policy.created','policy.updated','policy.deleted','policy.rolled_back',"
            "'exception.created','exception.updated','exception.deleted',"
            "'suppression.created','suppression.updated','suppression.deleted',"
            "'destination.created','destination.updated','destination.deleted',"
            "'approval.requested','approval.approved','approval.rejected','approval.cancelled',"
            "'approval.expired','action.requested','action.executed','secret.created',"
            "'secret.updated','secret.deleted','secret.rotated')",
            name="ck_audit_events_action",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(event_metadata) = 'object' AND "
            "octet_length(event_metadata::text) <= 8192",
            name="ck_audit_events_metadata_object_size",
        ),
        sa.CheckConstraint(
            "length(previous_hash) = 64", name="ck_audit_events_previous_hash_length"
        ),
        sa.CheckConstraint("length(event_hash) = 64", name="ck_audit_events_hash_length"),
    )
    op.create_index(
        "ix_audit_events_org_occurred",
        "audit_events",
        ["organization_id", "occurred_at", "event_id"],
    )
    op.create_index(
        "ix_audit_events_org_action_time",
        "audit_events",
        ["organization_id", "action", "occurred_at"],
    )
    op.create_index(
        "ix_audit_events_org_actor_time",
        "audit_events",
        ["organization_id", "actor_id", "occurred_at"],
    )
    op.create_index(
        "ix_audit_events_org_resource_time",
        "audit_events",
        ["organization_id", "resource_type", "resource_id", "occurred_at"],
    )
    op.create_index(
        "ix_audit_events_org_correlation",
        "audit_events",
        ["organization_id", "correlation_id"],
    )
    op.execute(sa.text("ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE audit_events FORCE ROW LEVEL SECURITY"))
    op.execute(sa.text("GRANT SELECT, INSERT ON audit_events TO authenticated"))
    op.execute(sa.text("REVOKE UPDATE, DELETE ON audit_events FROM authenticated"))
    tenant = "organization_id = (auth.jwt() ->> 'org_id')"
    op.execute(
        sa.text(
            f"CREATE POLICY tenant_audit_events_select ON audit_events "
            f"FOR SELECT TO authenticated USING ({tenant})"
        )
    )
    op.execute(
        sa.text(
            f"CREATE POLICY tenant_audit_events_insert ON audit_events "
            f"FOR INSERT TO authenticated WITH CHECK ({tenant})"
        )
    )
    op.execute(
        sa.text(
            "CREATE FUNCTION reject_audit_event_mutation() RETURNS trigger "
            "LANGUAGE plpgsql AS $$ BEGIN "
            "RAISE EXCEPTION 'audit events are append-only'; END; $$"
        )
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER audit_events_immutable BEFORE UPDATE OR DELETE ON audit_events "
            "FOR EACH ROW EXECUTE FUNCTION reject_audit_event_mutation()"
        )
    )


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("P10 audit migration downgrade requires PostgreSQL")
    op.execute(sa.text("DROP TRIGGER audit_events_immutable ON audit_events"))
    op.drop_table("audit_events")
    op.execute(sa.text("DROP FUNCTION reject_audit_event_mutation()"))
