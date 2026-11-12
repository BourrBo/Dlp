"""Add tenant-scoped P06 exceptions, suppressions and immutable policy versions."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0006_exceptions_versions"
down_revision: str | None = "0005_policy_engine_core"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("P06 migration requires PostgreSQL with Supabase auth.jwt() support")

    op.create_unique_constraint("uq_dlp_policies_id_org", "dlp_policies", ["id", "org_id"])
    op.create_unique_constraint("uq_members_id_org", "members", ["id", "organization_id"])

    op.create_table(
        "dlp_policy_versions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "policy_id",
            sa.String(36),
            nullable=False,
        ),
        sa.Column(
            "org_id",
            sa.String(36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("snapshot", JSONB(), nullable=False),
        sa.Column(
            "created_by",
            sa.String(36),
            nullable=False,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint("policy_id", "version", name="uq_dlp_policy_versions_policy_version"),
        sa.CheckConstraint("version >= 1", name="ck_dlp_policy_versions_version"),
        sa.CheckConstraint(
            "jsonb_typeof(snapshot) = 'object'", name="ck_dlp_policy_versions_snapshot"
        ),
        sa.ForeignKeyConstraint(
            ["policy_id", "org_id"],
            ["dlp_policies.id", "dlp_policies.org_id"],
            ondelete="RESTRICT",
            name="fk_dlp_policy_versions_policy_tenant",
        ),
        sa.ForeignKeyConstraint(
            ["created_by", "org_id"],
            ["members.id", "members.organization_id"],
            ondelete="RESTRICT",
            name="fk_dlp_policy_versions_creator_tenant",
        ),
    )
    op.create_index("ix_dlp_policy_versions_org", "dlp_policy_versions", ["org_id"])
    op.create_index(
        "ix_dlp_policy_versions_policy_version",
        "dlp_policy_versions",
        ["org_id", "policy_id", "version"],
    )

    # Preserve every policy's current P05 state as the initial immutable version.
    op.execute(
        text("""
        INSERT INTO dlp_policy_versions
            (id, policy_id, org_id, version, snapshot, created_by, created_at)
        SELECT
            gen_random_uuid()::text,
            id,
            org_id,
            version,
            jsonb_build_object(
                'policy_id', id,
                'organization_id', org_id,
                'name', name,
                'enabled', enabled,
                'priority', priority,
                'conditions', conditions,
                'action', action,
                'version', version
            ),
            created_by,
            updated_at
        FROM dlp_policies
    """)
    )

    op.execute(
        text("""
        CREATE FUNCTION reject_dlp_policy_version_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'policy versions are immutable';
        END;
        $$
    """)
    )
    op.execute(
        text("""
        CREATE TRIGGER dlp_policy_versions_immutable
        BEFORE UPDATE OR DELETE ON dlp_policy_versions
        FOR EACH ROW EXECUTE FUNCTION reject_dlp_policy_version_mutation()
    """)
    )

    op.create_table(
        "dlp_exceptions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "policy_id",
            sa.String(36),
            nullable=False,
        ),
        sa.Column("scope", JSONB(), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column(
            "approver_id",
            sa.String(36),
            nullable=False,
        ),
        sa.Column(
            "created_by",
            sa.String(36),
            nullable=False,
        ),
        sa.Column(
            "updated_by",
            sa.String(36),
            nullable=False,
        ),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "jsonb_typeof(scope) = 'object' AND scope <> '{}'::jsonb",
            name="ck_dlp_exceptions_scope_object",
        ),
        sa.ForeignKeyConstraint(
            ["policy_id", "org_id"],
            ["dlp_policies.id", "dlp_policies.org_id"],
            ondelete="RESTRICT",
            name="fk_dlp_exceptions_policy_tenant",
        ),
        sa.ForeignKeyConstraint(
            ["approver_id", "org_id"],
            ["members.id", "members.organization_id"],
            ondelete="RESTRICT",
            name="fk_dlp_exceptions_approver_tenant",
        ),
        sa.ForeignKeyConstraint(
            ["created_by", "org_id"],
            ["members.id", "members.organization_id"],
            ondelete="RESTRICT",
            name="fk_dlp_exceptions_creator_tenant",
        ),
        sa.ForeignKeyConstraint(
            ["updated_by", "org_id"],
            ["members.id", "members.organization_id"],
            ondelete="RESTRICT",
            name="fk_dlp_exceptions_updater_tenant",
        ),
    )
    op.create_index("ix_dlp_exceptions_org", "dlp_exceptions", ["org_id"])
    op.create_index("ix_dlp_exceptions_expires", "dlp_exceptions", ["org_id", "expires_at"])
    op.create_index("ix_dlp_exceptions_policy", "dlp_exceptions", ["org_id", "policy_id"])

    op.create_table(
        "dlp_suppressions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("match", JSONB(), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column(
            "created_by",
            sa.String(36),
            nullable=False,
        ),
        sa.Column(
            "updated_by",
            sa.String(36),
            nullable=False,
        ),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.CheckConstraint(
            "jsonb_typeof(match) = 'object'", name="ck_dlp_suppressions_match_object"
        ),
        sa.CheckConstraint(
            "match - ARRAY['fingerprint','path','pattern'] = '{}'::jsonb "
            "AND (CASE WHEN match ? 'fingerprint' THEN 1 ELSE 0 END + "
            "CASE WHEN match ? 'path' THEN 1 ELSE 0 END + "
            "CASE WHEN match ? 'pattern' THEN 1 ELSE 0 END) = 1",
            name="ck_dlp_suppressions_match_key",
        ),
        sa.ForeignKeyConstraint(
            ["created_by", "org_id"],
            ["members.id", "members.organization_id"],
            ondelete="RESTRICT",
            name="fk_dlp_suppressions_creator_tenant",
        ),
        sa.ForeignKeyConstraint(
            ["updated_by", "org_id"],
            ["members.id", "members.organization_id"],
            ondelete="RESTRICT",
            name="fk_dlp_suppressions_updater_tenant",
        ),
    )
    op.create_index("ix_dlp_suppressions_org", "dlp_suppressions", ["org_id"])
    op.create_index("ix_dlp_suppressions_expires", "dlp_suppressions", ["org_id", "expires_at"])

    for table in ("dlp_policy_versions", "dlp_exceptions", "dlp_suppressions"):
        op.execute(text(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'))
        op.execute(text(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY'))
        if table == "dlp_policy_versions":
            op.execute(text(f'GRANT SELECT, INSERT ON TABLE "{table}" TO authenticated'))
            op.execute(
                text(f"""
                CREATE POLICY tenant_{table}_select ON {table} FOR SELECT TO authenticated
                USING (org_id = (auth.jwt() ->> 'org_id'))
            """)
            )
            op.execute(
                text(f"""
                CREATE POLICY tenant_{table}_insert ON {table} FOR INSERT TO authenticated
                WITH CHECK (org_id = (auth.jwt() ->> 'org_id')
                    AND (auth.jwt() ->> 'app_role') IN ('owner', 'admin'))
            """)
            )
            continue
        op.execute(
            text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "{table}" TO authenticated')
        )
        predicate = "org_id = (auth.jwt() ->> 'org_id')"
        admin_predicate = predicate + " AND (auth.jwt() ->> 'app_role') IN ('owner', 'admin')"
        op.execute(
            text(f"""
            CREATE POLICY tenant_{table}_select ON {table} FOR SELECT TO authenticated
            USING ({predicate})
        """)
        )
        op.execute(
            text(f"""
            CREATE POLICY tenant_{table}_insert ON {table} FOR INSERT TO authenticated
            WITH CHECK ({admin_predicate})
        """)
        )
        op.execute(
            text(f"""
            CREATE POLICY tenant_{table}_update ON {table} FOR UPDATE TO authenticated
            USING ({admin_predicate}) WITH CHECK ({admin_predicate})
        """)
        )
        op.execute(
            text(f"""
            CREATE POLICY tenant_{table}_delete ON {table} FOR DELETE TO authenticated
            USING ({admin_predicate})
        """)
        )


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("P06 migration downgrade requires PostgreSQL")
    for table in ("dlp_suppressions", "dlp_exceptions", "dlp_policy_versions"):
        op.execute(text(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY'))
        op.execute(text(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY'))
        op.drop_table(table)
    op.execute(text("DROP FUNCTION reject_dlp_policy_version_mutation()"))
    op.drop_constraint("uq_members_id_org", "members", type_="unique")
    op.drop_constraint("uq_dlp_policies_id_org", "dlp_policies", type_="unique")
