"""Enable Supabase JWT-backed row-level tenant isolation."""

from collections.abc import Sequence

from alembic import op
from sqlalchemy import text

revision: str = "0003_tenant_rls"
down_revision: str | None = "0002_api_keys"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLES = ("organizations", "members", "channels", "events", "dlp_api_keys")


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        raise RuntimeError("P03 migration requires PostgreSQL with Supabase auth.jwt() support")
    for table in TABLES:
        op.execute(text(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'))
        op.execute(text(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY'))

    # Missing claims evaluate to NULL and therefore deny all rows. These policies
    # intentionally grant reads only; mutations remain in trusted backend flows.
    op.execute("""
        CREATE POLICY tenant_organizations_select ON organizations FOR SELECT TO authenticated
        USING (id = (auth.jwt() ->> 'org_id'))
    """)
    for table in ("members", "channels", "events"):
        op.execute(f"""
            CREATE POLICY tenant_{table}_select ON {table} FOR SELECT TO authenticated
            USING (organization_id = (auth.jwt() ->> 'org_id'))
        """)
    op.execute("""
        CREATE POLICY tenant_api_keys_select ON dlp_api_keys FOR SELECT TO authenticated
        USING (org_id = (auth.jwt() ->> 'org_id')
            AND (auth.jwt() ->> 'app_role') IN ('owner', 'admin'))
    """)
    op.execute("""
        CREATE POLICY tenant_api_keys_insert ON dlp_api_keys FOR INSERT TO authenticated
        WITH CHECK (org_id = (auth.jwt() ->> 'org_id')
            AND (auth.jwt() ->> 'app_role') IN ('owner', 'admin'))
    """)
    op.execute("""
        CREATE POLICY tenant_api_keys_update ON dlp_api_keys FOR UPDATE TO authenticated
        USING (org_id = (auth.jwt() ->> 'org_id')
            AND (auth.jwt() ->> 'app_role') IN ('owner', 'admin'))
        WITH CHECK (org_id = (auth.jwt() ->> 'org_id')
            AND (auth.jwt() ->> 'app_role') IN ('owner', 'admin'))
    """)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        raise RuntimeError("P03 migration downgrade requires PostgreSQL")
    for table, policy in (
        ("dlp_api_keys", "tenant_api_keys_select"),
        ("dlp_api_keys", "tenant_api_keys_insert"),
        ("dlp_api_keys", "tenant_api_keys_update"),
        ("events", "tenant_events_select"),
        ("channels", "tenant_channels_select"),
        ("members", "tenant_members_select"),
        ("organizations", "tenant_organizations_select"),
    ):
        op.execute(f'DROP POLICY "{policy}" ON "{table}"')
        op.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')
