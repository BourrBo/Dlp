"""Add encrypted, tenant-scoped P09 secret vault storage."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008_secret_vault"
down_revision: str | None = "0007_advanced_actions_approvals"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("P09 migration requires PostgreSQL with Supabase auth.jwt() support")
    op.create_table(
        "dlp_vault_secrets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("secret_type", sa.String(32), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint("org_id", "name", name="uq_dlp_vault_secrets_org_name"),
        sa.CheckConstraint("key_version >= 1", name="ck_dlp_vault_secrets_key_version"),
        sa.CheckConstraint("octet_length(nonce) = 12", name="ck_dlp_vault_secrets_nonce_length"),
        sa.CheckConstraint(
            "octet_length(ciphertext) >= 16", name="ck_dlp_vault_secrets_ciphertext_length"
        ),
        sa.CheckConstraint(
            "secret_type IN ('oauth_client_secret','access_token','refresh_token',"
            "'api_credential','private_key','generic_secret')",
            name="ck_dlp_vault_secrets_type",
        ),
    )
    op.create_index("ix_dlp_vault_secrets_org", "dlp_vault_secrets", ["org_id"])
    op.create_index("ix_dlp_vault_secrets_org_enabled", "dlp_vault_secrets", ["org_id", "enabled"])
    op.execute(sa.text("ALTER TABLE dlp_vault_secrets ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE dlp_vault_secrets FORCE ROW LEVEL SECURITY"))
    op.execute(
        sa.text("GRANT SELECT, INSERT, UPDATE, DELETE ON dlp_vault_secrets TO authenticated")
    )
    tenant = "org_id = (auth.jwt() ->> 'org_id')"
    op.execute(
        sa.text(
            f"CREATE POLICY tenant_dlp_vault_secrets_select ON dlp_vault_secrets "
            f"FOR SELECT TO authenticated USING ({tenant})"
        )
    )
    op.execute(
        sa.text(
            f"CREATE POLICY tenant_dlp_vault_secrets_insert ON dlp_vault_secrets "
            f"FOR INSERT TO authenticated WITH CHECK ({tenant})"
        )
    )
    op.execute(
        sa.text(
            f"CREATE POLICY tenant_dlp_vault_secrets_update ON dlp_vault_secrets "
            f"FOR UPDATE TO authenticated USING ({tenant}) WITH CHECK ({tenant})"
        )
    )
    op.execute(
        sa.text(
            f"CREATE POLICY tenant_dlp_vault_secrets_delete ON dlp_vault_secrets "
            f"FOR DELETE TO authenticated USING ({tenant})"
        )
    )


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("P09 migration downgrade requires PostgreSQL")
    op.execute(sa.text("ALTER TABLE dlp_vault_secrets NO FORCE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE dlp_vault_secrets DISABLE ROW LEVEL SECURITY"))
    op.drop_table("dlp_vault_secrets")
