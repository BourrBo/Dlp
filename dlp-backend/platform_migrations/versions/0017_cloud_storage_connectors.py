"""Add S3 and Google Cloud Storage providers to the P16 connector registry."""

from collections.abc import Sequence

from alembic import op
from sqlalchemy import text

revision: str = "0017_cloud_storage_connectors"
down_revision: str | None = "0016_microsoft_connectors"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PROVIDERS = (
    "'google_drive','microsoft_onedrive','microsoft_sharepoint','aws_s3','google_cloud_storage'"
)
_PREVIOUS_PROVIDERS = "'google_drive','microsoft_onedrive','microsoft_sharepoint'"


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("P18 object storage connectors require PostgreSQL RLS")
    for table, constraint in (
        ("dlp_connectors", "ck_dlp_connectors_provider"),
        ("dlp_connector_state", "ck_dlp_connector_state_provider"),
    ):
        op.drop_constraint(constraint, table, type_="check")
        op.create_check_constraint(constraint, table, f"provider IN ({_PROVIDERS})")


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        raise RuntimeError("P18 object storage downgrade requires PostgreSQL RLS")
    count = (
        op.get_bind()
        .execute(
            text(
                "SELECT count(*) FROM dlp_connectors "
                "WHERE provider IN ('aws_s3','google_cloud_storage')"
            )
        )
        .scalar_one()
    )
    if count:
        raise RuntimeError("Cannot downgrade while S3 or GCS connectors exist")
    for table, constraint in (
        ("dlp_connector_state", "ck_dlp_connector_state_provider"),
        ("dlp_connectors", "ck_dlp_connectors_provider"),
    ):
        op.drop_constraint(constraint, table, type_="check")
        op.create_check_constraint(constraint, table, f"provider IN ({_PREVIOUS_PROVIDERS})")
