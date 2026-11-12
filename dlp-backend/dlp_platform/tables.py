"""P2 SQLAlchemy table metadata for API-key runtime queries."""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import CIDR, JSONB

metadata = sa.MetaData()
ORGANIZATIONS = sa.Table(
    "organizations",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("name", sa.String(200), nullable=False),
    sa.Column("settings_json", sa.JSON(), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
)
MEMBERS = sa.Table(
    "members",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
    sa.Column("auth_subject_id", sa.String(256), nullable=False),
    sa.Column("role", sa.String(32), nullable=False),
    sa.Column("email", sa.String(320), nullable=True),
    sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.UniqueConstraint("id", "organization_id", name="uq_members_id_org"),
)

APP_SESSIONS = sa.Table(
    "dlp_app_sessions",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("org_id", sa.String(36), nullable=False),
    sa.Column("member_id", sa.String(36), nullable=False),
    sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
    sa.Column("auth_method", sa.String(16), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("source_ip", sa.String(64), nullable=True),
    sa.Column("user_agent", sa.String(512), nullable=True),
    sa.ForeignKeyConstraint(
        ["member_id", "org_id"],
        ["members.id", "members.organization_id"],
        ondelete="CASCADE",
    ),
)
sa.Index("ix_dlp_app_sessions_org_member", APP_SESSIONS.c.org_id, APP_SESSIONS.c.member_id)

IP_ALLOWLIST_SETTINGS = sa.Table(
    "dlp_ip_allowlist_settings",
    metadata,
    sa.Column(
        "org_id",
        sa.String(36),
        sa.ForeignKey("organizations.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    sa.Column("updated_by", sa.String(36), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(["updated_by", "org_id"], ["members.id", "members.organization_id"]),
)

IP_ALLOWLIST_ENTRIES = sa.Table(
    "dlp_ip_allowlist_entries",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("org_id", sa.String(36), nullable=False),
    sa.Column("network", CIDR().with_variant(sa.String(50), "sqlite"), nullable=False),
    sa.Column("label", sa.String(120), nullable=False),
    sa.Column("created_by", sa.String(36), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(["org_id"], ["dlp_ip_allowlist_settings.org_id"], ondelete="CASCADE"),
    sa.ForeignKeyConstraint(["created_by", "org_id"], ["members.id", "members.organization_id"]),
    sa.UniqueConstraint("org_id", "network", name="uq_dlp_ip_allowlist_network"),
)
sa.Index("ix_dlp_ip_allowlist_entries_org", IP_ALLOWLIST_ENTRIES.c.org_id)

SCIM_CREDENTIALS = sa.Table(
    "dlp_scim_credentials",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column(
        "org_id",
        sa.String(36),
        sa.ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    ),
    sa.Column("name", sa.String(120), nullable=False),
    sa.Column("prefix", sa.String(12), nullable=False, unique=True),
    sa.Column("token_hash", sa.String(64), nullable=False),
    sa.Column("created_by", sa.String(36), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(["created_by", "org_id"], ["members.id", "members.organization_id"]),
    sa.UniqueConstraint("id", "org_id", name="uq_dlp_scim_credentials_id_org"),
)

SCIM_USERS = sa.Table(
    "dlp_scim_users",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("org_id", sa.String(36), nullable=False),
    sa.Column("member_id", sa.String(36), nullable=False),
    sa.Column("external_id", sa.String(512), nullable=True),
    sa.Column("user_name", sa.String(320), nullable=False),
    sa.Column("display_name", sa.String(256), nullable=True),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(
        ["member_id", "org_id"],
        ["members.id", "members.organization_id"],
        ondelete="CASCADE",
    ),
    sa.UniqueConstraint("org_id", "member_id", name="uq_dlp_scim_users_member"),
)
sa.Index(
    "uq_dlp_scim_users_username_ci",
    SCIM_USERS.c.org_id,
    sa.func.lower(SCIM_USERS.c.user_name),
    unique=True,
)
sa.Index(
    "uq_dlp_scim_users_external",
    SCIM_USERS.c.org_id,
    SCIM_USERS.c.external_id,
    unique=True,
    postgresql_where=SCIM_USERS.c.external_id.is_not(None),
    sqlite_where=SCIM_USERS.c.external_id.is_not(None),
)

SCIM_GROUPS = sa.Table(
    "dlp_scim_groups",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column(
        "org_id",
        sa.String(36),
        sa.ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    ),
    sa.Column("external_id", sa.String(512), nullable=True),
    sa.Column("display_name", sa.String(256), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.UniqueConstraint("id", "org_id", name="uq_dlp_scim_groups_id_org"),
)
sa.Index(
    "uq_dlp_scim_groups_name_ci",
    SCIM_GROUPS.c.org_id,
    sa.func.lower(SCIM_GROUPS.c.display_name),
    unique=True,
)
sa.Index(
    "uq_dlp_scim_groups_external",
    SCIM_GROUPS.c.org_id,
    SCIM_GROUPS.c.external_id,
    unique=True,
    postgresql_where=SCIM_GROUPS.c.external_id.is_not(None),
    sqlite_where=SCIM_GROUPS.c.external_id.is_not(None),
)

SCIM_GROUP_MEMBERS = sa.Table(
    "dlp_scim_group_members",
    metadata,
    sa.Column("org_id", sa.String(36), nullable=False),
    sa.Column("group_id", sa.String(36), nullable=False),
    sa.Column("member_id", sa.String(36), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(
        ["group_id", "org_id"],
        ["dlp_scim_groups.id", "dlp_scim_groups.org_id"],
        ondelete="CASCADE",
    ),
    sa.ForeignKeyConstraint(
        ["member_id", "org_id"],
        ["members.id", "members.organization_id"],
        ondelete="CASCADE",
    ),
    sa.PrimaryKeyConstraint("org_id", "group_id", "member_id"),
)

# Shared P16 connector registry. Credentials always live in P09 Vault; connector
# state is limited to bounded, non-secret synchronization checkpoints.
DLP_CONNECTORS = sa.Table(
    "dlp_connectors",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column(
        "org_id",
        sa.String(36),
        sa.ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    ),
    sa.Column("provider", sa.String(32), nullable=False),
    sa.Column("name", sa.String(120), nullable=False),
    sa.Column("status", sa.String(24), nullable=False),
    sa.Column("credential_secret_id", sa.String(36), nullable=True),
    sa.Column("config_json", sa.JSON().with_variant(JSONB(), "postgresql"), nullable=False),
    sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("last_error_code", sa.String(64), nullable=True),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.UniqueConstraint("id", "org_id", name="uq_dlp_connectors_id_org"),
    sa.CheckConstraint(
        "provider IN ('google_drive','microsoft_onedrive','microsoft_sharepoint','aws_s3','google_cloud_storage')",
        name="ck_dlp_connectors_provider",
    ),
    sa.CheckConstraint(
        "status IN ('disconnected','connecting','connected','degraded',"
        "'reauth_required','error','disconnecting')",
        name="ck_dlp_connectors_status",
    ),
    sa.CheckConstraint("length(name) BETWEEN 1 AND 120", name="ck_dlp_connectors_name"),
)
sa.Index("ix_dlp_connectors_org_provider", DLP_CONNECTORS.c.org_id, DLP_CONNECTORS.c.provider)

DLP_CONNECTOR_STATE = sa.Table(
    "dlp_connector_state",
    metadata,
    sa.Column("connector_id", sa.String(36), primary_key=True),
    sa.Column("org_id", sa.String(36), nullable=False),
    sa.Column("provider", sa.String(32), nullable=False),
    sa.Column("checkpoint", sa.String(2048), nullable=True),
    sa.Column("state_json", sa.JSON().with_variant(JSONB(), "postgresql"), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(
        ["connector_id", "org_id"],
        ["dlp_connectors.id", "dlp_connectors.org_id"],
        ondelete="CASCADE",
    ),
    sa.CheckConstraint(
        "length(coalesce(checkpoint, '')) <= 2048", name="ck_dlp_connector_state_checkpoint"
    ),
    sa.CheckConstraint(
        "provider IN ('google_drive','microsoft_onedrive','microsoft_sharepoint','aws_s3','google_cloud_storage')",
        name="ck_dlp_connector_state_provider",
    ),
)

OAUTH_TRANSACTIONS = sa.Table(
    "dlp_oauth_transactions",
    metadata,
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
        "provider IN ('google_drive','microsoft_graph')",
        name="ck_dlp_oauth_transactions_provider",
    ),
)

RETENTION_POLICIES = sa.Table(
    "dlp_retention_policies",
    metadata,
    sa.Column("org_id", sa.String(36), nullable=False),
    sa.Column("category", sa.String(32), nullable=False),
    sa.Column("retention_days", sa.Integer(), nullable=False),
    sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    sa.Column("effective_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_by", sa.String(36), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="RESTRICT"),
    sa.ForeignKeyConstraint(
        ["updated_by", "org_id"],
        ["members.id", "members.organization_id"],
        ondelete="RESTRICT",
    ),
    sa.PrimaryKeyConstraint("org_id", "category"),
    sa.CheckConstraint(
        "category IN ('sessions','scan_records','sso_ephemera','revoked_credentials')",
        name="ck_dlp_retention_policies_category",
    ),
    sa.CheckConstraint("retention_days BETWEEN 1 AND 3650", name="ck_dlp_retention_policies_days"),
)

LEGAL_HOLDS = sa.Table(
    "dlp_legal_holds",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("org_id", sa.String(36), nullable=False),
    sa.Column("name", sa.String(120), nullable=False),
    sa.Column("reason", sa.String(1000), nullable=False),
    sa.Column("scope_category", sa.String(32), nullable=True),
    sa.Column("status", sa.String(16), nullable=False, server_default="active"),
    sa.Column("created_by_member_id", sa.String(36), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("released_by_member_id", sa.String(36), nullable=True),
    sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("release_reason", sa.String(1000), nullable=True),
    sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="RESTRICT"),
    sa.CheckConstraint(
        "scope_category IS NULL OR scope_category IN "
        "('sessions','scan_records','sso_ephemera','revoked_credentials')",
        name="ck_dlp_legal_holds_scope",
    ),
    sa.CheckConstraint("status IN ('active','released')", name="ck_dlp_legal_holds_status"),
    sa.CheckConstraint("length(trim(name)) BETWEEN 1 AND 120", name="ck_dlp_legal_holds_name"),
    sa.CheckConstraint("length(trim(reason)) BETWEEN 1 AND 1000", name="ck_dlp_legal_holds_reason"),
    sa.CheckConstraint(
        "(status = 'active' AND released_at IS NULL AND released_by_member_id IS NULL) OR "
        "(status = 'released' AND released_at IS NOT NULL AND released_by_member_id IS NOT NULL)",
        name="ck_dlp_legal_holds_release_state",
    ),
)
sa.Index("ix_dlp_legal_holds_org_status", LEGAL_HOLDS.c.org_id, LEGAL_HOLDS.c.status)

ORG_DELETION_REQUESTS = sa.Table(
    "dlp_org_deletion_requests",
    metadata,
    sa.Column("org_id", sa.String(36), primary_key=True),
    sa.Column("status", sa.String(32), nullable=False),
    sa.Column("requested_by_member_id", sa.String(36), nullable=False),
    sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("current_table", sa.String(64), nullable=True),
    sa.Column("failure_code", sa.String(64), nullable=True),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="RESTRICT"),
    sa.CheckConstraint(
        "status IN ('requested','blocked_by_legal_hold','in_progress','failed','completed')",
        name="ck_dlp_org_deletion_status",
    ),
)

RETENTION_RUNS = sa.Table(
    "dlp_retention_runs",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("org_id", sa.String(36), nullable=False),
    sa.Column("category", sa.String(32), nullable=False),
    sa.Column("status", sa.String(16), nullable=False),
    sa.Column("deleted_count", sa.Integer(), nullable=False, server_default="0"),
    sa.Column("failure_code", sa.String(64), nullable=True),
    sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="RESTRICT"),
    sa.CheckConstraint(
        "category IN ('sessions','scan_records','sso_ephemera','revoked_credentials')",
        name="ck_dlp_retention_runs_category",
    ),
    sa.CheckConstraint(
        "status IN ('running','completed','failed')", name="ck_dlp_retention_runs_status"
    ),
    sa.CheckConstraint("deleted_count >= 0", name="ck_dlp_retention_runs_count"),
)
sa.Index("ix_dlp_retention_runs_org_started", RETENTION_RUNS.c.org_id, RETENTION_RUNS.c.started_at)

SCAN_IDEMPOTENCY = sa.Table(
    "dlp_scan_idempotency",
    metadata,
    sa.Column("organization_id", sa.String(36), primary_key=True),
    sa.Column("request_id", sa.String(36), primary_key=True),
    sa.Column("input_hash", sa.String(64), nullable=False),
    sa.Column("state", sa.String(16), nullable=False),
    sa.Column("result_json", sa.JSON().with_variant(JSONB(), "postgresql"), nullable=True),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
)

CHANNELS = sa.Table(
    "channels",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("organization_id", sa.String(36), nullable=False),
    sa.Column("channel_type", sa.String(64), nullable=False),
    sa.Column("name", sa.String(200), nullable=False),
    sa.Column("enabled", sa.Boolean(), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
)

EVENTS = sa.Table(
    "events",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("organization_id", sa.String(36), nullable=False),
    sa.Column("request_id", sa.String(36), nullable=False),
    sa.Column("scan_id", sa.String(36), nullable=False),
    sa.Column("channel", sa.String(64), nullable=False),
    sa.Column("destination", sa.String(2048), nullable=True),
    sa.Column("decision", sa.String(32), nullable=False),
    sa.Column("reason", sa.String(2048), nullable=False),
    sa.Column("finding_count", sa.Integer(), nullable=False),
    sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
)

SSO_CONFIGS = sa.Table(
    "dlp_sso_configs",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column(
        "org_id",
        sa.String(36),
        sa.ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    ),
    sa.Column("protocol", sa.String(8), nullable=False),
    sa.Column("issuer", sa.String(2048), nullable=False),
    sa.Column("client_id", sa.String(512), nullable=True),
    sa.Column("secret_ref", sa.String(36), nullable=True),
    sa.Column("certificate_ref", sa.String(36), nullable=True),
    sa.Column("settings", sa.JSON().with_variant(JSONB(), "postgresql"), nullable=False),
    sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    sa.Column("created_by", sa.String(36), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.UniqueConstraint("org_id", "protocol", name="uq_dlp_sso_configs_org_protocol"),
    sa.UniqueConstraint("id", "org_id", name="uq_dlp_sso_configs_id_org"),
    sa.ForeignKeyConstraint(["created_by", "org_id"], ["members.id", "members.organization_id"]),
    sa.ForeignKeyConstraint(
        ["secret_ref", "org_id"],
        ["dlp_vault_secrets.id", "dlp_vault_secrets.org_id"],
        ondelete="RESTRICT",
    ),
    sa.ForeignKeyConstraint(
        ["certificate_ref", "org_id"],
        ["dlp_vault_secrets.id", "dlp_vault_secrets.org_id"],
        ondelete="RESTRICT",
    ),
    sa.CheckConstraint("protocol IN ('oidc','saml')", name="ck_dlp_sso_configs_protocol"),
    sa.CheckConstraint(
        "(protocol = 'oidc' AND client_id IS NOT NULL AND secret_ref IS NOT NULL) OR "
        "(protocol = 'saml' AND certificate_ref IS NOT NULL)",
        name="ck_dlp_sso_configs_protocol_refs",
    ),
)

SSO_IDENTITIES = sa.Table(
    "dlp_sso_identities",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("org_id", sa.String(36), nullable=False),
    sa.Column("config_id", sa.String(36), nullable=False),
    sa.Column("member_id", sa.String(36), nullable=False),
    sa.Column("issuer", sa.String(2048), nullable=False),
    sa.Column("subject", sa.String(512), nullable=False),
    sa.Column("email", sa.String(320), nullable=True),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(
        ["config_id", "org_id"],
        ["dlp_sso_configs.id", "dlp_sso_configs.org_id"],
        ondelete="CASCADE",
    ),
    sa.ForeignKeyConstraint(
        ["member_id", "org_id"], ["members.id", "members.organization_id"], ondelete="CASCADE"
    ),
    sa.UniqueConstraint("org_id", "config_id", "issuer", "subject", name="uq_dlp_sso_identity"),
    sa.UniqueConstraint("org_id", "member_id", "config_id", name="uq_dlp_sso_member_config"),
)

SSO_TRANSACTIONS = sa.Table(
    "dlp_sso_transactions",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("org_id", sa.String(36), nullable=False),
    sa.Column("config_id", sa.String(36), nullable=False),
    sa.Column("protocol", sa.String(8), nullable=False),
    sa.Column("state_hash", sa.String(64), nullable=False),
    sa.Column("nonce_hash", sa.String(64), nullable=False),
    sa.Column("request_id", sa.String(256), nullable=True),
    sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(
        ["config_id", "org_id"],
        ["dlp_sso_configs.id", "dlp_sso_configs.org_id"],
        ondelete="CASCADE",
    ),
    sa.UniqueConstraint("state_hash", name="uq_dlp_sso_transaction_state"),
)

SSO_REPLAYS = sa.Table(
    "dlp_sso_replays",
    metadata,
    sa.Column("org_id", sa.String(36), nullable=False),
    sa.Column("config_id", sa.String(36), nullable=False),
    sa.Column("assertion_id", sa.String(256), nullable=False),
    sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(
        ["config_id", "org_id"],
        ["dlp_sso_configs.id", "dlp_sso_configs.org_id"],
        ondelete="CASCADE",
    ),
    sa.PrimaryKeyConstraint("org_id", "assertion_id"),
)
API_KEYS = sa.Table(
    "dlp_api_keys",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("org_id", sa.String(36), nullable=False),
    sa.Column("name", sa.String(120), nullable=False),
    sa.Column("prefix", sa.String(12), nullable=False),
    sa.Column("key_hash", sa.String(64), nullable=False),
    sa.Column("scopes", sa.JSON(), nullable=False),
    sa.Column("created_by", sa.String(36), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
)

VAULT_SECRETS = sa.Table(
    "dlp_vault_secrets",
    metadata,
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
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.UniqueConstraint("org_id", "name", name="uq_dlp_vault_secrets_org_name"),
    sa.UniqueConstraint("id", "org_id", name="uq_dlp_vault_secrets_id_org"),
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

AUDIT_EVENTS = sa.Table(
    "audit_events",
    metadata,
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
    sa.UniqueConstraint("organization_id", "sequence_number", name="uq_audit_events_org_sequence"),
    sa.CheckConstraint("sequence_number >= 1", name="ck_audit_events_sequence_positive"),
    sa.CheckConstraint("outcome IN ('success','failure','denied')", name="ck_audit_events_outcome"),
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
        "'secret.updated','secret.deleted','secret.rotated','sso.configuration_created',"
        "'sso.configuration_updated','sso.configuration_enabled','sso.configuration_disabled',"
        "'sso.login_started','sso.login_success','sso.login_failed',"
        "'sso.identity_mapping_created','sso.configuration_deleted','scim.credential_created',"
        "'scim.credential_revoked','scim.user_provisioned','scim.user_updated',"
        "'scim.user_deactivated','scim.group_created','scim.group_updated',"
        "'scim.group_deleted','scim.membership_changed','identity.session_established',"
        "'identity.session_revoked','identity.sessions_revoked','identity.organization_switched',"
        "'identity.ip_allowlist_enabled','identity.ip_allowlist_disabled',"
        "'identity.ip_allowlist_entry_added','identity.ip_allowlist_entry_removed',"
        "'identity.ip_allowlist_blocked','retention.policy_updated','retention.batch_completed',"
        "'retention.batch_failed','legal_hold.created','legal_hold.released',"
        "'organization.deletion_requested','organization.deletion_confirmed',"
        "'organization.deletion_started','organization.deletion_blocked',"
        "'organization.deletion_failed','organization.deletion_completed',"
        "'subject.export_requested','subject.export_completed','subject.export_failed',"
        "'connector.created','connector.oauth_completed','connector.connected',"
        "'connector.disconnected','connector.reauth_required','connector.sync_failed',"
        "'connector.exposure_detected','connector.share_revoked','connector.share_revoke_requested',"
        "'connector.share_revoke_failed','connector.quarantine_requested',"
        "'connector.quarantine_completed','connector.quarantine_failed',"
        "'connector.microsoft_library_selected')",
        name="ck_audit_events_action",
    ),
    sa.CheckConstraint("length(previous_hash) = 64", name="ck_audit_events_previous_hash_length"),
    sa.CheckConstraint("length(event_hash) = 64", name="ck_audit_events_hash_length"),
)

POLICIES = sa.Table(
    "dlp_policies",
    metadata,
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
    sa.Column("conditions", sa.JSON().with_variant(JSONB(), "postgresql"), nullable=False),
    sa.Column("action", sa.String(32), nullable=False),
    sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
    sa.Column(
        "created_by",
        sa.String(36),
        sa.ForeignKey("members.id", ondelete="RESTRICT"),
        nullable=False,
    ),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("priority >= 0", name="ck_dlp_policies_priority"),
    sa.CheckConstraint("version >= 1", name="ck_dlp_policies_version"),
    sa.CheckConstraint(
        "action IN ('allow','warn','block','log','redact','quarantine','revoke_share',"
        "'require_approval')",
        name="ck_dlp_policies_action",
    ),
    sa.UniqueConstraint("id", "org_id", name="uq_dlp_policies_id_org"),
)

DESTINATIONS = sa.Table(
    "dlp_destinations",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column(
        "org_id",
        sa.String(36),
        sa.ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    ),
    sa.Column("class", sa.String(32), key="destination_class", nullable=False),
    sa.Column("kind", sa.String(32), nullable=False),
    sa.Column("pattern", sa.String(255), nullable=False),
    sa.UniqueConstraint("org_id", "kind", "pattern", name="uq_dlp_destinations_org_kind_pattern"),
    sa.CheckConstraint(
        "class IN ('internal', 'public', 'personal', 'partner')",
        name="ck_dlp_destinations_class",
    ),
    sa.CheckConstraint(
        "kind IN ('domain', 'repo', 'email_domain')", name="ck_dlp_destinations_kind"
    ),
)

POLICY_VERSIONS = sa.Table(
    "dlp_policy_versions",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("policy_id", sa.String(36), nullable=False),
    sa.Column(
        "org_id",
        sa.String(36),
        sa.ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    ),
    sa.Column("version", sa.Integer(), nullable=False),
    sa.Column("snapshot", sa.JSON().with_variant(JSONB(), "postgresql"), nullable=False),
    sa.Column("created_by", sa.String(36), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.UniqueConstraint("policy_id", "version", name="uq_dlp_policy_versions_policy_version"),
    sa.CheckConstraint("version >= 1", name="ck_dlp_policy_versions_version"),
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

EXCEPTIONS = sa.Table(
    "dlp_exceptions",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column(
        "org_id",
        sa.String(36),
        sa.ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    ),
    sa.Column("policy_id", sa.String(36), nullable=False),
    sa.Column("scope", sa.JSON().with_variant(JSONB(), "postgresql"), nullable=False),
    sa.Column("reason", sa.String(500), nullable=False),
    sa.Column("approver_id", sa.String(36), nullable=False),
    sa.Column("created_by", sa.String(36), nullable=False),
    sa.Column("updated_by", sa.String(36), nullable=False),
    sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
    sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
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

SUPPRESSIONS = sa.Table(
    "dlp_suppressions",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column(
        "org_id",
        sa.String(36),
        sa.ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    ),
    sa.Column("match", sa.JSON().with_variant(JSONB(), "postgresql"), nullable=False),
    sa.Column("reason", sa.String(500), nullable=False),
    sa.Column("created_by", sa.String(36), nullable=False),
    sa.Column("updated_by", sa.String(36), nullable=False),
    sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
    sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
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

ACTIONS = sa.Table(
    "dlp_actions",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column(
        "org_id",
        sa.String(36),
        sa.ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    ),
    sa.Column("request_id", sa.String(36), nullable=False),
    sa.Column("policy_id", sa.String(36), nullable=True),
    sa.Column("policy_version", sa.Integer(), nullable=True),
    sa.Column("requested_by", sa.String(36), nullable=False),
    sa.Column("action", sa.String(32), nullable=False),
    sa.Column("status", sa.String(32), nullable=False),
    sa.Column("justification", sa.String(1000), nullable=False),
    sa.Column("metadata", sa.JSON().with_variant(JSONB(), "postgresql"), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.UniqueConstraint("org_id", "request_id", "action", name="uq_dlp_actions_idempotency"),
    sa.UniqueConstraint("id", "org_id", name="uq_dlp_actions_id_org"),
)

APPROVALS = sa.Table(
    "dlp_approvals",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column(
        "org_id",
        sa.String(36),
        sa.ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    ),
    sa.Column("action_id", sa.String(36), nullable=False),
    sa.Column("requested_by", sa.String(36), nullable=False),
    sa.Column("status", sa.String(32), nullable=False),
    sa.Column("justification", sa.String(1000), nullable=False),
    sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("decided_by", sa.String(36), nullable=True),
    sa.Column("decision_reason", sa.String(1000), nullable=True),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("escalated_at", sa.DateTime(timezone=True), nullable=True),
    sa.UniqueConstraint("action_id", name="uq_dlp_approvals_action"),
)
