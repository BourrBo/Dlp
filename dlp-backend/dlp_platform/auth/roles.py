"""Central role and capability vocabulary."""

from enum import StrEnum

from dlp_platform.contracts.common import Role


class Permission(StrEnum):
    IDENTITY_READ = "identity:read"
    API_KEYS_READ = "api_keys:read"
    API_KEYS_WRITE = "api_keys:write"
    SCAN_REQUEST = "scan:request"
    APPROVALS_DECIDE = "approvals:decide"
    VAULT_METADATA_READ = "vault:metadata:read"
    VAULT_WRITE = "vault:write"
    VAULT_DELETE = "vault:delete"
    VAULT_USE = "vault:use"
    AUDIT_READ = "audit:read"
    SSO_CONFIG_READ = "sso:config:read"
    SSO_CONFIG_WRITE = "sso:config:write"
    SCIM_CREDENTIALS_READ = "scim:credentials:read"
    SCIM_CREDENTIALS_WRITE = "scim:credentials:write"
    IDENTITY_SECURITY_WRITE = "identity:security:write"
    DATA_LIFECYCLE_READ = "data_lifecycle:read"
    DATA_LIFECYCLE_WRITE = "data_lifecycle:write"
    SUBJECT_DATA_EXPORT = "subject_data:export"
    ORGANIZATION_DELETE = "organization:delete"
    CONNECTORS_READ = "connectors:read"
    CONNECTORS_WRITE = "connectors:write"


ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.OWNER: frozenset(Permission),
    Role.ADMIN: frozenset(
        permission
        for permission in Permission
        if permission not in {Permission.VAULT_USE, Permission.ORGANIZATION_DELETE}
    ),
    Role.ANALYST: frozenset({Permission.IDENTITY_READ, Permission.SCAN_REQUEST}),
    Role.VIEWER: frozenset({Permission.IDENTITY_READ}),
    Role.AUDITOR: frozenset({Permission.IDENTITY_READ, Permission.AUDIT_READ}),
}

# Client-requested API-key scopes must be a subset of this closed vocabulary.
API_KEY_SCOPES = frozenset(Permission)
