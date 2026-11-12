"""Contract for security accountability events, distinct from scan decision events."""

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import Field

from .common import ContractModel


class AuditAction(StrEnum):
    AUTHORIZATION_DENIED = "auth.authorization_denied"
    API_KEY_CREATED = "auth.api_key_created"
    API_KEY_REVOKED = "auth.api_key_revoked"
    POLICY_CREATED = "policy.created"
    POLICY_UPDATED = "policy.updated"
    POLICY_DELETED = "policy.deleted"
    POLICY_ROLLED_BACK = "policy.rolled_back"
    EXCEPTION_CREATED = "exception.created"
    EXCEPTION_UPDATED = "exception.updated"
    EXCEPTION_REVOKED = "exception.deleted"
    SUPPRESSION_CREATED = "suppression.created"
    SUPPRESSION_UPDATED = "suppression.updated"
    SUPPRESSION_REVOKED = "suppression.deleted"
    DESTINATION_CREATED = "destination.created"
    DESTINATION_UPDATED = "destination.updated"
    DESTINATION_DELETED = "destination.deleted"
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_APPROVED = "approval.approved"
    APPROVAL_REJECTED = "approval.rejected"
    APPROVAL_CANCELLED = "approval.cancelled"
    APPROVAL_EXPIRED = "approval.expired"
    ACTION_REQUESTED = "action.requested"
    ACTION_EXECUTED = "action.executed"
    SECRET_CREATED = "secret.created"
    SECRET_UPDATED = "secret.updated"
    SECRET_DISABLED = "secret.deleted"
    SECRET_ROTATED = "secret.rotated"
    SSO_CONFIGURATION_CREATED = "sso.configuration_created"
    SSO_CONFIGURATION_UPDATED = "sso.configuration_updated"
    SSO_CONFIGURATION_ENABLED = "sso.configuration_enabled"
    SSO_CONFIGURATION_DISABLED = "sso.configuration_disabled"
    SSO_LOGIN_STARTED = "sso.login_started"
    SSO_LOGIN_SUCCESS = "sso.login_success"
    SSO_LOGIN_FAILED = "sso.login_failed"
    SSO_IDENTITY_MAPPING_CREATED = "sso.identity_mapping_created"
    SSO_CONFIGURATION_DELETED = "sso.configuration_deleted"
    SCIM_CREDENTIAL_CREATED = "scim.credential_created"
    SCIM_CREDENTIAL_REVOKED = "scim.credential_revoked"
    SCIM_USER_PROVISIONED = "scim.user_provisioned"
    SCIM_USER_UPDATED = "scim.user_updated"
    SCIM_USER_DEACTIVATED = "scim.user_deactivated"
    SCIM_GROUP_CREATED = "scim.group_created"
    SCIM_GROUP_UPDATED = "scim.group_updated"
    SCIM_GROUP_DELETED = "scim.group_deleted"
    SCIM_MEMBERSHIP_CHANGED = "scim.membership_changed"
    IDENTITY_SESSION_ESTABLISHED = "identity.session_established"
    IDENTITY_SESSION_REVOKED = "identity.session_revoked"
    IDENTITY_SESSIONS_REVOKED = "identity.sessions_revoked"
    IDENTITY_ORGANIZATION_SWITCHED = "identity.organization_switched"
    IDENTITY_IP_ALLOWLIST_ENABLED = "identity.ip_allowlist_enabled"
    IDENTITY_IP_ALLOWLIST_DISABLED = "identity.ip_allowlist_disabled"
    IDENTITY_IP_ALLOWLIST_ENTRY_ADDED = "identity.ip_allowlist_entry_added"
    IDENTITY_IP_ALLOWLIST_ENTRY_REMOVED = "identity.ip_allowlist_entry_removed"
    IDENTITY_IP_ALLOWLIST_BLOCKED = "identity.ip_allowlist_blocked"
    RETENTION_POLICY_UPDATED = "retention.policy_updated"
    RETENTION_BATCH_COMPLETED = "retention.batch_completed"
    RETENTION_BATCH_FAILED = "retention.batch_failed"
    LEGAL_HOLD_CREATED = "legal_hold.created"
    LEGAL_HOLD_RELEASED = "legal_hold.released"
    ORGANIZATION_DELETION_REQUESTED = "organization.deletion_requested"
    ORGANIZATION_DELETION_CONFIRMED = "organization.deletion_confirmed"
    ORGANIZATION_DELETION_STARTED = "organization.deletion_started"
    ORGANIZATION_DELETION_BLOCKED = "organization.deletion_blocked"
    ORGANIZATION_DELETION_FAILED = "organization.deletion_failed"
    ORGANIZATION_DELETION_COMPLETED = "organization.deletion_completed"
    SUBJECT_EXPORT_REQUESTED = "subject.export_requested"
    SUBJECT_EXPORT_COMPLETED = "subject.export_completed"
    SUBJECT_EXPORT_FAILED = "subject.export_failed"
    CONNECTOR_CREATED = "connector.created"
    CONNECTOR_OAUTH_COMPLETED = "connector.oauth_completed"
    CONNECTOR_CONNECTED = "connector.connected"
    CONNECTOR_DISCONNECTED = "connector.disconnected"
    CONNECTOR_REAUTH_REQUIRED = "connector.reauth_required"
    CONNECTOR_SYNC_FAILED = "connector.sync_failed"
    CONNECTOR_EXPOSURE_DETECTED = "connector.exposure_detected"
    CONNECTOR_SHARE_REVOKED = "connector.share_revoked"
    CONNECTOR_SHARE_REVOKE_REQUESTED = "connector.share_revoke_requested"
    CONNECTOR_SHARE_REVOKE_FAILED = "connector.share_revoke_failed"
    CONNECTOR_QUARANTINE_REQUESTED = "connector.quarantine_requested"
    CONNECTOR_QUARANTINE_COMPLETED = "connector.quarantine_completed"
    CONNECTOR_QUARANTINE_FAILED = "connector.quarantine_failed"
    CONNECTOR_MICROSOFT_LIBRARY_SELECTED = "connector.microsoft_library_selected"


class AuditOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


class AuditEvent(ContractModel):
    event_id: UUID
    organization_id: UUID
    occurred_at: datetime
    actor_id: str = Field(min_length=1, max_length=256)
    actor_type: str = Field(min_length=1, max_length=32)
    auth_method: str = Field(min_length=1, max_length=32)
    actor_role: str = Field(min_length=1, max_length=32)
    action: AuditAction
    resource_type: str = Field(min_length=1, max_length=64)
    resource_id: str = Field(min_length=1, max_length=256)
    outcome: AuditOutcome
    correlation_id: UUID | None = None
    source_ip: str | None = Field(default=None, max_length=64)
    user_agent: str | None = Field(default=None, max_length=512)
    metadata: dict[str, object]
    sequence_number: int = Field(ge=1)
    previous_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    event_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
