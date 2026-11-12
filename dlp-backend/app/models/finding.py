from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class DataType(str, Enum):
    CREDIT_CARD = "credit_card"
    API_KEY = "api_key"
    EMAIL_PII = "email_pii"
    NATIONAL_ID = "national_id"
    PERSON_NAME = "person_name"
    ADDRESS = "address"
    PHONE_NUMBER = "phone_number"
    DOCUMENT_MATCH = "document_match"
    CUSTOM = "custom"


class Channel(str, Enum):
    BROWSER = "browser"
    EMAIL = "email"
    CLOUD_STORAGE = "cloud_storage"
    API = "api"


class Decision(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    LOG = "log"


class Finding(BaseModel):
    """
    Normalized output of the Detection Engine. Person B: add new DataType
    values / detectors here rather than inventing a parallel schema, so the
    Policy Engine only ever has to reason about one shape.
    """

    id: UUID = Field(default_factory=uuid4)
    data_type: DataType
    confidence: float = Field(ge=0.0, le=1.0)
    matched_snippet: str
    sensitivity_level: str = "internal"  # public | internal | confidential | restricted
    matched_rule_id: Optional[UUID] = None
    label: Optional[str] = None
    # Optional character offsets in the analyzed text. Ingestion and developer
    # tooling use these to report precise source locations; existing detector
    # integrations may omit them until they can provide stable offsets.
    start: Optional[int] = Field(default=None, ge=0)
    end: Optional[int] = Field(default=None, ge=0)


class ScanRequest(BaseModel):
    # Optional on the wire: authenticated handlers fill it from the caller's organization.
    org_id: Optional[UUID] = None
    # Deprecated caller field: authenticated scan handlers replace it with the
    # verified principal ID before policy or persistence work begins.
    user_id: Optional[UUID] = None
    channel: Channel
    destination: str  # domain, email address, or share target
    content: str  # raw text extracted from the file/paste/attachment being scanned
    filename: Optional[str] = None
    event_id: Optional[UUID] = None


class ScanResult(BaseModel):
    findings: list[Finding]
    decision: Decision
    matched_policy_id: Optional[UUID] = None
    reason: str


class DlpEvent(BaseModel):
    """Mirrors the dlp_events table — what actually gets persisted."""

    id: UUID = Field(default_factory=uuid4)
    org_id: UUID
    user_id: UUID
    channel: Channel
    data_type: DataType
    confidence: float
    destination: str
    decision: Decision
    snippet: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
