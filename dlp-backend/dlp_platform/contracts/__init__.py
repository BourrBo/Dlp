"""Versioned, privacy-safe boundary contracts for the P2 platform."""

from .audit_event import AuditAction, AuditEvent, AuditOutcome
from .common import (
    ActorType,
    AuthMethod,
    ClassificationLevel,
    ContractModel,
    DataChannel,
    FindingLocation,
    FindingStatus,
    PolicyAction,
    Role,
    SeverityLevel,
)
from .event import Event
from .finding import Finding
from .incident import Incident, IncidentStatus
from .policy import Policy
from .principal import Principal
from .scan_request import ScanRequest
from .scan_result import ScanResult

CONTRACT_VERSION = "1.0.0"
CONTRACT_STATUS = "PROPOSED"

__all__ = [
    "ActorType",
    "AuditAction",
    "AuditEvent",
    "AuditOutcome",
    "AuthMethod",
    "ClassificationLevel",
    "ContractModel",
    "CONTRACT_STATUS",
    "CONTRACT_VERSION",
    "DataChannel",
    "Event",
    "Finding",
    "FindingLocation",
    "FindingStatus",
    "Incident",
    "IncidentStatus",
    "Policy",
    "PolicyAction",
    "Principal",
    "Role",
    "ScanRequest",
    "ScanResult",
    "SeverityLevel",
]
