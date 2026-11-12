"""Deterministic matching for policy metadata and destination patterns."""

import re
from collections.abc import Mapping
from urllib.parse import urlsplit

from dlp_platform.contracts.finding import Finding
from dlp_platform.contracts.principal import Principal
from dlp_platform.contracts.scan_request import ScanRequest
from dlp_platform.policy.models import ConditionValue, Destination, validate_conditions

_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_destination_pattern(kind: str, pattern: str) -> str:
    value = pattern.strip().casefold().rstrip(".")
    if not value or any(char.isspace() for char in value):
        raise ValueError("invalid destination pattern")
    if kind in {"domain", "email_domain"}:
        wildcard = value.startswith("*.")
        host = value[2:] if wildcard else value
        if "*" in host or not host or len(host) > 253:
            raise ValueError("invalid domain pattern")
        labels = host.split(".")
        if any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
            raise ValueError("invalid domain pattern")
        return f"*.{host}" if wildcard else host
    if kind == "repo":
        if "*" in value or "?" in value or len(value) > 255 or value.startswith("/"):
            raise ValueError("repository destinations must be exact paths")
        return value
    raise ValueError("unsupported destination kind")


def _destination_value(kind: str, destination: str | None) -> str | None:
    if not destination:
        return None
    raw = destination.strip()
    if kind == "email_domain":
        if "@" not in raw:
            return None
        domain = raw.rsplit("@", 1)[1].casefold().rstrip(".")
        return domain or None
    if kind == "domain":
        parsed = urlsplit(raw if "://" in raw else f"//{raw}")
        return (parsed.hostname or "").casefold().rstrip(".") or None
    if kind == "repo":
        return raw.casefold().rstrip("/") or None
    return None


def _matches_destination(kind: str, pattern: str, destination: str | None) -> bool:
    actual = _destination_value(kind, destination)
    if actual is None:
        return False
    if pattern.startswith("*."):
        suffix = pattern[1:]
        # Wildcards match subdomains only, not the apex domain.
        return actual.endswith(suffix) and actual != pattern[2:]
    return actual == pattern


def resolve_destination_class(
    destination: str | None, destinations: tuple[Destination, ...]
) -> str | None:
    matches: list[tuple[int, int, str, str, Destination]] = []
    for item in destinations:
        pattern = normalize_destination_pattern(item.kind, item.pattern)
        if _matches_destination(item.kind, pattern, destination):
            wildcard = int(pattern.startswith("*."))
            specificity = len(pattern.replace("*.", ""))
            matches.append(
                (wildcard, -specificity, item.destination_class, str(item.destination_id), item)
            )
    if not matches:
        return None
    matches.sort(key=lambda row: row[:4])
    return matches[0][4].destination_class


def policy_matches(
    conditions: Mapping[str, ConditionValue],
    request: ScanRequest,
    principal: Principal,
    findings: tuple[Finding, ...],
    destination_class: str | None,
) -> bool:
    checked = validate_conditions(conditions)  # also rejects malformed persisted policy data
    finding_conditions = {key for key in ("data_type", "classification") if key in checked}
    if finding_conditions and not any(
        all(
            _value_matches(
                checked[key],
                finding.data_type if key == "data_type" else finding.classification.value,
            )
            for key in finding_conditions
        )
        for finding in findings
    ):
        return False

    actual_values: dict[str, object] = {
        "channel": request.channel.value,
        "destination_class": destination_class,
        # The P01 Principal has no group field; use its verified role until a trusted
        # group claim/membership contract exists.
        "user_group": principal.role.value,
        "volume": len(request.content.get_secret_value().encode("utf-8")),
        "file_type": request.context.get("file_type"),
    }
    return all(
        _value_matches(checked[key], actual_values[key])
        for key in checked
        if key not in finding_conditions
    )


def _value_matches(expected: object, actual: object) -> bool:
    if isinstance(expected, list):
        return actual in expected
    return expected == actual


def matched_condition_names(conditions: Mapping[str, ConditionValue]) -> tuple[str, ...]:
    return tuple(sorted(conditions))
