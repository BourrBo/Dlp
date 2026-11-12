"""Client IP resolution and canonical CIDR matching for P13 allowlists."""

import ipaddress
import os
from collections.abc import Sequence
from typing import Any


class NetworkConfigurationError(ValueError):
    """Raised when trusted proxy configuration is malformed."""


def parse_network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Parse and normalize an IP address or CIDR range."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Invalid IP address or CIDR")
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ValueError("Invalid IP address or CIDR") from exc


def _trusted_proxies() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    raw = os.getenv("DLP_TRUSTED_PROXY_CIDRS", "")
    try:
        if not raw.strip():
            return []
        items = [item.strip() for item in raw.split(",")]
        if any(not item for item in items):
            raise ValueError("empty trusted proxy network")
        return [parse_network(item) for item in items]
    except ValueError as exc:
        raise NetworkConfigurationError("Trusted proxy configuration is invalid") from exc


def _contains(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    networks: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> bool:
    return any(address.version == network.version and address in network for network in networks)


def client_ip(request: Any) -> str | None:
    """Honor X-Forwarded-For only when the direct peer is a configured trusted proxy."""
    peer = getattr(getattr(request, "client", None), "host", None)
    if not isinstance(peer, (str, bytes, int, ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return None
    try:
        peer_address = ipaddress.ip_address(peer)
    except (ValueError, TypeError):
        return None
    trusted = _trusted_proxies()
    if not _contains(peer_address, trusted):
        return str(peer_address)

    forwarded = request.headers.get("x-forwarded-for", "")
    if not forwarded:
        return None
    pieces = [part.strip() for part in forwarded.split(",")]
    if len(pieces) > 10 or any(not part for part in pieces):
        return None
    try:
        chain = [ipaddress.ip_address(part) for part in pieces]
    except ValueError:
        return None
    chain.append(peer_address)
    for address in reversed(chain):
        if not _contains(address, trusted):
            return str(address)
    return None


def is_allowed(address: str | None, networks: Sequence[str]) -> bool:
    if address is None:
        return False
    try:
        parsed = ipaddress.ip_address(address)
        return any(
            parsed.version == network.version and parsed in network
            for network in (parse_network(value) for value in networks)
        )
    except ValueError:
        return False
