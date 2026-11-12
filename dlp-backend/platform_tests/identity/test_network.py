"""IP parser and trusted-proxy behavior used by P13 interactive auth."""

from types import SimpleNamespace

import pytest

from dlp_platform.identity.network import NetworkConfigurationError, client_ip, is_allowed, parse_network


@pytest.mark.parametrize("value", ["", "not-an-ip", "192.0.2.1/99", "2001:db8::zz/32"])
def test_malformed_addresses_and_cidrs_are_rejected(value: str) -> None:
    with pytest.raises(ValueError, match="Invalid IP address or CIDR"):
        parse_network(value)
    assert is_allowed(value, ["192.0.2.0/24"]) is False


def test_empty_networks_never_allow_an_address() -> None:
    assert is_allowed("192.0.2.1", []) is False
    assert is_allowed(None, ["0.0.0.0/0"]) is False


def _request(peer: str, forwarded: str = ""):
    return SimpleNamespace(
        client=SimpleNamespace(host=peer),
        headers={"x-forwarded-for": forwarded},
    )


def test_untrusted_peer_cannot_spoof_forwarded_address(monkeypatch) -> None:
    monkeypatch.delenv("DLP_TRUSTED_PROXY_CIDRS", raising=False)
    request = _request("203.0.113.9", "192.0.2.1")
    assert client_ip(request) == "203.0.113.9"


def test_trusted_proxy_chain_selects_first_untrusted_hop(monkeypatch) -> None:
    monkeypatch.setenv("DLP_TRUSTED_PROXY_CIDRS", "10.0.0.0/8,2001:db8:ffff::/48")
    request = _request("10.0.0.2", "198.51.100.7, 10.0.0.1")
    assert client_ip(request) == "198.51.100.7"


def test_trusted_proxy_without_forwarded_chain_fails_closed(monkeypatch) -> None:
    monkeypatch.setenv("DLP_TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
    assert client_ip(_request("10.0.0.2")) is None


def test_invalid_forwarded_chain_and_proxy_configuration_fail_closed(monkeypatch) -> None:
    monkeypatch.setenv("DLP_TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
    assert client_ip(_request("10.0.0.2", "bad-address")) is None
    monkeypatch.setenv("DLP_TRUSTED_PROXY_CIDRS", "bad-cidr")
    with pytest.raises(NetworkConfigurationError):
        client_ip(_request("10.0.0.2", "192.0.2.1"))
    monkeypatch.setenv("DLP_TRUSTED_PROXY_CIDRS", "10.0.0.0/8,")
    with pytest.raises(NetworkConfigurationError):
        client_ip(_request("10.0.0.2", "192.0.2.1"))
