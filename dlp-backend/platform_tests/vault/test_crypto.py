"""Cryptographic boundary and key configuration tests for P09."""

import base64

import pytest

from dlp_platform.vault.config import VaultConfigurationError, VaultSettings
from dlp_platform.vault.crypto import (
    AesGcmEncryptionProvider,
    SecretDecryptionError,
    VaultKeyVersionUnavailable,
)


class FakeKeyProvider:
    def __init__(self, active: int = 1, keys: dict[int, bytes] | None = None) -> None:
        self.active_key_version = active
        self.keys = keys or {active: b"k" * 32}

    def key_for_version(self, version: int) -> bytes:
        if version not in self.keys:
            raise VaultKeyVersionUnavailable("Vault key version is unavailable")
        return self.keys[version]


def test_authenticated_encryption_round_trip_and_distinct_nonces() -> None:
    provider = AesGcmEncryptionProvider(FakeKeyProvider())
    first = provider.encrypt("secret-canary", b"tenant-a:record-1")
    second = provider.encrypt("secret-canary", b"tenant-a:record-1")
    assert first.key_version == 1
    assert first.nonce != second.nonce
    assert first.ciphertext != second.ciphertext
    assert (
        provider.decrypt(first.ciphertext, first.nonce, 1, b"tenant-a:record-1") == "secret-canary"
    )


def test_authenticated_encryption_rejects_tampering_and_wrong_associated_data() -> None:
    provider = AesGcmEncryptionProvider(FakeKeyProvider())
    encrypted = provider.encrypt("secret-canary", b"tenant-a:record-1")
    corrupted = encrypted.ciphertext[:-1] + bytes([encrypted.ciphertext[-1] ^ 1])
    with pytest.raises(SecretDecryptionError):
        provider.decrypt(corrupted, encrypted.nonce, 1, b"tenant-a:record-1")
    with pytest.raises(SecretDecryptionError):
        provider.decrypt(encrypted.ciphertext, encrypted.nonce, 1, b"tenant-b:record-1")


def test_unknown_key_version_fails_closed() -> None:
    provider = AesGcmEncryptionProvider(FakeKeyProvider())
    with pytest.raises(VaultKeyVersionUnavailable):
        provider.decrypt(b"x" * 16, b"n" * 12, 3, b"tenant")


def test_vault_settings_validate_active_and_previous_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    active = base64.b64encode(b"a" * 32).decode()
    previous = base64.b64encode(b"b" * 32).decode()
    monkeypatch.setenv("DLP_VAULT_ENABLED", "true")
    monkeypatch.setenv("DLP_VAULT_ACTIVE_KEY_VERSION", "2")
    monkeypatch.setenv("DLP_VAULT_MASTER_KEY", active)
    monkeypatch.setenv("DLP_VAULT_PREVIOUS_KEYS", '{"1":"' + previous + '"}')
    settings = VaultSettings.from_env()
    assert settings.enabled
    assert settings.active_key_version == 2
    assert settings.keys == {1: b"b" * 32, 2: b"a" * 32}


@pytest.mark.parametrize(
    ("key", "version"),
    [
        ("not-base64", "1"),
        (base64.b64encode(b"short").decode(), "1"),
        (base64.b64encode(b"a" * 32).decode(), "0"),
    ],
)
def test_invalid_key_configuration_fails_without_echoing_key(
    monkeypatch: pytest.MonkeyPatch, key: str, version: str
) -> None:
    monkeypatch.setenv("DLP_VAULT_ENABLED", "true")
    monkeypatch.setenv("DLP_VAULT_ACTIVE_KEY_VERSION", version)
    monkeypatch.setenv("DLP_VAULT_MASTER_KEY", key)
    with pytest.raises(VaultConfigurationError) as error:
        VaultSettings.from_env()
    assert key not in str(error.value)


def test_enabled_vault_requires_configured_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DLP_VAULT_ENABLED", "true")
    monkeypatch.delenv("DLP_VAULT_MASTER_KEY", raising=False)
    monkeypatch.delenv("DLP_VAULT_PREVIOUS_KEYS", raising=False)
    with pytest.raises(VaultConfigurationError):
        VaultSettings.from_env()
