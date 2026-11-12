"""AES-256-GCM encryption boundary for vault values."""

import secrets
from dataclasses import dataclass
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from dlp_platform.vault.config import VaultConfigurationError

NONCE_BYTES = 12
TAG_BYTES = 16


class KeyProvider(Protocol):
    @property
    def active_key_version(self) -> int: ...

    def key_for_version(self, version: int) -> bytes: ...


class VaultKeyVersionUnavailable(ValueError):
    """No configured encryption key exists for the stored version."""


class SecretDecryptionError(ValueError):
    """Ciphertext authentication or decoding failed."""


@dataclass(frozen=True)
class EnvironmentKeyProvider:
    active_key_version: int
    keys: dict[int, bytes]

    @classmethod
    def from_env(cls) -> "EnvironmentKeyProvider":
        from dlp_platform.vault.config import VaultSettings

        settings = VaultSettings.from_env()
        settings.validate_if_enabled()
        if not settings.enabled:
            raise VaultConfigurationError("Vault is not enabled")
        return cls(active_key_version=settings.active_key_version, keys=settings.keys.copy())

    def key_for_version(self, version: int) -> bytes:
        key = self.keys.get(version)
        if key is None:
            raise VaultKeyVersionUnavailable("Vault key version is unavailable")
        if len(key) != 32:
            raise VaultConfigurationError("Vault keys must contain exactly 32 bytes")
        return key


@dataclass(frozen=True)
class EncryptedSecret:
    ciphertext: bytes
    nonce: bytes
    key_version: int


class AesGcmEncryptionProvider:
    """Authenticated AES-256-GCM using a replaceable versioned key provider."""

    def __init__(self, key_provider: KeyProvider) -> None:
        self._key_provider = key_provider

    @property
    def active_key_version(self) -> int:
        return self._key_provider.active_key_version

    def encrypt(self, plaintext: str, associated_data: bytes) -> EncryptedSecret:
        version = self.active_key_version
        nonce = secrets.token_bytes(NONCE_BYTES)
        key = self._key_provider.key_for_version(version)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), associated_data)
        return EncryptedSecret(ciphertext=ciphertext, nonce=nonce, key_version=version)

    def decrypt(
        self, ciphertext: bytes, nonce: bytes, key_version: int, associated_data: bytes
    ) -> str:
        if len(nonce) != NONCE_BYTES or len(ciphertext) < TAG_BYTES:
            raise SecretDecryptionError("Stored secret ciphertext is invalid")
        try:
            plaintext = AESGCM(self._key_provider.key_for_version(key_version)).decrypt(
                nonce, ciphertext, associated_data
            )
            return plaintext.decode("utf-8")
        except (InvalidTag, UnicodeDecodeError, ValueError) as exc:
            if isinstance(exc, VaultKeyVersionUnavailable):
                raise
            raise SecretDecryptionError("Stored secret could not be authenticated") from None
