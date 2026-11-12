"""Versioned environment key configuration for local/development vault use."""

import base64
import binascii
import json
import os
from dataclasses import dataclass


class VaultConfigurationError(ValueError):
    """Vault configuration is missing or invalid; messages contain no key material."""


def _positive_version(value: str, variable: str) -> int:
    try:
        version = int(value)
    except ValueError as exc:
        raise VaultConfigurationError(f"{variable} must be a positive integer") from exc
    if version < 1:
        raise VaultConfigurationError(f"{variable} must be a positive integer")
    return version


def _decode_key(value: str, variable: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise VaultConfigurationError(f"{variable} must be standard Base64") from exc
    if len(decoded) != 32:
        raise VaultConfigurationError(f"{variable} must encode exactly 32 bytes")
    return decoded


@dataclass(frozen=True)
class VaultSettings:
    enabled: bool
    active_key_version: int
    keys: dict[int, bytes]

    @classmethod
    def from_env(cls) -> "VaultSettings":
        enabled_value = os.getenv("DLP_VAULT_ENABLED", "false").strip().lower()
        if enabled_value not in {"true", "false"}:
            raise VaultConfigurationError("DLP_VAULT_ENABLED must be true or false")
        enabled = enabled_value == "true"
        active_version = _positive_version(
            os.getenv("DLP_VAULT_ACTIVE_KEY_VERSION", "1"),
            "DLP_VAULT_ACTIVE_KEY_VERSION",
        )
        encoded_active = os.getenv("DLP_VAULT_MASTER_KEY", "").strip()
        encoded_previous = os.getenv("DLP_VAULT_PREVIOUS_KEYS", "").strip()
        keys: dict[int, bytes] = {}
        if encoded_active:
            keys[active_version] = _decode_key(encoded_active, "DLP_VAULT_MASTER_KEY")
        if encoded_previous:
            try:
                previous = json.loads(encoded_previous)
            except json.JSONDecodeError as exc:
                raise VaultConfigurationError(
                    "DLP_VAULT_PREVIOUS_KEYS must be a JSON object"
                ) from exc
            if not isinstance(previous, dict):
                raise VaultConfigurationError("DLP_VAULT_PREVIOUS_KEYS must be a JSON object")
            for version_text, encoded_key in previous.items():
                if not isinstance(version_text, str) or not isinstance(encoded_key, str):
                    raise VaultConfigurationError("DLP_VAULT_PREVIOUS_KEYS entries are invalid")
                version = _positive_version(version_text, "DLP_VAULT_PREVIOUS_KEYS version")
                if version in keys:
                    raise VaultConfigurationError("Vault key versions must be unique")
                keys[version] = _decode_key(encoded_key, "DLP_VAULT_PREVIOUS_KEYS value")
        if enabled and active_version not in keys:
            raise VaultConfigurationError(
                "DLP_VAULT_MASTER_KEY is required when the vault is enabled"
            )
        return cls(enabled=enabled, active_key_version=active_version, keys=keys)

    def validate_if_enabled(self) -> None:
        if self.enabled and self.active_key_version not in self.keys:
            raise VaultConfigurationError(
                "DLP_VAULT_MASTER_KEY is required when the vault is enabled"
            )
