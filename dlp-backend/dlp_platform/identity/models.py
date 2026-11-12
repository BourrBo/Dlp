"""SSO provider configuration and safe API response contracts."""

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class SSOProtocol(StrEnum):
    OIDC = "oidc"
    SAML = "saml"


class SSOConfigWrite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol: SSOProtocol
    issuer: str = Field(min_length=1, max_length=2048)
    client_id: str | None = Field(default=None, max_length=512)
    secret_ref: UUID | None = None
    certificate_ref: UUID | None = None
    sso_url: str | None = Field(default=None, max_length=2048)
    claimed_domains: list[str] = Field(min_length=1, max_length=32)
    attributes: dict[str, str] = Field(default_factory=dict)
    scopes: list[str] = Field(default_factory=lambda: ["openid", "email", "profile"])

    @field_validator("claimed_domains")
    @classmethod
    def normalize_domains(cls, domains: list[str]) -> list[str]:
        result: list[str] = []
        for domain in domains:
            value = domain.strip().rstrip(".").encode("idna").decode("ascii").lower()
            if not value or len(value) > 253 or "." not in value or "@" in value:
                raise ValueError("Invalid claimed email domain")
            if any(
                not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
                for label in value.split(".")
            ):
                raise ValueError("Invalid claimed email domain")
            result.append(value)
        if len(set(result)) != len(result):
            raise ValueError("Claimed email domains must be unique")
        return result

    @model_validator(mode="after")
    def protocol_fields(self) -> "SSOConfigWrite":
        if self.protocol is SSOProtocol.OIDC:
            if not self.client_id or self.secret_ref is None:
                raise ValueError("OIDC requires a client ID and a vault secret reference")
            if self.certificate_ref is not None or self.sso_url is not None:
                raise ValueError("SAML settings cannot be used with OIDC")
            if "openid" not in self.scopes or set(self.scopes) - {"openid", "email", "profile"}:
                raise ValueError("OIDC scopes must be selected from openid, email, and profile")
            if not self.issuer.startswith("https://"):
                raise ValueError("OIDC issuer must use HTTPS")
        else:
            if self.certificate_ref is None or self.sso_url is None:
                raise ValueError("SAML requires a signing certificate and SSO URL")
            if self.client_id is not None or self.secret_ref is not None:
                raise ValueError("OIDC settings cannot be used with SAML")
            if not self.sso_url.startswith("https://"):
                raise ValueError("SAML SSO URL must use HTTPS")
        allowed_attributes = {"email", "email_verified", "display_name", "external_id"}
        if set(self.attributes) - allowed_attributes:
            raise ValueError("Unsupported SSO attribute mapping")
        if any(not value or len(value) > 256 for value in self.attributes.values()):
            raise ValueError("Invalid SSO attribute mapping")
        return self


class SSOConfigView(BaseModel):
    config_id: UUID
    organization_id: UUID
    protocol: SSOProtocol
    issuer: str
    client_id: str | None
    secret_configured: bool
    certificate_configured: bool
    claimed_domains: list[str]
    attributes: dict[str, str]
    scopes: list[str]
    enabled: bool
    created_at: datetime
    updated_at: datetime


class IdentityLinkWrite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    member_id: UUID
    issuer: str = Field(min_length=1, max_length=2048)
    subject: str = Field(min_length=1, max_length=512)


class SSOLoginResult(BaseModel):
    organization_id: UUID
    member_id: UUID
    role: str
    access_token: str
    token_type: str = "bearer"
