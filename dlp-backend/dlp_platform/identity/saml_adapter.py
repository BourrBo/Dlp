"""SAML 2.0 Service Provider adapter backed by OneLogin's XML-security toolkit."""

from datetime import UTC, datetime, timedelta
from typing import Any

from onelogin.saml2.auth import OneLogin_Saml2_Auth  # type: ignore[import-untyped]
from onelogin.saml2.constants import OneLogin_Saml2_Constants  # type: ignore[import-untyped]
from onelogin.saml2.settings import OneLogin_Saml2_Settings  # type: ignore[import-untyped]

from dlp_platform.identity.oidc import OIDCError, OIDCIdentity


class SAMLAdapter:
    """Strict SP-initiated SAML login; XML signature verification is delegated to xmlsec."""

    def __init__(self, *, base_url: str, organization_id: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.organization_id = organization_id
        self.acs_url = f"{self.base_url}/auth/sso/{organization_id}/saml/acs"
        self.entity_id = f"{self.base_url}/auth/sso/saml/{organization_id}/metadata"

    def _settings(
        self,
        *,
        issuer: str,
        sso_url: str,
        certificate: str,
    ) -> dict[str, Any]:
        if "BEGIN CERTIFICATE" not in certificate or len(certificate) > 32_000:
            raise OIDCError("SSO provider configuration is invalid")
        return {
            "strict": True,
            "debug": False,
            "sp": {
                "entityId": self.entity_id,
                "assertionConsumerService": {
                    "url": self.acs_url,
                    "binding": OneLogin_Saml2_Constants.BINDING_HTTP_POST,
                },
            },
            "idp": {
                "entityId": issuer,
                "singleSignOnService": {
                    "url": sso_url,
                    "binding": OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT,
                },
                "x509cert": certificate,
            },
            "security": {
                "authnRequestsSigned": False,
                "wantAssertionsSigned": True,
                "wantMessagesSigned": False,
                "wantNameId": True,
                "rejectDeprecatedAlgorithm": True,
                "requestedAuthnContext": False,
                "allowSingleLabelDomains": False,
            },
        }

    def _request_data(
        self, *, post_data: dict[str, str], query: dict[str, str] | None = None
    ) -> dict[str, Any]:
        host = self.base_url.removeprefix("https://").removeprefix("http://")
        return {
            "https": "on" if self.base_url.startswith("https://") else "off",
            "http_host": host,
            "script_name": f"/auth/sso/{self.organization_id}/saml/acs",
            "get_data": query or {},
            "post_data": post_data,
        }

    def start(
        self,
        *,
        issuer: str,
        sso_url: str,
        certificate: str,
        relay_state: str,
    ) -> tuple[str, str]:
        auth = OneLogin_Saml2_Auth(
            self._request_data(post_data={}),
            self._settings(issuer=issuer, sso_url=sso_url, certificate=certificate),
        )
        url = auth.login(return_to=relay_state)
        request_id = auth.get_last_request_id()
        if not isinstance(request_id, str) or not request_id:
            raise OIDCError("SSO provider request could not be created")
        return url, request_id

    def validate_response(
        self,
        *,
        issuer: str,
        sso_url: str,
        certificate: str,
        response: str,
        relay_state: str,
        request_id: str,
        email_attribute: str,
        verified_attribute: str,
        name_attribute: str | None,
    ) -> tuple[OIDCIdentity, str, datetime]:
        if len(response) > 1_000_000:
            raise OIDCError("SSO response is invalid")
        auth = OneLogin_Saml2_Auth(
            self._request_data(post_data={"SAMLResponse": response, "RelayState": relay_state}),
            self._settings(issuer=issuer, sso_url=sso_url, certificate=certificate),
        )
        try:
            auth.process_response(request_id=request_id)
            if auth.get_errors() or not auth.is_authenticated():
                raise OIDCError("SSO response is invalid")
            assertion_id = auth.get_last_assertion_id()
            name_id = auth.get_nameid()
            attrs = auth.get_attributes()
            email_values = attrs.get(email_attribute, [])
            verified_values = attrs.get(verified_attribute, [])
            email = email_values[0] if email_values else None
            verified = (
                verified_values[0].lower() in {"true", "1", "yes"} if verified_values else False
            )
            if (
                not isinstance(assertion_id, str)
                or not assertion_id
                or not isinstance(name_id, str)
                or not name_id
                or not isinstance(email, str)
                or not verified
            ):
                raise OIDCError("SSO identity claims are invalid")
            display_name = None
            if name_attribute:
                values = attrs.get(name_attribute, [])
                display_name = values[0][:200] if values and isinstance(values[0], str) else None
            expiry = auth.get_session_expiration()
            expires_at = (
                datetime.fromtimestamp(expiry, UTC)
                if isinstance(expiry, (int, float))
                else datetime.now(UTC) + timedelta(minutes=5)
            )
            return (
                OIDCIdentity(issuer, name_id, email.strip().lower(), True, display_name),
                assertion_id,
                expires_at,
            )
        except OIDCError:
            raise
        except Exception as exc:
            # Never surface SAML XML, signature diagnostics, or certificate details.
            raise OIDCError("SSO response is invalid") from exc

    def metadata(self, *, issuer: str, sso_url: str, certificate: str) -> str:
        settings = OneLogin_Saml2_Settings(
            self._settings(issuer=issuer, sso_url=sso_url, certificate=certificate)
        )
        return str(settings.get_sp_metadata())
