"""Focused P11 tests for transaction protection, URL safety, and token validation."""

import time
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4

import jwt
import pytest
import xmlsec
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from dlp_platform.contracts.common import Role
from dlp_platform.identity import oidc
from dlp_platform.identity.mapping import map_identity
from dlp_platform.identity.models import SSOConfigWrite, SSOProtocol
from dlp_platform.identity.oidc import OIDCDiscovery, OIDCError, OIDCIdentity, UnsafeProviderURL
from dlp_platform.identity.saml_adapter import SAMLAdapter
from dlp_platform.identity.state import StateError, cookie_name, new_secret, open_cookie, seal


def _clear_jwks() -> None:
    oidc._jwks.clear()
    oidc._jwks_refreshed.clear()


@pytest.mark.parametrize(
    "url",
    [
        "http://idp.example.com",
        "https://localhost/",
        "https://127.0.0.1/",
        "https://169.254.169.254/latest/meta-data",
        "https://10.0.0.5/",
        "https://idp.example.com:8443/",
        "file:///etc/passwd",
    ],
)
def test_provider_url_rejects_unsafe_targets(url: str) -> None:
    with pytest.raises(UnsafeProviderURL):
        oidc.validate_provider_url(url, resolve=False)


def test_provider_url_rejects_private_dns_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        oidc.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(None, None, None, None, ("192.168.1.20", 443))],
    )
    with pytest.raises(UnsafeProviderURL):
        oidc.validate_provider_url("https://idp.example.com", resolve=True)


def test_state_cookie_is_signed_bound_and_short_lived(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DLP_SSO_STATE_SECRET", "unit-test-state-secret-0123456789abcd")
    state = new_secret()
    payload = {
        "state": state,
        "nonce": new_secret(),
        "verifier": new_secret(48),
        "config_id": str(uuid4()),
        "org_id": str(uuid4()),
        "exp": int(time.time()) + 300,
    }
    cookie = seal(payload)
    assert open_cookie(cookie, state=state) == payload
    assert cookie_name(state) != cookie_name(new_secret())
    with pytest.raises(StateError):
        open_cookie(cookie, state=new_secret())
    with pytest.raises(StateError):
        open_cookie(f"{cookie}x", state=state)
    expired = {**payload, "exp": int(time.time()) - 1}
    with pytest.raises(StateError):
        open_cookie(seal(expired), state=state)


def test_oidc_authorization_request_uses_state_nonce_and_s256_pkce() -> None:
    discovery = OIDCDiscovery(
        "https://idp.example.com",
        "https://idp.example.com/authorize",
        "https://idp.example.com/token",
        "https://idp.example.com/jwks",
    )
    target = oidc.authorization_url(
        discovery,
        client_id="synthetic-client",
        redirect_uri="https://dlp.example.com/callback",
        scopes=["openid", "email"],
        state="one-time-state",
        nonce="one-time-nonce",
        challenge="s256-code-challenge",
    )
    query = parse_qs(urlsplit(target).query)
    assert query["state"] == ["one-time-state"]
    assert query["nonce"] == ["one-time-nonce"]
    assert query["code_challenge"] == ["s256-code-challenge"]
    assert query["code_challenge_method"] == ["S256"]


def _jwk(public_key, kid: str) -> dict[str, str]:
    numbers = public_key.public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": jwt.utils.base64url_encode(
            numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
        ).decode(),
        "e": jwt.utils.base64url_encode(
            numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
        ).decode(),
    }


def test_oidc_signature_claims_nonce_and_unknown_kid_refresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = "https://idp.example.com"
    discovery = OIDCDiscovery(
        issuer,
        f"{issuer}/authorize",
        f"{issuer}/token",
        f"{issuer}/jwks",
    )
    nonce = new_secret()
    now = int(datetime.now(UTC).timestamp())
    token = jwt.encode(
        {
            "iss": issuer,
            "aud": "dlp-client",
            "sub": "provider-user-123",
            "email": "user@example.com",
            "email_verified": True,
            "nonce": nonce,
            "iat": now,
            "exp": now + 300,
        },
        key,
        algorithm="RS256",
        headers={"kid": "rotated-key"},
    )
    calls: list[str] = []

    def fetch(url: str, **kwargs):
        calls.append(url)
        if url.endswith("/token"):
            return {"token_type": "Bearer", "id_token": token}
        return {"keys": [_jwk(key.public_key(), "rotated-key")]}

    monkeypatch.setattr(oidc, "_fetch_json", fetch)
    _clear_jwks()
    identity = oidc.exchange_and_validate(
        discovery,
        code="synthetic-code",
        client_id="dlp-client",
        client_secret="synthetic-client-secret",
        redirect_uri=f"{issuer}/callback",
        verifier=new_secret(48),
        expected_nonce=nonce,
    )
    assert identity.subject == "provider-user-123"
    assert identity.email_verified is True
    assert calls.count(discovery.jwks_uri) == 1


@pytest.mark.parametrize("wrong_claim", ["issuer", "audience", "nonce", "expired", "unverified"])
def test_oidc_rejects_invalid_tokens(monkeypatch: pytest.MonkeyPatch, wrong_claim: str) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = "https://idp.example.com"
    discovery = OIDCDiscovery(issuer, f"{issuer}/authorize", f"{issuer}/token", f"{issuer}/jwks")
    nonce = new_secret()
    claims = {
        "iss": issuer,
        "aud": "dlp-client",
        "sub": "provider-user-123",
        "email": "user@example.com",
        "email_verified": True,
        "nonce": nonce,
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
    }
    if wrong_claim == "issuer":
        claims["iss"] = "https://attacker.example.com"
    elif wrong_claim == "audience":
        claims["aud"] = "other-client"
    elif wrong_claim == "nonce":
        claims["nonce"] = "wrong-nonce"
    elif wrong_claim == "expired":
        claims["exp"] = int(time.time()) - 10
    elif wrong_claim == "unverified":
        claims["email_verified"] = False
    token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "test-key"})

    def fetch(url: str, **kwargs):
        return (
            {"token_type": "Bearer", "id_token": token}
            if url.endswith("/token")
            else {"keys": [_jwk(key.public_key(), "test-key")]}
        )

    monkeypatch.setattr(oidc, "_fetch_json", fetch)
    _clear_jwks()
    with pytest.raises(OIDCError):
        oidc.exchange_and_validate(
            discovery,
            code="synthetic-code",
            client_id="dlp-client",
            client_secret="synthetic-client-secret",
            redirect_uri=f"{issuer}/callback",
            verifier=new_secret(48),
            expected_nonce=nonce,
        )


def test_oidc_rejects_unknown_kid(monkeypatch: pytest.MonkeyPatch) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = "https://idp.example.com"
    discovery = OIDCDiscovery(issuer, f"{issuer}/authorize", f"{issuer}/token", f"{issuer}/jwks")
    nonce = new_secret()
    claims = {
        "iss": issuer,
        "aud": "dlp-client",
        "sub": "s",
        "email": "a@example.com",
        "email_verified": True,
        "nonce": nonce,
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
    }
    token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "missing"})
    monkeypatch.setattr(
        oidc,
        "_fetch_json",
        lambda url, **_kwargs: {"token_type": "Bearer", "id_token": token}
        if url.endswith("/token")
        else {"keys": [_jwk(other_key.public_key(), "other")]},
    )
    _clear_jwks()
    with pytest.raises(OIDCError):
        oidc.exchange_and_validate(
            discovery,
            code="c",
            client_id="dlp-client",
            client_secret="x",
            redirect_uri="https://x",
            verifier="v",
            expected_nonce=nonce,
        )


def test_oidc_rejects_invalid_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    trusted_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = "https://idp.example.com"
    discovery = OIDCDiscovery(issuer, f"{issuer}/authorize", f"{issuer}/token", f"{issuer}/jwks")
    nonce = new_secret()
    token = jwt.encode(
        {
            "iss": issuer,
            "aud": "dlp-client",
            "sub": "s",
            "email": "a@example.com",
            "email_verified": True,
            "nonce": nonce,
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
        },
        signing_key,
        algorithm="RS256",
        headers={"kid": "trusted-kid"},
    )
    monkeypatch.setattr(
        oidc,
        "_fetch_json",
        lambda url, **_kwargs: {"token_type": "Bearer", "id_token": token}
        if url.endswith("/token")
        else {"keys": [_jwk(trusted_key.public_key(), "trusted-kid")]},
    )
    _clear_jwks()
    with pytest.raises(OIDCError):
        oidc.exchange_and_validate(
            discovery,
            code="c",
            client_id="dlp-client",
            client_secret="x",
            redirect_uri="https://x",
            verifier="v",
            expected_nonce=nonce,
        )


def test_sso_configuration_rejects_untrusted_url_and_protocol_mixing() -> None:
    ref = uuid4()
    with pytest.raises(ValueError):
        SSOConfigWrite(
            protocol="oidc",
            issuer="http://idp.example.com",
            client_id="x",
            secret_ref=ref,
            claimed_domains=["example.com"],
        )
    with pytest.raises(ValueError):
        SSOConfigWrite(
            protocol="saml",
            issuer="idp",
            sso_url="http://idp.example.com",
            certificate_ref=ref,
            claimed_domains=["example.com"],
        )


def test_sso_token_resolves_existing_member_principal(auth_client, monkeypatch) -> None:
    from dlp_platform.identity.mapping import issue_access_token
    from platform_tests.auth.conftest import ORG_A, ORG_B

    secret = "synthetic-p11-token-signing-secret-0123456789"
    monkeypatch.setenv("DLP_SSO_TOKEN_SECRET", secret)
    token = issue_access_token(
        "user-owner-a",
        ORG_A,
        secret=secret,
        issuer="dlp-sso",
        audience="dlp-api",
    )
    response = auth_client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["auth_method"] == "sso"
    assert response.json()["role"] == "owner"
    cross_tenant = issue_access_token(
        "user-owner-a",
        ORG_B,
        secret=secret,
        issuer="dlp-sso",
        audience="dlp-api",
    )
    rejected = auth_client.get("/auth/me", headers={"Authorization": f"Bearer {cross_tenant}"})
    assert rejected.status_code == 401


def test_sso_configuration_read_requires_permission(auth_client) -> None:
    from platform_tests.auth.helpers import signed_token

    factory = auth_client.app.state.test_session_factory
    with factory.begin() as session:
        session.execute(
            text(
                "CREATE TABLE dlp_sso_configs (id TEXT PRIMARY KEY, org_id TEXT NOT NULL, "
                "protocol TEXT, issuer TEXT, client_id TEXT, secret_ref TEXT, "
                "certificate_ref TEXT, settings JSON, enabled BOOLEAN, created_by TEXT, "
                "created_at TIMESTAMP, updated_at TIMESTAMP)"
            )
        )
    for subject in ("user-owner-a", "user-admin-a"):
        response = auth_client.get(
            "/sso/configs", headers={"Authorization": f"Bearer {signed_token(subject)}"}
        )
        assert response.status_code == 200
        assert response.json() == []
    for subject in ("user-viewer-a", "user-analyst-a", "user-auditor-a"):
        response = auth_client.get(
            "/sso/configs", headers={"Authorization": f"Bearer {signed_token(subject)}"}
        )
        assert response.status_code == 403


def test_identity_mapping_is_tenant_scoped_and_keeps_existing_role(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    from dlp_platform.audit.service import AuditService

    monkeypatch.setattr(AuditService, "record_event", lambda *_args, **_kwargs: None)
    engine = create_engine(f"sqlite:///{(tmp_path / 'sso-identity.db').as_posix()}")
    org = str(uuid4())
    config = str(uuid4())
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE members (id TEXT PRIMARY KEY, organization_id TEXT, "
                "auth_subject_id TEXT, role TEXT, email TEXT, created_at TIMESTAMP)"
            )
        )
        connection.execute(
            text(
                "CREATE TABLE dlp_sso_identities (id TEXT PRIMARY KEY, org_id TEXT, "
                "config_id TEXT, member_id TEXT, issuer TEXT, subject TEXT, email TEXT, "
                "created_at TIMESTAMP)"
            )
        )
    try:
        identity = OIDCIdentity(
            "https://idp.example.com", "provider-subject", "new@example.com", True, "New User"
        )
        with Session(engine) as session:
            subject, role, created = map_identity(
                session,
                organization_id=UUID(org),
                config_id=UUID(config),
                protocol=SSOProtocol.OIDC,
                identity=identity,
                claimed_domains=["example.com"],
            )
            assert subject.startswith(f"sso:{config}:")
            assert role is Role.VIEWER
            assert created is True
            session.commit()
            session.execute(
                text("UPDATE members SET role='owner' WHERE auth_subject_id=:subject"),
                {"subject": subject},
            )
            session.commit()
            linked_subject, linked_role, linked = map_identity(
                session,
                organization_id=UUID(org),
                config_id=UUID(config),
                protocol=SSOProtocol.OIDC,
                identity=OIDCIdentity(
                    "https://idp.example.com",
                    "provider-subject",
                    "changed@attacker.example",
                    False,
                    None,
                ),
                claimed_domains=["example.com"],
            )
            assert linked_subject == subject
            assert linked_role is Role.OWNER
            assert linked is False
    finally:
        engine.dispose()


def _test_certificate():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic IdP")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return (
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        certificate.public_bytes(serialization.Encoding.PEM).decode(),
    )


def _signed_saml_response(
    private_key: bytes,
    *,
    audience: str,
    expires: str,
    issuer: str = "https://idp.example.com/entity",
    destination: str | None = None,
    recipient: str | None = None,
) -> str:
    from base64 import b64encode

    samlp = "urn:oasis:names:tc:SAML:2.0:protocol"
    saml = "urn:oasis:names:tc:SAML:2.0:assertion"
    now = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    acs = "https://dlp.example.com/auth/sso/11111111-1111-4111-8111-111111111111/saml/acs"
    response = etree.Element(
        f"{{{samlp}}}Response",
        nsmap={"samlp": samlp, "saml": saml},
        ID="_response",
        Version="2.0",
        IssueInstant=now,
        Destination=destination or acs,
        InResponseTo="_request",
    )
    etree.SubElement(response, f"{{{saml}}}Issuer").text = issuer
    status = etree.SubElement(response, f"{{{samlp}}}Status")
    etree.SubElement(
        status,
        f"{{{samlp}}}StatusCode",
        Value="urn:oasis:names:tc:SAML:2.0:status:Success",
    )
    assertion = etree.SubElement(
        response,
        f"{{{saml}}}Assertion",
        ID="_assertion",
        Version="2.0",
        IssueInstant=now,
    )
    etree.SubElement(assertion, f"{{{saml}}}Issuer").text = issuer
    subject = etree.SubElement(assertion, f"{{{saml}}}Subject")
    etree.SubElement(subject, f"{{{saml}}}NameID").text = "synthetic-user"
    confirmation = etree.SubElement(
        subject, f"{{{saml}}}SubjectConfirmation", Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"
    )
    etree.SubElement(
        confirmation,
        f"{{{saml}}}SubjectConfirmationData",
        InResponseTo="_request",
        Recipient=recipient or acs,
        NotOnOrAfter=expires,
    )
    conditions = etree.SubElement(
        assertion,
        f"{{{saml}}}Conditions",
        NotBefore=(datetime.now(UTC) - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        NotOnOrAfter=expires,
    )
    restriction = etree.SubElement(conditions, f"{{{saml}}}AudienceRestriction")
    etree.SubElement(restriction, f"{{{saml}}}Audience").text = audience
    authn = etree.SubElement(assertion, f"{{{saml}}}AuthnStatement", AuthnInstant=now)
    context = etree.SubElement(authn, f"{{{saml}}}AuthnContext")
    etree.SubElement(
        context, f"{{{saml}}}AuthnContextClassRef"
    ).text = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
    attribute_statement = etree.SubElement(assertion, f"{{{saml}}}AttributeStatement")
    for name, value in (("email", "user@example.com"), ("email_verified", "true")):
        attribute = etree.SubElement(attribute_statement, f"{{{saml}}}Attribute", Name=name)
        etree.SubElement(attribute, f"{{{saml}}}AttributeValue").text = value

    signature = xmlsec.template.create(
        assertion, xmlsec.Transform.EXCL_C14N, xmlsec.Transform.RSA_SHA256
    )
    assertion.insert(1, signature)
    reference = xmlsec.template.add_reference(signature, xmlsec.Transform.SHA256, uri="#_assertion")
    xmlsec.template.add_transform(reference, xmlsec.Transform.ENVELOPED)
    xmlsec.template.add_transform(reference, xmlsec.Transform.EXCL_C14N)
    key_info = xmlsec.template.ensure_key_info(signature)
    x509_data = xmlsec.template.add_x509_data(key_info)
    xmlsec.template.x509_data_add_certificate(x509_data)
    xmlsec.tree.add_ids(assertion, ["ID"])
    sign_context = xmlsec.SignatureContext()
    sign_context.key = xmlsec.Key.from_memory(private_key, xmlsec.KeyFormat.PEM, None)
    sign_context.sign(signature)
    return b64encode(etree.tostring(response)).decode()


def test_saml_requires_strict_settings_and_signed_assertions() -> None:
    from base64 import b64encode

    _, certificate = _test_certificate()
    adapter = SAMLAdapter(
        base_url="https://dlp.example.com",
        organization_id="11111111-1111-4111-8111-111111111111",
    )
    settings = adapter._settings(
        issuer="https://idp.example.com/entity",
        sso_url="https://idp.example.com/sso",
        certificate=certificate,
    )
    assert settings["strict"] is True
    assert settings["security"]["wantAssertionsSigned"] is True
    assert settings["security"]["wantMessagesSigned"] is False
    assert adapter.acs_url.endswith("/auth/sso/11111111-1111-4111-8111-111111111111/saml/acs")
    saml_target, request_id = adapter.start(
        issuer="https://idp.example.com/entity",
        sso_url="https://idp.example.com/sso",
        certificate=certificate,
        relay_state="synthetic-relay-state",
    )
    assert request_id
    assert "SAMLRequest=" in saml_target
    assert "RelayState=synthetic-relay-state" in saml_target

    unsigned_response = b64encode(
        b"<samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' "
        b"xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion' ID='_response' "
        b"Version='2.0' IssueInstant='2026-10-23T00:00:00Z' "
        b"Destination='https://dlp.example.com/auth/sso/"
        b"11111111-1111-4111-8111-111111111111/saml/acs' "
        b"InResponseTo='_request'><saml:Issuer>https://idp.example.com/entity</saml:Issuer>"
        b"<samlp:Status><samlp:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/>"
        b"</samlp:Status><saml:Assertion ID='_assertion' Version='2.0' "
        b"IssueInstant='2026-10-23T00:00:00Z'><saml:Issuer>https://idp.example.com/entity</saml:Issuer>"
        b"</saml:Assertion></samlp:Response>"
    ).decode()
    with pytest.raises(OIDCError):
        adapter.validate_response(
            issuer="https://idp.example.com/entity",
            sso_url="https://idp.example.com/sso",
            certificate=certificate,
            response=unsigned_response,
            relay_state="synthetic-relay-state",
            request_id="_request",
            email_attribute="email",
            verified_attribute="email_verified",
            name_attribute=None,
        )


def test_saml_accepts_a_valid_signed_assertion_and_rejects_wrong_audience() -> None:
    private_key, certificate = _test_certificate()
    adapter = SAMLAdapter(
        base_url="https://dlp.example.com",
        organization_id="11111111-1111-4111-8111-111111111111",
    )
    audience = adapter.entity_id
    expiration = (datetime.now(UTC) + timedelta(minutes=2)).replace(microsecond=0)
    expires = expiration.isoformat().replace("+00:00", "Z")
    signed = _signed_saml_response(private_key, audience=audience, expires=expires)
    identity, assertion_id, _expiry = adapter.validate_response(
        issuer="https://idp.example.com/entity",
        sso_url="https://idp.example.com/sso",
        certificate=certificate,
        response=signed,
        relay_state="synthetic-relay-state",
        request_id="_request",
        email_attribute="email",
        verified_attribute="email_verified",
        name_attribute=None,
    )
    assert identity.subject == "synthetic-user"
    assert identity.email_verified is True
    assert assertion_id == "_assertion"

    wrong_audience = _signed_saml_response(
        private_key, audience="https://attacker.example.com", expires=expires
    )
    with pytest.raises(OIDCError):
        adapter.validate_response(
            issuer="https://idp.example.com/entity",
            sso_url="https://idp.example.com/sso",
            certificate=certificate,
            response=wrong_audience,
            relay_state="synthetic-relay-state",
            request_id="_request",
            email_attribute="email",
            verified_attribute="email_verified",
            name_attribute=None,
        )
    invalid_responses = [
        _signed_saml_response(
            private_key,
            audience=audience,
            expires=expires,
            issuer="https://attacker.example.com/entity",
        ),
        _signed_saml_response(
            private_key,
            audience=audience,
            expires=expires,
            destination="https://attacker.example.com/acs",
        ),
        _signed_saml_response(
            private_key,
            audience=audience,
            expires=expires,
            recipient="https://attacker.example.com/acs",
        ),
    ]
    expired = (datetime.now(UTC) - timedelta(minutes=2)).replace(microsecond=0)
    invalid_responses.append(
        _signed_saml_response(
            private_key,
            audience=audience,
            expires=expired.isoformat().replace("+00:00", "Z"),
        )
    )
    for invalid_response in invalid_responses:
        with pytest.raises(OIDCError):
            adapter.validate_response(
                issuer="https://idp.example.com/entity",
                sso_url="https://idp.example.com/sso",
                certificate=certificate,
                response=invalid_response,
                relay_state="synthetic-relay-state",
                request_id="_request",
                email_attribute="email",
                verified_attribute="email_verified",
                name_attribute=None,
            )
    _, wrong_certificate = _test_certificate()
    with pytest.raises(OIDCError):
        adapter.validate_response(
            issuer="https://idp.example.com/entity",
            sso_url="https://idp.example.com/sso",
            certificate=wrong_certificate,
            response=signed,
            relay_state="synthetic-relay-state",
            request_id="_request",
            email_attribute="email",
            verified_attribute="email_verified",
            name_attribute=None,
        )
    from base64 import b64encode

    xxe = b64encode(
        b"<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"
        b"<samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol'>&xxe;</samlp:Response>"
    ).decode()
    with pytest.raises(OIDCError):
        adapter.validate_response(
            issuer="https://idp.example.com/entity",
            sso_url="https://idp.example.com/sso",
            certificate=certificate,
            response=xxe,
            relay_state="synthetic-relay-state",
            request_id="_request",
            email_attribute="email",
            verified_attribute="email_verified",
            name_attribute=None,
        )
    with pytest.raises(OIDCError):
        adapter.validate_response(
            issuer="https://idp.example.com/entity",
            sso_url="https://idp.example.com/sso",
            certificate=certificate,
            response="A" * 1_000_001,
            relay_state="synthetic-relay-state",
            request_id="_request",
            email_attribute="email",
            verified_attribute="email_verified",
            name_attribute=None,
        )
