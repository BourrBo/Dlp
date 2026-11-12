"""JWT authentication accepts only correctly signed, current provider tokens."""

from datetime import UTC, datetime

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import text

from dlp_platform.auth import jwt as jwt_module
from dlp_platform.auth.jwt import TokenRejected, decode_access_token
from dlp_platform.auth.settings import AuthSettings
from platform_tests.auth.conftest import ISSUER, ORG_B
from platform_tests.auth.helpers import auth_headers, signed_token


def test_valid_jwt_resolves_principal(auth_client) -> None:
    response = auth_client.get("/auth/me", headers=auth_headers())
    assert response.status_code == 200
    assert response.json()["organization_id"] == "11111111-1111-4111-8111-111111111111"
    assert response.json()["role"] == "owner"
    assert response.json()["auth_method"] == "jwt"


def test_jwt_without_org_claim_uses_unique_database_membership(auth_client) -> None:
    token = signed_token(include_org=False)
    response = auth_client.get("/auth/me", headers=auth_headers(token))
    assert response.status_code == 200
    assert response.json()["organization_id"] == "11111111-1111-4111-8111-111111111111"


def test_jwt_without_org_claim_rejects_ambiguous_membership(auth_client) -> None:
    factory = auth_client.app.state.test_session_factory
    with factory.begin() as session:
        session.execute(
            text(
                "INSERT INTO members (id, organization_id, auth_subject_id, role) "
                "VALUES (:id, :org, :subject, :role)"
            ),
            {
                "id": "99999999-9999-4999-8999-999999999999",
                "org": "22222222-2222-4222-8222-222222222222",
                "subject": "user-owner-a",
                "role": "admin",
            },
        )
    assert (
        auth_client.get(
            "/auth/me",
            headers=auth_headers(signed_token(include_org=False)),
        ).status_code
        == 401
    )
    scoped_token = signed_token(organization_id=ORG_B, subject="user-owner-a")
    assert auth_client.get("/auth/me", headers=auth_headers(scoped_token)).status_code == 200


@pytest.mark.parametrize(
    ("subject", "expected_role"),
    [
        ("user-owner-a", "owner"),
        ("user-admin-a", "admin"),
        ("user-analyst-a", "analyst"),
        ("user-viewer-a", "viewer"),
        ("user-auditor-a", "auditor"),
    ],
)
def test_all_named_roles_resolve_from_membership(
    auth_client, subject: str, expected_role: str
) -> None:
    response = auth_client.get("/auth/me", headers=auth_headers(signed_token(subject=subject)))
    assert response.status_code == 200
    assert response.json()["role"] == expected_role


def test_small_configured_clock_skew_is_allowed(
    auth_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("JWT_LEEWAY_SECONDS", "15")
    token = signed_token(expires_in=-10)
    assert auth_client.get("/auth/me", headers=auth_headers(token)).status_code == 200


@pytest.mark.parametrize("token", [None, "not-a-jwt", "a.b.c"])
def test_missing_or_malformed_jwt_is_unauthenticated(auth_client, token: str | None) -> None:
    headers = {} if token is None else auth_headers(token)
    assert auth_client.get("/auth/me", headers=headers).status_code == 401


def test_expired_jwt_is_rejected(auth_client) -> None:
    assert (
        auth_client.get("/auth/me", headers=auth_headers(signed_token(expires_in=-60))).status_code
        == 401
    )


def test_forged_or_invalid_signature_is_rejected(auth_client) -> None:
    forged = signed_token(secret="attacker-controlled-synthetic-secret-0123456789")
    assert auth_client.get("/auth/me", headers=auth_headers(forged)).status_code == 401


def test_invalid_audience_is_rejected(auth_client) -> None:
    token = signed_token(audience="other-service")
    assert auth_client.get("/auth/me", headers=auth_headers(token)).status_code == 401


def test_unknown_org_and_missing_membership_are_rejected(auth_client) -> None:
    other_org_member_token = signed_token(subject="user-owner-b", organization_id=ORG_B)
    assert (
        auth_client.get("/auth/me", headers=auth_headers(other_org_member_token)).status_code == 200
    )
    unknown_org_token = signed_token(organization_id=ORG_B)
    assert auth_client.get("/auth/me", headers=auth_headers(unknown_org_token)).status_code == 401
    wrong_subject = signed_token(subject="not-a-member")
    assert auth_client.get("/auth/me", headers=auth_headers(wrong_subject)).status_code == 401


def test_unsigned_jwt_is_rejected(auth_client) -> None:
    token = jwt.encode(
        {
            "sub": "user-owner-a",
            "org_id": "11111111-1111-4111-8111-111111111111",
            "aud": "authenticated",
        },
        key="",
        algorithm="none",
    )
    assert auth_client.get("/auth/me", headers=auth_headers(token)).status_code == 401


def test_jwt_issuer_must_match(auth_client) -> None:
    token = jwt.encode(
        {
            "sub": "user-owner-a",
            "org_id": "11111111-1111-4111-8111-111111111111",
            "iss": "https://attacker.invalid",
            "aud": "authenticated",
            "exp": 4_102_444_800,
        },
        "synthetic-test-signing-secret-never-use-outside-tests-0123456789",
        algorithm="HS256",
    )
    assert auth_client.get("/auth/me", headers=auth_headers(token)).status_code == 401


def test_required_claims_are_enforced(auth_client) -> None:
    token = jwt.encode(
        {
            "sub": "user-owner-a",
            "org_id": "11111111-1111-4111-8111-111111111111",
            "exp": 4_102_444_800,
        },
        "synthetic-test-signing-secret-never-use-outside-tests-0123456789",
        algorithm="HS256",
    )
    assert auth_client.get("/auth/me", headers=auth_headers(token)).status_code == 401


def test_configured_key_sources_are_exclusive() -> None:
    settings = AuthSettings(
        database_url="sqlite://",
        supabase_url=None,
        jwt_secret="synthetic-secret",
        jwks_url="https://synthetic.invalid/jwks.json",
        jwt_issuer=None,
        jwt_audience="authenticated",
        jwt_leeway_seconds=0,
    )
    with pytest.raises(TokenRejected):
        decode_access_token(signed_token(), settings)


def test_asymmetric_jwks_validation_uses_fixed_algorithms(monkeypatch: pytest.MonkeyPatch) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    now = int(datetime.now(UTC).timestamp())
    token = jwt.encode(
        {
            "sub": "synthetic-user",
            "org_id": "11111111-1111-4111-8111-111111111111",
            "iss": ISSUER,
            "aud": "authenticated",
            "iat": now,
            "exp": now + 60,
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "synthetic-kid"},
    )

    class FakeJWKClient:
        def get_signing_key_from_jwt(self, supplied_token: str):
            assert supplied_token == token

            class SigningKey:
                key = public_key

            return SigningKey()

    monkeypatch.setattr(jwt_module, "_jwks_client", lambda _url: FakeJWKClient())
    settings = AuthSettings(
        database_url="sqlite://",
        supabase_url=None,
        jwt_secret=None,
        jwks_url="https://synthetic.invalid/jwks.json",
        jwt_issuer=ISSUER,
        jwt_audience="authenticated",
        jwt_leeway_seconds=0,
    )
    assert decode_access_token(token, settings)["sub"] == "synthetic-user"
