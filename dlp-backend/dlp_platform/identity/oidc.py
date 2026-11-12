"""OIDC discovery, authorization-code exchange, and verified ID-token handling."""

import base64
import http.client
import ipaddress
import json
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlsplit

import jwt
from jwt.exceptions import PyJWTError


class OIDCError(ValueError):
    """Safe OIDC operation failure; no provider response details are exposed."""


class UnsafeProviderURL(OIDCError):
    """Provider URLs may not reach local or non-public networks."""


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection pinned to a validated public IP while retaining TLS host checks."""

    def __init__(self, host: str, address: str, **kwargs: Any) -> None:
        super().__init__(host, **kwargs)
        self._validated_address = address
        self._tls_context = kwargs.get("context") or ssl.create_default_context()

    def connect(self) -> None:
        self.sock = socket.create_connection((self._validated_address, self.port), self.timeout)
        self.sock = self._tls_context.wrap_socket(self.sock, server_hostname=self.host)


def validate_provider_url(url: str, *, resolve: bool = True) -> str:
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise UnsafeProviderURL("SSO provider URL is not allowed") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.fragment
    ):
        raise UnsafeProviderURL("SSO provider URL is not allowed")
    host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    if host in {"localhost", "localhost.localdomain"} or host.endswith(
        (".localhost", ".local", ".internal")
    ):
        raise UnsafeProviderURL("SSO provider URL is not allowed")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        raise UnsafeProviderURL("SSO provider URL is not allowed")
    if resolve:
        _public_addresses(host, 443)
    return url


def _public_addresses(host: str, port: int) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        addresses = list(
            dict.fromkeys(
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            )
        )
    except (OSError, ValueError) as exc:
        raise UnsafeProviderURL("SSO provider URL is not allowed") from exc
    if not addresses or any(not address.is_global for address in addresses):
        raise UnsafeProviderURL("SSO provider URL is not allowed")
    return addresses


def _fetch_json(
    url: str,
    *,
    method: str = "GET",
    data: dict[str, str] | None = None,
    auth: tuple[str, str] | None = None,
) -> dict[str, Any]:
    validate_provider_url(url, resolve=False)
    parsed = urlsplit(url)
    assert parsed.hostname is not None
    addresses = _public_addresses(parsed.hostname, 443)
    request_body = urlencode(data).encode("ascii") if data is not None else None
    headers = {"Accept": "application/json", "Connection": "close"}
    if request_body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Content-Length"] = str(len(request_body))
    if auth is not None:
        encoded_auth = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode("ascii")
        headers["Authorization"] = f"Basic {encoded_auth}"
    target = parsed.path or "/"
    if parsed.query:
        target = f"{target}?{parsed.query}"
    connection = _PinnedHTTPSConnection(
        parsed.hostname,
        str(addresses[0]),
        port=443,
        timeout=5,
        context=ssl.create_default_context(),
    )
    try:
        connection.request(method, target, body=request_body, headers=headers)
        response = connection.getresponse()
        if response.status != 200:
            raise OIDCError("SSO provider request failed")
        raw = response.read(512_001)
        if len(raw) > 512_000:
            raise OIDCError("SSO provider response is too large")
        decoded = json.loads(raw)
        if not isinstance(decoded, dict):
            raise OIDCError("SSO provider response is invalid")
        return decoded
    except OIDCError:
        raise
    except (OSError, http.client.HTTPException, ValueError, json.JSONDecodeError) as exc:
        raise OIDCError("SSO provider request failed") from exc
    finally:
        connection.close()


@dataclass(frozen=True)
class OIDCDiscovery:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    token_auth_method: str = "client_secret_basic"


@dataclass(frozen=True)
class OIDCIdentity:
    issuer: str
    subject: str
    email: str
    email_verified: bool
    display_name: str | None


def discover(issuer: str) -> OIDCDiscovery:
    validate_provider_url(issuer)
    document = _fetch_json(f"{issuer.rstrip('/')}/.well-known/openid-configuration")
    if document.get("issuer") != issuer.rstrip("/"):
        raise OIDCError("SSO provider configuration is invalid")
    endpoints: list[str] = []
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        value = document.get(key)
        if not isinstance(value, str):
            raise OIDCError("SSO provider configuration is invalid")
        endpoints.append(validate_provider_url(value))
    methods = document.get("token_endpoint_auth_methods_supported")
    if methods is None or isinstance(methods, list) and "client_secret_basic" in methods:
        token_auth_method = "client_secret_basic"
    elif isinstance(methods, list) and "client_secret_post" in methods:
        token_auth_method = "client_secret_post"
    else:
        raise OIDCError("SSO provider configuration is invalid")
    return OIDCDiscovery(
        issuer=issuer.rstrip("/"),
        authorization_endpoint=endpoints[0],
        token_endpoint=endpoints[1],
        jwks_uri=endpoints[2],
        token_auth_method=token_auth_method,
    )


def authorization_url(
    discovery: OIDCDiscovery,
    *,
    client_id: str,
    redirect_uri: str,
    scopes: list[str],
    state: str,
    nonce: str,
    challenge: str,
) -> str:
    query = urlencode(
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    return f"{discovery.authorization_endpoint}?{query}"


_jwks: dict[str, tuple[float, list[dict[str, Any]]]] = {}
_jwks_refreshed: dict[str, float] = {}
_jwks_lock = threading.Lock()


def _key_for(jwks_uri: str, kid: str) -> Any:
    now = time.monotonic()
    with _jwks_lock:
        cached = _jwks.get(jwks_uri)
        keys = cached[1] if cached is not None and cached[0] > now else []
    candidate = next((item for item in keys if item.get("kid") == kid), None)
    if candidate is None:
        with _jwks_lock:
            last_refresh = _jwks_refreshed.get(jwks_uri, 0.0)
            if now - last_refresh < 5:
                raise OIDCError("SSO provider signing key is unknown")
            _jwks_refreshed[jwks_uri] = now
        fresh = _fetch_json(jwks_uri).get("keys")
        if not isinstance(fresh, list) or len(fresh) > 100:
            raise OIDCError("SSO provider keys are invalid")
        keys = [item for item in fresh if isinstance(item, dict)]
        with _jwks_lock:
            _jwks[jwks_uri] = (now + 300, keys)
        candidate = next((item for item in keys if item.get("kid") == kid), None)
    if candidate is None or candidate.get("use", "sig") != "sig":
        raise OIDCError("SSO provider signing key is unknown")
    algorithm = candidate.get("alg")
    if algorithm not in {"RS256", "ES256"} or candidate.get("kty") != (
        "RSA" if algorithm == "RS256" else "EC"
    ):
        raise OIDCError("SSO provider signing key is invalid")
    try:
        return jwt.PyJWK.from_dict(candidate, algorithm=algorithm).key, algorithm
    except (PyJWTError, ValueError, TypeError) as exc:
        raise OIDCError("SSO provider signing key is invalid") from exc


def exchange_and_validate(
    discovery: OIDCDiscovery,
    *,
    code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    verifier: str,
    expected_nonce: str,
) -> OIDCIdentity:
    if not code or len(code) > 4096:
        raise OIDCError("SSO response is invalid")
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": verifier,
    }
    auth = None
    if discovery.token_auth_method == "client_secret_basic":
        auth = (client_id, client_secret)
    elif discovery.token_auth_method == "client_secret_post":
        data.update(client_id=client_id, client_secret=client_secret)
    else:
        raise OIDCError("SSO provider configuration is invalid")
    tokens = _fetch_json(discovery.token_endpoint, method="POST", data=data, auth=auth)
    if tokens.get("token_type", "Bearer").lower() != "bearer":
        raise OIDCError("SSO response is invalid")
    id_token = tokens.get("id_token")
    if not isinstance(id_token, str) or len(id_token) > 32_000:
        raise OIDCError("SSO response is invalid")
    try:
        header = jwt.get_unverified_header(id_token)
        kid, algorithm = header.get("kid"), header.get("alg")
        if not isinstance(kid, str) or algorithm not in {"RS256", "ES256"}:
            raise OIDCError("SSO token is invalid")
        key, expected_algorithm = _key_for(discovery.jwks_uri, kid)
        if algorithm != expected_algorithm:
            raise OIDCError("SSO token is invalid")
        claims = jwt.decode(
            id_token,
            key,
            algorithms=[expected_algorithm],
            audience=client_id,
            issuer=discovery.issuer,
            leeway=0,
            options={"require": ["exp", "iat", "iss", "aud", "sub", "nonce"]},
        )
    except OIDCError:
        raise
    except (PyJWTError, ValueError, TypeError) as exc:
        raise OIDCError("SSO token is invalid") from exc
    subject, email, email_verified = (
        claims.get("sub"),
        claims.get("email"),
        claims.get("email_verified"),
    )
    issued_at = claims.get("iat")
    if (
        not isinstance(subject, str)
        or not subject
        or len(subject) > 512
        or not isinstance(email, str)
        or len(email) > 320
        or email_verified is not True
        or claims.get("nonce") != expected_nonce
        or not isinstance(issued_at, (float, int))
        or issued_at > time.time() + 60
    ):
        raise OIDCError("SSO identity claims are invalid")
    audience = claims.get("aud")
    if isinstance(audience, list) and claims.get("azp") != client_id:
        raise OIDCError("SSO identity claims are invalid")
    name = claims.get("name")
    return OIDCIdentity(
        discovery.issuer,
        subject,
        email.strip().lower(),
        True,
        name[:200] if isinstance(name, str) else None,
    )
