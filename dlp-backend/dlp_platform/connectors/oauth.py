"""Provider-neutral OAuth Authorization Code + PKCE safety primitives."""

import base64
import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode, urlparse
from uuid import UUID

from sqlalchemy import delete, insert, text, update
from sqlalchemy.orm import Session

from dlp_platform.contracts.common import AuthMethod, Role
from dlp_platform.tables import OAUTH_TRANSACTIONS


class OAuthRejected(ValueError):
    """An OAuth transaction or endpoint did not satisfy our trust policy."""


@dataclass(frozen=True)
class OAuthTransaction:
    state: str
    verifier: str
    organization_id: UUID
    principal_id: str
    binding_id: str | None
    role: Role | None
    member_id: UUID | None
    session_id: UUID | None
    scopes: tuple[str, ...]
    auth_method: AuthMethod | None
    provider: str
    redirect_uri: str
    expires_at: float


class OAuthTransactions:
    """Bounded one-time OAuth transactions for a single application process."""

    def __init__(self, *, ttl_seconds: int = 600, capacity: int = 10_000) -> None:
        if not 30 <= ttl_seconds <= 900 or capacity < 1:
            raise ValueError("Invalid OAuth transaction bounds")
        self.ttl_seconds = ttl_seconds
        self.capacity = capacity
        self._items: dict[str, OAuthTransaction] = {}
        self._lock = threading.Lock()

    def create(
        self,
        *,
        organization_id: UUID,
        principal_id: str,
        provider: str,
        redirect_uri: str,
        binding_id: str | None = None,
        role: Role | None = None,
        member_id: UUID | None = None,
        session_id: UUID | None = None,
        scopes: tuple[str, ...] = (),
        auth_method: AuthMethod | None = None,
    ) -> tuple[OAuthTransaction, str]:
        parsed = urlparse(redirect_uri)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise OAuthRejected("OAuth redirect URI is not an allowed HTTPS URI")
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(64)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )
        now = time.time()
        transaction = OAuthTransaction(
            state,
            verifier,
            organization_id,
            principal_id,
            binding_id,
            role,
            member_id,
            session_id,
            scopes,
            auth_method,
            provider,
            redirect_uri,
            now + self.ttl_seconds,
        )
        with self._lock:
            self._purge(now)
            if len(self._items) >= self.capacity:
                raise OAuthRejected("OAuth transaction capacity reached")
            self._items[state] = transaction
        return transaction, challenge

    def consume(
        self, state: str, *, organization_id: UUID, principal_id: str, provider: str
    ) -> OAuthTransaction:
        with self._lock:
            item = self._items.get(state)
            if item is not None and item.expires_at <= time.time():
                self._items.pop(state, None)
        if (
            item is None
            or item.expires_at <= time.time()
            or item.organization_id != organization_id
            or not secrets.compare_digest(item.principal_id, principal_id)
            or item.provider != provider
        ):
            raise OAuthRejected("OAuth state is invalid or expired")
        with self._lock:
            if self._items.pop(state, None) != item:
                raise OAuthRejected("OAuth state is invalid or expired")
        return item

    def consume_callback(self, state: str, *, provider: str) -> OAuthTransaction:
        """Consume a one-time callback capability bound to its initiating principal."""
        with self._lock:
            item = self._items.get(state)
            if item is None or item.expires_at <= time.time() or item.provider != provider:
                if item is not None:
                    self._items.pop(state, None)
                raise OAuthRejected("OAuth state is invalid or expired")
            self._items.pop(state, None)
            return item

    def _purge(self, now: float) -> None:
        self._items = {key: value for key, value in self._items.items() if value.expires_at > now}


class PersistentOAuthTransactions:
    """PostgreSQL-backed, tenant-scoped one-use OAuth state.

    Only a hash of the opaque state is persisted. The tenant UUID prefix lets the
    callback establish the RLS context; changing it invalidates the stored hash.
    Consumption is one atomic UPDATE, so concurrent callbacks have one winner.
    """

    def __init__(self, *, ttl_seconds: int = 600) -> None:
        if not 30 <= ttl_seconds <= 900:
            raise ValueError("Invalid OAuth transaction bounds")
        self.ttl_seconds = ttl_seconds

    @staticmethod
    def _claims(
        session: Session, organization_id: UUID, principal_id: str = "oauth-callback"
    ) -> None:
        if session.bind is not None and session.bind.dialect.name != "postgresql":
            raise OAuthRejected("Persistent OAuth state requires PostgreSQL")
        session.execute(text("SET LOCAL ROLE authenticated"))
        session.execute(
            text("SELECT set_config('request.jwt.claims', :claims, true)"),
            {
                "claims": json.dumps(
                    {
                        "role": "authenticated",
                        "aud": "authenticated",
                        "org_id": str(organization_id),
                        "sub": principal_id,
                    }
                )
            },
        )

    def create(
        self,
        session: Session,
        *,
        organization_id: UUID,
        principal_id: str,
        provider: str,
        redirect_uri: str,
        binding_id: str,
        role: Role,
        member_id: UUID,
        session_id: UUID,
        scopes: tuple[str, ...],
        auth_method: AuthMethod,
    ) -> tuple[OAuthTransaction, str]:
        parsed = urlparse(redirect_uri)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise OAuthRejected("OAuth redirect URI is not an allowed HTTPS URI")
        if provider not in {"google_drive", "microsoft_graph"}:
            raise OAuthRejected("OAuth provider is not supported")
        state = f"{organization_id}.{secrets.token_urlsafe(32)}"
        verifier = secrets.token_urlsafe(64)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )
        now = datetime.now(UTC)
        transaction = OAuthTransaction(
            state,
            verifier,
            organization_id,
            principal_id,
            binding_id,
            role,
            member_id,
            session_id,
            scopes,
            auth_method,
            provider,
            redirect_uri,
            (now + timedelta(seconds=self.ttl_seconds)).timestamp(),
        )
        self._claims(session, organization_id, principal_id)
        digest = hashlib.sha256(state.encode()).hexdigest()
        session.execute(delete(OAUTH_TRANSACTIONS).where(OAUTH_TRANSACTIONS.c.expires_at <= now))
        session.execute(
            insert(OAUTH_TRANSACTIONS).values(
                state_hash=digest,
                org_id=str(organization_id),
                provider=provider,
                principal_id=principal_id,
                binding_id=binding_id,
                role=role.value,
                member_id=str(member_id),
                session_id=str(session_id),
                scopes=list(scopes),
                auth_method=auth_method.value,
                verifier=verifier,
                redirect_uri=redirect_uri,
                expires_at=now + timedelta(seconds=self.ttl_seconds),
                consumed_at=None,
            )
        )
        session.commit()
        return transaction, challenge

    def consume_callback(self, session: Session, state: str, *, provider: str) -> OAuthTransaction:
        if len(state) > 128 or "." not in state:
            raise OAuthRejected("OAuth state is invalid or expired")
        tenant_part, _, random_part = state.partition(".")
        if not random_part:
            raise OAuthRejected("OAuth state is invalid or expired")
        try:
            organization_id = UUID(tenant_part)
        except ValueError:
            raise OAuthRejected("OAuth state is invalid or expired") from None
        self._claims(session, organization_id)
        digest = hashlib.sha256(state.encode()).hexdigest()
        now = datetime.now(UTC)
        row = (
            session.execute(
                update(OAUTH_TRANSACTIONS)
                .where(
                    OAUTH_TRANSACTIONS.c.state_hash == digest,
                    OAUTH_TRANSACTIONS.c.org_id == str(organization_id),
                    OAUTH_TRANSACTIONS.c.provider == provider,
                    OAUTH_TRANSACTIONS.c.consumed_at.is_(None),
                    OAUTH_TRANSACTIONS.c.expires_at > now,
                )
                .values(consumed_at=now)
                .returning(*OAUTH_TRANSACTIONS.c)
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            session.rollback()
            raise OAuthRejected("OAuth state is invalid or expired")
        transaction = OAuthTransaction(
            state=state,
            verifier=str(row["verifier"]),
            organization_id=UUID(str(row["org_id"])),
            principal_id=str(row["principal_id"]),
            binding_id=str(row["binding_id"]),
            role=Role(str(row["role"])),
            member_id=UUID(str(row["member_id"])),
            session_id=UUID(str(row["session_id"])),
            scopes=tuple(str(scope) for scope in row["scopes"]),
            auth_method=AuthMethod(str(row["auth_method"])),
            provider=str(row["provider"]),
            redirect_uri=str(row["redirect_uri"]),
            expires_at=row["expires_at"].timestamp(),
        )
        session.commit()
        return transaction


def authorization_url(
    *,
    endpoint: str,
    allowed_hosts: frozenset[str],
    client_id: str,
    redirect_uri: str,
    scopes: tuple[str, ...],
    state: str,
    challenge: str,
) -> str:
    parsed = urlparse(endpoint)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in allowed_hosts
        or parsed.port not in (None, 443)
    ):
        raise OAuthRejected("OAuth provider endpoint is not allowlisted")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise OAuthRejected("OAuth provider endpoint is malformed")
    callback = urlparse(redirect_uri)
    if (
        callback.scheme != "https"
        or not callback.hostname
        or callback.username
        or callback.password
    ):
        raise OAuthRejected("OAuth redirect URI is not allowed")
    query = urlencode(
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(scopes),
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "access_type": "offline",
            "prompt": "consent",
            "include_granted_scopes": "true",
        }
    )
    return f"{endpoint}?{query}"


def validate_provider_endpoint(url: str, allowed_hosts: frozenset[str]) -> str:
    parsed = urlparse(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in allowed_hosts
        or parsed.port not in (None, 443)
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise OAuthRejected("Provider endpoint is not allowlisted")
    return url
