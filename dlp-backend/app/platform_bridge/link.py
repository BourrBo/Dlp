"""Link a main-backend organization and member into the platform database.

The platform keeps its own organization/member tables (same UUIDs as the main
backend's ``organizations``/``org_members``) so its JWT and API-key checks can
resolve the same people. Linking is idempotent.
"""

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select, text

from app.platform_bridge.api_keys import _session

_ROLE_MAP = {"owner": "owner", "admin": "admin", "member": "analyst", "analyst": "analyst",
             "viewer": "viewer", "auditor": "auditor"}


def link_member(org_id: str, org_name: str, user_id: str, email: str | None, org_role: str | None) -> str:
    from dlp_platform.tables import MEMBERS, ORGANIZATIONS

    role = _ROLE_MAP.get((org_role or "").lower(), "analyst")
    now = datetime.now(UTC)
    with _session() as session:
        if session.execute(select(ORGANIZATIONS.c.id).where(ORGANIZATIONS.c.id == org_id)).first() is None:
            session.execute(ORGANIZATIONS.insert().values(
                id=org_id, name=org_name[:200] or "Organization", settings_json={}, created_at=now, updated_at=now))
        member = session.execute(text(
            "SELECT id, role FROM members WHERE organization_id = :o AND auth_subject_id = :s"),
            {"o": org_id, "s": user_id}).mappings().one_or_none()
        if member is None:
            member_id = str(uuid4())
            session.execute(MEMBERS.insert().values(
                id=member_id, organization_id=org_id, auth_subject_id=user_id, role=role,
                email=email, active=True, created_at=now))
        else:
            member_id = member["id"]
        session.commit()
        return role
