"""PostgreSQL RLS tests for P11 tenant-scoped provider and identity data."""

import json
import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text

DATABASE_URL = os.getenv("P03_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    DATABASE_URL is None, reason="P03_TEST_DATABASE_URL is not configured"
)


def test_sso_tables_enforce_tenant_and_role_rls() -> None:
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL)
    org_a, org_b = str(uuid4()), str(uuid4())
    member_a, member_b = str(uuid4()), str(uuid4())
    config_a, config_b = str(uuid4()), str(uuid4())
    secret_a, secret_b = str(uuid4()), str(uuid4())
    identity_a, identity_b = str(uuid4()), str(uuid4())
    try:
        with engine.begin() as conn:
            for org in (org_a, org_b):
                conn.execute(
                    text("INSERT INTO organizations (id,name) VALUES (:id,'P11 test')"),
                    {"id": org},
                )
            for member, org in ((member_a, org_a), (member_b, org_b)):
                conn.execute(
                    text(
                        "INSERT INTO members (id,organization_id,auth_subject_id,role,email) "
                        "VALUES (:id,:org,:subject,'owner',:email)"
                    ),
                    {
                        "id": member,
                        "org": org,
                        "subject": member,
                        "email": f"{member}@test.example",
                    },
                )
            for secret, org in ((secret_a, org_a), (secret_b, org_b)):
                conn.execute(
                    text(
                        "INSERT INTO dlp_vault_secrets "
                        "(id,org_id,name,secret_type,ciphertext,nonce,key_version) "
                        "VALUES (:id,:org,'P11 test','oauth_client_secret',:cipher,:nonce,1)"
                    ),
                    {"id": secret, "org": org, "cipher": b"x" * 16, "nonce": b"n" * 12},
                )
            for config, member, org, secret in (
                (config_a, member_a, org_a, secret_a),
                (config_b, member_b, org_b, secret_b),
            ):
                conn.execute(
                    text(
                        "INSERT INTO dlp_sso_configs "
                        "(id,org_id,protocol,issuer,client_id,secret_ref,settings,enabled,"
                        "created_by,created_at,updated_at) "
                        "VALUES (:id,:org,'oidc','https://idp.example.com','client',:secret,"
                        '\'{"claimed_domains":["test.example"],"scopes":["openid"]}\',true,:member,now(),now())'
                    ),
                    {"id": config, "org": org, "secret": secret, "member": member},
                )
            for identity, config, member, org in (
                (identity_a, config_a, member_a, org_a),
                (identity_b, config_b, member_b, org_b),
            ):
                conn.execute(
                    text(
                        "INSERT INTO dlp_sso_identities "
                        "(id,org_id,config_id,member_id,issuer,subject,created_at) "
                        "VALUES (:id,:org,:config,:member,'https://idp.example.com',:subject,now())"
                    ),
                    {
                        "id": identity,
                        "org": org,
                        "config": config,
                        "member": member,
                        "subject": identity,
                    },
                )

        with engine.connect() as conn:
            trans = conn.begin()
            conn.execute(text("SET LOCAL ROLE authenticated"))
            conn.execute(
                text("SELECT set_config('request.jwt.claims', :claims, true)"),
                {
                    "claims": json.dumps(
                        {
                            "role": "authenticated",
                            "aud": "authenticated",
                            "org_id": org_a,
                            "app_role": "owner",
                        }
                    )
                },
            )
            assert conn.execute(
                text("SELECT id FROM dlp_sso_configs WHERE id IN (:a,:b)"),
                {"a": config_a, "b": config_b},
            ).scalars().all() == [config_a]
            assert conn.execute(
                text("SELECT id FROM dlp_sso_identities WHERE id IN (:a,:b)"),
                {"a": identity_a, "b": identity_b},
            ).scalars().all() == [identity_a]
            assert (
                conn.execute(
                    text("UPDATE dlp_sso_configs SET enabled=false WHERE id=:id"), {"id": config_b}
                ).rowcount
                == 0
            )
            assert (
                conn.execute(
                    text("DELETE FROM dlp_sso_identities WHERE id=:id"), {"id": identity_b}
                ).rowcount
                == 0
            )
            trans.rollback()

            trans = conn.begin()
            conn.execute(text("SET LOCAL ROLE authenticated"))
            conn.execute(
                text("SELECT set_config('request.jwt.claims', :claims, true)"),
                {
                    "claims": json.dumps(
                        {
                            "role": "authenticated",
                            "aud": "authenticated",
                            "org_id": org_a,
                            "app_role": "viewer",
                        }
                    )
                },
            )
            assert (
                conn.execute(
                    text("SELECT id FROM dlp_sso_configs WHERE id=:id"), {"id": config_a}
                ).scalar_one_or_none()
                is None
            )
            trans.rollback()

            trans = conn.begin()
            conn.execute(text("SET LOCAL ROLE authenticated"))
            conn.execute(
                text("SELECT set_config('request.jwt.claims', :claims, true)"),
                {"claims": json.dumps({"role": "authenticated", "aud": "authenticated"})},
            )
            assert (
                conn.execute(
                    text("SELECT id FROM dlp_sso_configs WHERE id IN (:a,:b)"),
                    {"a": config_a, "b": config_b},
                )
                .scalars()
                .all()
                == []
            )
            trans.rollback()
    finally:
        with engine.begin() as conn:
            conn.execute(
                text("DELETE FROM organizations WHERE id IN (:a,:b)"), {"a": org_a, "b": org_b}
            )
        engine.dispose()
