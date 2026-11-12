import hashlib
import os
import tempfile
import unittest
from datetime import UTC, datetime
from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from app.models.finding import Decision
from main import app

ORG = str(uuid4())
OWNER = str(uuid4())
PREFIX = "a1b2c3d4e5f6"
KEY = f"dlp_{PREFIX}." + "k" * 43


class PlatformKeyAuthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        url = f"sqlite:///{self.tmp.name}/platform.db"
        self.env = patch.dict(os.environ, {"APP_ENV": "unit-test", "DATABASE_URL": url})
        self.env.start()
        from dlp_platform.tables import API_KEYS, MEMBERS, ORGANIZATIONS, metadata

        engine = create_engine(url)
        metadata.create_all(engine)
        now = datetime.now(UTC)
        member_id = str(uuid4())
        with engine.begin() as conn:
            conn.execute(ORGANIZATIONS.insert().values(id=ORG, name="Acme", settings_json={}, created_at=now, updated_at=now))
            conn.execute(MEMBERS.insert().values(id=member_id, organization_id=ORG, auth_subject_id=OWNER,
                                                 role="admin", email=None, active=True, created_at=now))
            self._insert_key = lambda scopes, revoked=None: conn.execute(API_KEYS.insert().values(
                id=str(uuid4()), org_id=ORG, name="ext", prefix=PREFIX,
                key_hash=hashlib.sha256(KEY.encode()).hexdigest(), scopes=scopes,
                created_by=member_id, created_at=now, last_used_at=None, revoked_at=revoked))
            self._insert_key(["scan:request"])
        engine.dispose()
        self.enabled = patch("app.platform_bridge.platform_enabled", return_value=True)
        self.enabled.start()
        self.client = TestClient(app)

    def tearDown(self):
        self.enabled.stop()
        self.env.stop()
        self.tmp.cleanup()

    def _payload(self, org=ORG):
        return {"org_id": org, "channel": "api", "destination": "x.com",
                "content": "key AKIAIOSFODNN7EXAMPLE"}

    def _scan(self, token, org=ORG):
        with patch("app.routers.detect.policy_engine.evaluate", return_value=(Decision.BLOCK, None, "blocked")), \
                patch("app.routers.detect._persist_event", return_value=False), \
                patch("app.services.person_b.detection_service._detect_custom_regex", return_value=[]), \
                patch("app.services.person_b.detection_service.edm_service.detect", return_value=[]), \
                patch("app.services.person_b.detection_service.fingerprint_service.detect", return_value=[]):
            return self.client.post("/api/scan", json=self._payload(org),
                                    headers={"Authorization": f"Bearer {token}"})

    def test_valid_key_scans_and_blocks(self):
        r = self._scan(KEY)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["decision"], "block")
        self.assertTrue(r.json()["findings"])

    def test_key_cannot_scan_another_org(self):
        self.assertEqual(self._scan(KEY, org=str(uuid4())).status_code, 403)

    def test_wrong_secret_is_rejected(self):
        self.assertEqual(self._scan(f"dlp_{PREFIX}." + "z" * 43).status_code, 401)

    def test_key_cannot_read_dashboard_routes(self):
        r = self.client.get("/api/v1/findings", headers={"Authorization": f"Bearer {KEY}"})
        self.assertIn(r.status_code, (401, 403, 503))

    def test_platform_pipeline_detects_with_main_detectors(self):
        from app.platform_bridge.pipeline import build_stages
        from dlp_platform.contracts.scan_request import ScanRequest

        stages = build_stages()
        req = ScanRequest(channel="api", content="token AKIAIOSFODNN7EXAMPLE")
        found = stages.detector.detect(stages.extractor.extract(req), req)
        self.assertTrue(found)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", found[0].masked_evidence)


if __name__ == "__main__":
    unittest.main()


class OrgOptionalTests(unittest.TestCase):
    """Extension, CLI and agent calls omit org_id; it comes from the key."""

    def test_org_resolves_from_principal_when_omitted(self):
        from app.auth import AuthenticatedPrincipal, resolve_org

        principal = AuthenticatedPrincipal(user_id=uuid4(), org_id=uuid4(), access_token="", auth_method="api_key")
        self.assertEqual(resolve_org(principal, None), principal.org_id)
        with self.assertRaises(Exception):
            resolve_org(principal, uuid4())
