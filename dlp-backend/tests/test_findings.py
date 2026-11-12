import os
import unittest
from unittest.mock import patch
from uuid import UUID, uuid4

from fastapi.testclient import TestClient

from app.auth import AuthenticatedPrincipal, get_current_principal
from app.models.finding import Channel, Decision, DataType, Finding, ScanRequest
from app.services import findings_service
from main import app

ORG = UUID("00000000-0000-0000-0000-000000000001")
USER = UUID("00000000-0000-0000-0000-000000000003")


class FakeQuery:
    def __init__(self, store, table):
        self.store, self.table = store, table
        self.filters, self.method, self.body, self._limit = {}, "GET", None, None

    def select(self, _c="*"): return self
    def eq(self, c, v): self.filters[c] = str(v); return self
    def order(self, *_a, **_k): return self
    def limit(self, n): self._limit = n; return self
    def insert(self, v): self.method, self.body = "POST", v; return self
    def update(self, v): self.method, self.body = "PATCH", v; return self

    def _match(self, row):
        return all(str(row.get(k)) == v for k, v in self.filters.items())

    def execute(self):
        rows = self.store.setdefault(self.table, [])
        if self.method == "POST":
            items = self.body if isinstance(self.body, list) else [self.body]
            out = [{"id": str(uuid4()), **i} for i in items]
            rows.extend(out)
            return type("R", (), {"data": out})()
        if self.method == "PATCH":
            hit = [r for r in rows if self._match(r)]
            for r in hit:
                r.update(self.body)
            return type("R", (), {"data": hit})()
        hit = [r for r in rows if self._match(r)]
        return type("R", (), {"data": hit[: self._limit] if self._limit else hit})()


class FakeClient:
    def __init__(self, store): self.store = store
    def table(self, name): return FakeQuery(self.store, name)


def _request():
    return ScanRequest(org_id=ORG, user_id=USER, channel=Channel.API, destination="x.com",
                       content="c", filename="a.txt")


def _finding(level="restricted"):
    return Finding(data_type=DataType.API_KEY, confidence=0.98, matched_snippet="sha256:abc",
                   sensitivity_level=level, label="Secret: aws access key", start=0, end=4)


class FindingsServiceTests(unittest.TestCase):
    def test_block_persists_finding_and_opens_incident_once(self):
        store = {}
        with patch("app.services.findings_service.database.get_supabase", return_value=FakeClient(store)):
            findings_service.record_scan(_request(), [_finding()], Decision.BLOCK, None, uuid4())
            findings_service.record_scan(_request(), [_finding()], Decision.BLOCK, None, uuid4())
        self.assertEqual(len(store["dlp_findings"]), 2)
        self.assertEqual(store["dlp_findings"][0]["severity"], "critical")
        self.assertEqual(store["dlp_findings"][0]["masked_evidence"], "sha256:abc")
        self.assertEqual(len(store["dlp_incidents"]), 1)
        self.assertEqual(store["dlp_incidents"][0]["number"], "INC-0001")
        self.assertEqual([e["event_type"] for e in store["dlp_incident_events"]], ["created", "detection_repeated"])

    def test_allow_and_log_do_not_open_incident(self):
        store = {}
        with patch("app.services.findings_service.database.get_supabase", return_value=FakeClient(store)):
            findings_service.record_scan(_request(), [_finding("internal")], Decision.LOG, None, None)
        self.assertEqual(len(store["dlp_findings"]), 1)
        self.assertNotIn("dlp_incidents", store)

    def test_storage_failure_never_raises(self):
        with patch("app.services.findings_service.database.get_supabase", side_effect=RuntimeError("down")):
            findings_service.record_scan(_request(), [_finding()], Decision.BLOCK, None, None)


@unittest.skipIf(os.name == "nt", "TestClient sockets")
class FindingsRouterTests(unittest.TestCase):
    def setUp(self):
        self.store = {"dlp_findings": [
            {"id": str(uuid4()), "org_id": str(ORG), "user_id": str(USER), "severity": "high",
             "data_type": "api_key", "status": "open", "source": "api", "confidence": 0.9,
             "created_at": "2026-11-01T00:00:00+00:00", "updated_at": "2026-11-01T00:00:00+00:00"},
            {"id": str(uuid4()), "org_id": str(uuid4()), "user_id": str(USER), "severity": "low",
             "data_type": "email_pii", "status": "open", "source": "api", "confidence": 0.5,
             "created_at": "2026-11-01T00:00:00+00:00", "updated_at": "2026-11-01T00:00:00+00:00"},
        ]}
        app.dependency_overrides[get_current_principal] = lambda: AuthenticatedPrincipal(
            user_id=USER, org_id=ORG, access_token="t")
        self.patcher = patch("app.routers.findings.get_authenticated_supabase", return_value=FakeClient(self.store))
        self.patcher.start()
        self.client = TestClient(app)

    def tearDown(self):
        self.patcher.stop(); app.dependency_overrides.clear()

    def test_list_is_org_scoped_and_filterable(self):
        rows = self.client.get("/api/v1/findings").json()
        self.assertEqual(len(rows), 1)
        self.assertEqual(self.client.get("/api/v1/findings?severity=low").json(), [])

    def test_patch_updates_status_and_rejects_empty_body(self):
        fid = self.store["dlp_findings"][0]["id"]
        r = self.client.patch(f"/api/v1/findings/{fid}", json={"status": "triaged", "owner": "sam"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["status"], "triaged")
        self.assertEqual(self.client.patch(f"/api/v1/findings/{fid}", json={}).status_code, 422)
        self.assertEqual(self.client.get(f"/api/v1/findings/{uuid4()}").status_code, 404)


if __name__ == "__main__":
    unittest.main()


class AllowlistTests(unittest.TestCase):
    def setUp(self):
        self.store = {}
        self.client_fake = FakeClient(self.store)
        app.dependency_overrides[get_current_principal] = lambda: AuthenticatedPrincipal(
            user_id=USER, org_id=ORG, access_token="t")
        from app.auth import get_scan_principal
        app.dependency_overrides[get_scan_principal] = lambda: AuthenticatedPrincipal(
            user_id=USER, org_id=ORG, access_token="", auth_method="api_key", scopes=("scan:request",))
        self.patches = [
            patch("app.routers.allowlist.database.get_supabase", return_value=self.client_fake),
            patch("app.routers.allowlist.database.get_authenticated_supabase", return_value=self.client_fake),
        ]
        for p in self.patches: p.start()
        self.client = TestClient(app)

    def tearDown(self):
        for p in self.patches: p.stop()
        app.dependency_overrides.clear()

    def test_admin_adds_and_cli_key_reads_fingerprints(self):
        self.assertEqual(self.client.post("/api/v1/allowlist", json={"fingerprint": "0123456789abcdef"}).status_code, 201)
        self.assertEqual(self.client.get("/api/v1/allowlist").json(), {"fingerprints": ["0123456789abcdef"]})

    def test_rejects_values_that_are_not_fingerprints(self):
        r = self.client.post("/api/v1/allowlist", json={"fingerprint": "AKIAIOSFODNN7EXAMPLE"})
        self.assertEqual(r.status_code, 422)


class RestDeleteTests(unittest.TestCase):
    def test_delete_requires_a_filter_and_sends_delete(self):
        from app import database

        with patch.object(database, "_base_url", return_value="http://x"), \
                patch.object(database, "_headers", return_value={}), \
                patch("app.database.httpx.delete") as delete:
            delete.return_value.content = b""
            delete.return_value.raise_for_status = lambda: None
            with self.assertRaises(ValueError):
                database._RestQuery("dlp_allowlist").delete().execute()
            database._RestQuery("dlp_allowlist").eq("org_id", "1").delete().execute()
            delete.assert_called_once()
