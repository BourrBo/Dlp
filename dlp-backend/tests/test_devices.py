import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import Settings
from app.models.finding import DataType, Decision, Finding, ScanResult
from app.routers import devices
from app.services.device_store import DeviceStore, validate_config

ORG = "11111111-1111-1111-1111-111111111111"
ADMIN = {"X-DLP-Admin-Key": "admin-secret"}


def fake_scan(request):
    if "CARD" in request.content:
        finding = Finding(data_type=DataType.CREDIT_CARD, confidence=0.9, matched_snippet="41***11")
        return ScanResult(findings=[finding], decision=Decision.BLOCK, reason="blocked")
    if "MAIL" in request.content:
        finding = Finding(data_type=DataType.EMAIL_PII, confidence=0.6, matched_snippet="so***st")
        return ScanResult(findings=[finding], decision=Decision.WARN, reason="warned")
    return ScanResult(findings=[], decision=Decision.ALLOW, reason="clean")


class DeviceApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = Path(self.tmp.name) / "devices.sqlite3"
        self.store = DeviceStore(self.db_path)
        app = FastAPI()
        app.include_router(devices.agent_router)
        app.include_router(devices.admin_router)
        app.dependency_overrides[devices.get_device_store] = lambda: self.store
        self.client = TestClient(app)
        for target, value in (
            ("app.routers.classifications.get_settings", Settings(dlp_admin_api_key="admin-secret")),
        ):
            patcher = patch(target, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        scan_patch = patch.object(devices, "run_scan", fake_scan)
        scan_patch.start()
        self.addCleanup(scan_patch.stop)

    def enrol(self):
        token = self.client.post("/devices/enrolment-tokens", json={"org_id": ORG}, headers=ADMIN).json()["enrolment_token"]
        res = self.client.post("/agent/enrol", json={"enrolment_token": token, "hostname": "LAPTOP-1", "os_name": "Windows 11", "agent_version": "0.1.0"})
        self.assertEqual(res.status_code, 201, res.text)
        data = res.json()
        return data, {"Authorization": f"Bearer {data['device_key']}"}

    # ---------------------------------------------------------------- enrol
    def test_enrolment_token_is_single_use_and_key_is_stored_hashed(self):
        data, auth = self.enrol()
        self.assertTrue(data["device_key"].startswith("dlpd_"))
        self.assertEqual(data["config"]["unscannable_action"], "warn")
        raw = sqlite3.connect(self.db_path).execute("SELECT group_concat(key_hash) FROM devices").fetchone()[0]
        self.assertNotIn(data["device_key"], raw)
        token = self.client.post("/devices/enrolment-tokens", json={"org_id": ORG}, headers=ADMIN).json()["enrolment_token"]
        body = {"enrolment_token": token, "hostname": "h", "os_name": "o", "agent_version": "1"}
        self.assertEqual(self.client.post("/agent/enrol", json=body).status_code, 201)
        self.assertEqual(self.client.post("/agent/enrol", json=body).status_code, 401)

    def test_unknown_and_expired_tokens_are_rejected(self):
        body = {"enrolment_token": "dlpe_unknowntoken123456", "hostname": "h", "os_name": "o", "agent_version": "1"}
        self.assertEqual(self.client.post("/agent/enrol", json=body).status_code, 401)
        token, _ = self.store.create_enrolment_token(ORG, ttl_seconds=-5)
        self.assertEqual(self.client.post("/agent/enrol", json={**body, "enrolment_token": token}).status_code, 401)

    def test_admin_routes_need_the_admin_key(self):
        self.assertEqual(self.client.post("/devices/enrolment-tokens", json={"org_id": ORG}).status_code, 401)
        self.assertEqual(self.client.get("/devices", params={"org_id": ORG}, headers={"X-DLP-Admin-Key": "wrong"}).status_code, 401)

    # ------------------------------------------------------------ heartbeat
    def test_heartbeat_syncs_config_and_records_tamper(self):
        _, auth = self.enrol()
        version = self.client.put(f"/devices/config/{ORG}", json={"stable_seconds": 9, "unscannable_action": "block"}, headers=ADMIN).json()["config_version"]
        res = self.client.post("/agent/heartbeat", headers=auth, json={"agent_version": "0.1.1", "queue_depth": 4, "config_version": 0, "tamper": ["service_stop"]})
        self.assertEqual(res.status_code, 200)
        reply = res.json()
        self.assertEqual((reply["config_version"], reply["config"]["stable_seconds"], reply["config"]["unscannable_action"]), (version, 9, "block"))
        same = self.client.post("/agent/heartbeat", headers=auth, json={"agent_version": "0.1.1", "queue_depth": 0, "config_version": version, "tamper": []}).json()
        self.assertNotIn("config", same)
        [device] = self.client.get("/devices", params={"org_id": ORG}, headers=ADMIN).json()["devices"]
        self.assertEqual((device["tamper_flags"], device["agent_version"], device["config_version"]), (["service_stop"], "0.1.1", version))
        self.assertIsNotNone(device["tamper_at"])
        self.client.post(f"/devices/{device['device_id']}/tamper/acknowledge", headers=ADMIN)
        [device] = self.client.get("/devices", params={"org_id": ORG}, headers=ADMIN).json()["devices"]
        self.assertEqual(device["tamper_flags"], [])

    def test_unknown_tamper_codes_are_rejected(self):
        _, auth = self.enrol()
        res = self.client.post("/agent/heartbeat", headers=auth, json={"agent_version": "1", "queue_depth": 0, "config_version": 0, "tamper": ["whatever"]})
        self.assertEqual(res.status_code, 422)

    # ----------------------------------------------------------- revocation
    def test_revoked_device_is_rejected_immediately(self):
        data, auth = self.enrol()
        hb = {"agent_version": "1", "queue_depth": 0, "config_version": 0}
        self.assertEqual(self.client.post("/agent/heartbeat", headers=auth, json=hb).status_code, 200)
        self.assertEqual(self.client.post(f"/devices/{data['device_id']}/revoke", headers=ADMIN).status_code, 200)
        for call in (
            lambda: self.client.post("/agent/heartbeat", headers=auth, json=hb),
            lambda: self.client.get("/agent/config", headers=auth),
            lambda: self.client.post("/agent/scan", headers=auth, json={"filename": "a.txt", "chunks": [{"text": "x"}]}),
        ):
            self.assertEqual(call().status_code, 401)
        self.assertEqual(self.client.post(f"/devices/{data['device_id']}/revoke", headers=ADMIN).status_code, 404)

    def test_bad_or_missing_credentials(self):
        for headers in ({}, {"Authorization": "Bearer nope"}, {"Authorization": "Basic abc"}, {"Authorization": "Bearer dlpd_" + "x" * 30}):
            self.assertEqual(self.client.get("/agent/config", headers=headers).status_code, 401)

    # --------------------------------------------------------------- events
    def test_events_are_stored_masked_and_schema_is_strict(self):
        data, auth = self.enrol()
        event = {"kind": "quarantine", "decision": "block", "folder_class": "downloads", "filename": "payroll.xlsx",
                 "data_types": ["credit_card"], "findings_count": 3, "quarantined": True, "detail": "moved to quarantine"}
        res = self.client.post("/agent/events", headers=auth, json={"events": [event]})
        self.assertEqual((res.status_code, res.json()), (202, {"accepted": 1}))
        [row] = self.client.get(f"/devices/{data['device_id']}/events", headers=ADMIN).json()["events"]
        self.assertEqual((row["kind"], row["filename"], row["data_types"], row["quarantined"]), ("quarantine", "payroll.xlsx", ["credit_card"], True))
        for bad in ({**event, "content": "4111 1111 1111 1111"}, {**event, "filename": "C:\\Users\\a\\x.txt"},
                    {**event, "filename": "../x"}, {**event, "kind": "nope"}, {**event, "findings_count": -1}):
            self.assertEqual(self.client.post("/agent/events", headers=auth, json={"events": [bad]}).status_code, 422)
        self.assertEqual(self.client.post("/agent/events", headers=auth, json={"events": []}).status_code, 422)

    # ----------------------------------------------------------------- scan
    def test_scan_returns_strictest_decision_and_uses_device_org(self):
        _, auth = self.enrol()
        seen = []

        def spy(request):
            seen.append(request)
            return fake_scan(request)

        with patch.object(devices, "run_scan", spy):
            res = self.client.post("/agent/scan", headers=auth, json={"filename": "a.csv", "chunks": [
                {"text": "hello", "location": {"row": 1}}, {"text": "MAIL", "location": {"row": 2}},
                {"text": "CARD", "location": {"row": 3}}]})
        body = res.json()
        self.assertEqual((res.status_code, body["decision"]), (200, "block"))
        self.assertEqual([f["location"]["row"] for f in body["findings"]], [2, 3])
        self.assertEqual({str(r.org_id) for r in seen}, {ORG})
        self.assertEqual({r.destination for r in seen}, {"endpoint"})

    def test_scan_rejects_client_supplied_identity_and_oversize(self):
        _, auth = self.enrol()
        res = self.client.post("/agent/scan", headers=auth, json={"filename": "a.txt", "org_id": ORG, "chunks": [{"text": "x"}]})
        self.assertEqual(res.status_code, 422)
        chunks = [{"text": "a" * 1_000_000} for _ in range(6)]
        self.assertEqual(self.client.post("/agent/scan", headers=auth, json={"filename": "a.txt", "chunks": chunks}).status_code, 413)

    # --------------------------------------------------------------- config
    def test_config_validation(self):
        for bad in ({"unknown": 1}, {"stable_seconds": 0}, {"stable_seconds": True}, {"watch_folders": []},
                    {"unscannable_action": "ignore"}, {"quarantine_on_block": "yes"}, {"heartbeat_seconds": 5}):
            self.assertEqual(self.client.put(f"/devices/config/{ORG}", json=bad, headers=ADMIN).status_code, 422, bad)
        self.assertEqual(validate_config({})["heartbeat_seconds"], 60)

    def test_event_retention_prunes_oldest(self):
        data, _ = self.enrol()
        device = self.store.get(data["device_id"])
        from app.services import device_store
        with patch.object(device_store, "MAX_EVENTS_PER_DEVICE", 5):
            for i in range(8):
                self.store.add_events(device, [{"kind": "file_scan", "decision": "allow", "folder_class": "other",
                                                "data_types": [], "findings_count": 0, "quarantined": False, "filename": f"{i}.txt"}])
        self.assertEqual(len(self.store.list_events(ORG, device.device_id, 100)), 5)


if __name__ == "__main__":
    unittest.main()
