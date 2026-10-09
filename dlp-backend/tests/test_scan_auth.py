import unittest
from contextlib import contextmanager, ExitStack
from unittest.mock import Mock, patch
from uuid import UUID

from fastapi.testclient import TestClient

from app.auth import AuthenticatedPrincipal, get_current_principal
from app.models.finding import Decision, Finding
from main import app


ORG_ID = UUID("00000000-0000-0000-0000-000000000001")
OTHER_ORG_ID = UUID("00000000-0000-0000-0000-000000000002")
USER_ID = UUID("00000000-0000-0000-0000-000000000003")
SPOOFED_USER_ID = UUID("00000000-0000-0000-0000-000000000004")


class _MembershipQuery:
    def __init__(self, rows: list[dict]):
        self.rows = rows
        self.filters: dict[str, str] = {}

    def select(self, _columns: str):
        return self

    def eq(self, column: str, value: str):
        self.filters[column] = value
        return self

    def limit(self, _count: int):
        return self

    def execute(self):
        return Mock(data=self.rows)


class ScanAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.principal = AuthenticatedPrincipal(
            user_id=USER_ID,
            org_id=OTHER_ORG_ID,
            access_token="verified-token",
        )
        app.dependency_overrides[get_current_principal] = lambda: self.principal

    def tearDown(self):
        app.dependency_overrides.clear()

    def _authorize_org(self, rows: list[dict]):
        query = _MembershipQuery(rows)
        client = Mock()
        client.table.return_value.select.return_value = query
        return patch("app.auth.get_authenticated_supabase", return_value=client), query

    def _scan_payload(self, **overrides):
        payload = {
            "org_id": str(ORG_ID),
            "channel": "api",
            "destination": "manual-dashboard-scan",
            "content": "test content",
        }
        payload.update(overrides)
        return payload

    @contextmanager
    def _scan_side_effects(self):
        targets = {
            "detection": "app.routers.detect.detection_service.detect",
            "policy": "app.routers.detect.policy_engine.evaluate",
            "persistence": "app.routers.detect._persist_event",
            "alerts": "app.routers.detect.send_alert",
        }
        with ExitStack() as stack:
            yield {name: stack.enter_context(patch(target)) for name, target in targets.items()}

    def _assert_scan_side_effects_not_called(self, effects):
        for effect in effects.values():
            effect.assert_not_called()

    def test_missing_bearer_token_is_rejected(self):
        app.dependency_overrides.clear()
        with self._scan_side_effects() as effects:
            response = self.client.post("/api/scan", json=self._scan_payload())

        self.assertEqual(response.status_code, 401)
        self._assert_scan_side_effects_not_called(effects)

    def test_invalid_bearer_token_is_rejected(self):
        app.dependency_overrides.clear()
        with (
            self._scan_side_effects() as effects,
            patch("app.auth.get_settings") as get_settings,
            patch("app.auth.httpx.get") as http_get,
        ):
            get_settings.return_value.supabase_url = "https://example.supabase.co"
            get_settings.return_value.supabase_service_role_key = "service-key"
            http_get.return_value.status_code = 401

            response = self.client.post(
                "/api/scan",
                headers={"Authorization": "Bearer invalid-token"},
                json=self._scan_payload(),
            )

        self.assertEqual(response.status_code, 401)
        self._assert_scan_side_effects_not_called(effects)

    @patch("app.routers.detect._persist_event")
    @patch("app.routers.detect.policy_engine.evaluate")
    @patch("app.routers.detect.detection_service.detect")
    def test_member_can_scan_non_first_organization(
        self, detect, evaluate, persist_event
    ):
        membership_patch, query = self._authorize_org([{"org_id": str(ORG_ID)}])
        detect.return_value = []
        evaluate.return_value = (Decision.ALLOW, None, "No policy matched")

        with membership_patch:
            response = self.client.post("/api/scan", json=self._scan_payload())

        self.assertEqual(response.status_code, 200)
        self.assertEqual(query.filters["user_id"], str(USER_ID))
        self.assertEqual(query.filters["org_id"], str(ORG_ID))
        detect.assert_called_once()
        persist_event.assert_called_once()

    @patch("app.routers.detect.send_alert")
    @patch("app.routers.detect._persist_event")
    @patch("app.routers.detect.policy_engine.evaluate")
    @patch("app.routers.detect.detection_service.detect")
    def test_nonmember_is_rejected_before_detection_or_persistence(
        self, detect, evaluate, persist_event, send_alert
    ):
        membership_patch, _query = self._authorize_org([])

        with membership_patch:
            response = self.client.post("/api/scan", json=self._scan_payload())

        self.assertEqual(response.status_code, 403)
        detect.assert_not_called()
        evaluate.assert_not_called()
        persist_event.assert_not_called()
        send_alert.assert_not_called()

    def test_membership_verification_error_returns_503_before_scan_work(self):
        with (
            self._scan_side_effects() as effects,
            patch(
                "app.auth.get_authenticated_supabase",
                side_effect=RuntimeError("Supabase is unavailable"),
            ),
        ):
            response = self.client.post("/api/scan", json=self._scan_payload())

        self.assertEqual(response.status_code, 503)
        self._assert_scan_side_effects_not_called(effects)

    @patch("app.routers.detect._persist_event")
    @patch("app.routers.detect.policy_engine.evaluate")
    @patch("app.routers.detect.detection_service.detect")
    def test_body_user_id_cannot_override_authenticated_identity(
        self, detect, evaluate, persist_event
    ):
        membership_patch, _query = self._authorize_org([{"org_id": str(ORG_ID)}])
        finding = Finding(
            data_type="email_pii",
            confidence=0.9,
            matched_snippet="person@example.com",
        )
        detect.return_value = [finding]
        evaluate.return_value = (Decision.ALLOW, None, "Allowed")

        with membership_patch:
            response = self.client.post(
                "/api/scan",
                json=self._scan_payload(user_id=str(SPOOFED_USER_ID)),
            )

        self.assertEqual(response.status_code, 200)
        persisted_event = persist_event.call_args.args[0]
        self.assertEqual(persisted_event.user_id, USER_ID)

    @patch("app.routers.detect.send_alert")
    @patch("app.routers.detect._persist_event")
    @patch("app.routers.detect.policy_engine.evaluate")
    @patch("app.routers.detect.detection_service.detect")
    def test_scan_response_and_warn_block_alerts_are_preserved(
        self, detect, evaluate, persist_event, send_alert
    ):
        membership_patch, _query = self._authorize_org([{"org_id": str(ORG_ID)}])
        finding = Finding(
            data_type="email_pii",
            confidence=0.9,
            matched_snippet="person@example.com",
        )
        detect.return_value = [finding]
        send_alert.return_value = {"sent": True, "reason": "Sent"}

        with membership_patch:
            for decision in (Decision.WARN, Decision.BLOCK):
                evaluate.return_value = (decision, None, f"{decision.value} reason")
                response = self.client.post("/api/scan", json=self._scan_payload())
                self.assertEqual(response.status_code, 200)
                self.assertEqual(
                    set(response.json()),
                    {"findings", "decision", "matched_policy_id", "reason"},
                )
                self.assertEqual(response.json()["decision"], decision.value)
                self.assertEqual(response.json()["reason"], f"{decision.value} reason")

        self.assertEqual(send_alert.call_count, 2)
        self.assertEqual(
            [call.kwargs["decision"] for call in send_alert.call_args_list],
            ["warn", "block"],
        )
        self.assertEqual(persist_event.call_count, 2)


if __name__ == "__main__":
    unittest.main()
