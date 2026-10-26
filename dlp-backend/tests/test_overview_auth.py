
import unittest
from unittest.mock import Mock, patch
from uuid import UUID

from fastapi.testclient import TestClient

from app.auth import AuthenticatedPrincipal, get_current_principal
from main import app


ORG_ID = UUID("00000000-0000-0000-0000-000000000001")
USER_ID = UUID("00000000-0000-0000-0000-000000000003")


class OverviewAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.principal = AuthenticatedPrincipal(
            user_id=USER_ID,
            org_id=ORG_ID,
            access_token="verified-token",
        )
        app.dependency_overrides[get_current_principal] = lambda: self.principal

    def tearDown(self):
        app.dependency_overrides.clear()

    def test_missing_bearer_token_is_rejected(self):
        app.dependency_overrides.clear()

        response = self.client.get("/api/overview")

        self.assertEqual(response.status_code, 401)

    @patch("app.routers.overview.get_authenticated_supabase")
    def test_overview_uses_authenticated_organization(self, get_supabase):
        events_query = Mock()
        events_query.params = {}
        events_query.execute.return_value.data = []
        table = Mock()
        table.select.return_value.eq.return_value = events_query
        client = Mock()
        client.table.return_value = table
        get_supabase.return_value = client

        response = self.client.get("/api/overview?days=7")

        self.assertEqual(response.status_code, 200)
        get_supabase.assert_called_once_with("verified-token")
        client.table.assert_called_once_with("dlp_events")
        table.select.return_value.eq.assert_called_once_with(
            "org_id", str(ORG_ID)
        )

        payload = response.json()
        self.assertEqual(payload["total_events"], 0)
        self.assertEqual(payload["decision_counts"], {})
        self.assertEqual(payload["data_type_counts"], {})
        self.assertEqual(payload["channel_counts"], {})
        self.assertEqual(len(payload["daily_trend"]), 7)
        self.assertEqual(payload["recent_events"], [])
        self.assertEqual(payload["severity_counts"], {})
        self.assertEqual(payload["classification_counts"], {})

    def test_invalid_days_are_rejected(self):
        response = self.client.get("/api/overview?days=0")

        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()
