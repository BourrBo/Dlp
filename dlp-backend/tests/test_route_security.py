import unittest
from unittest.mock import Mock, patch
from uuid import UUID

from fastapi import HTTPException
from fastapi.routing import APIRoute

from app.routers import detect, scan_jobs, scans
from app.auth import AuthenticatedPrincipal, get_current_principal, get_scan_principal
from app.database import _headers
from fastapi.security import HTTPAuthorizationCredentials


class ScanRouteSecurityTests(unittest.TestCase):
    def test_scan_routes_require_verified_supabase_principal(self):
        for router in (detect.router, scans.router, scan_jobs.router):
            with self.subTest(prefix=router.prefix):
                routes = [route for route in router.routes if isinstance(route, APIRoute)]
                self.assertTrue(routes)
                for route in routes:
                    self.assertTrue(
                        any(dependency.call is get_scan_principal for dependency in route.dependant.dependencies),
                        f"{route.path} has no verified-principal dependency",
                    )

    def test_verified_token_resolves_user_and_rls_visible_membership(self):
        user_id = UUID("00000000-0000-0000-0000-000000000003")
        org_id = UUID("00000000-0000-0000-0000-000000000001")
        query = Mock()
        query.execute.return_value.data = [{"org_id": str(org_id)}]
        client = Mock()
        client.table.return_value.select.return_value.eq.return_value.limit.return_value = query
        response = Mock(status_code=200, is_error=False)
        response.json.return_value = {"id": str(user_id)}
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="valid-token")
        with (
            patch("app.auth.get_settings", return_value=type("Settings", (), {
                "supabase_url": "https://project.example", "supabase_publishable_key": "publishable"
            })()),
            patch("app.auth.httpx.get", return_value=response),
            patch("app.auth.get_authenticated_supabase", return_value=client),
        ):
            principal = get_current_principal(credentials)
        self.assertEqual(principal, AuthenticatedPrincipal(user_id, org_id, "valid-token"))

    def test_invalid_session_is_rejected_before_membership_lookup(self):
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="expired-token")
        response = Mock(status_code=401)
        with (
            patch("app.auth.get_settings", return_value=type("Settings", (), {
                "supabase_url": "https://project.example", "supabase_publishable_key": "publishable"
            })()),
            patch("app.auth.httpx.get", return_value=response),
            patch("app.auth.get_authenticated_supabase") as client,
        ):
            with self.assertRaises(HTTPException) as raised:
                get_current_principal(credentials)
        self.assertEqual(raised.exception.status_code, 401)
        client.assert_not_called()

    def test_authenticated_data_api_uses_publishable_key_and_user_token(self):
        settings = type("Settings", (), {
            "supabase_publishable_key": "sb_publishable_public",
            "supabase_service_role_key": "sb_secret_server_only",
        })()
        with patch("app.database.get_settings", return_value=settings):
            headers = _headers(access_token="user-access-token")
        self.assertEqual(headers["apikey"], "sb_publishable_public")
        self.assertEqual(headers["Authorization"], "Bearer user-access-token")
        self.assertNotIn("sb_secret_server_only", repr(headers))


if __name__ == "__main__":
    unittest.main()
