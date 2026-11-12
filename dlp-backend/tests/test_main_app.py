import os
import unittest

from fastapi.testclient import TestClient

from main import app


@unittest.skipIf(os.name == "nt", "ASGI socket event loop is verified in the Linux Docker suite")
class MainAppIntegrationTests(unittest.TestCase):
    def test_lifespan_initializes_webhook_queue_and_mounts_public_health_and_github_routes(self):
        with TestClient(app) as client:
            health = client.get("/health")
            self.assertEqual(health.status_code, 200)
            self.assertEqual(health.json(), {"status": "ok"})
            paths = set(app.openapi()["paths"])
            self.assertIn("/webhooks/github", paths)


if __name__ == "__main__":
    unittest.main()
