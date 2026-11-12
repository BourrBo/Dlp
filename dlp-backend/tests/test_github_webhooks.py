import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.datastructures import Headers

from app.config import Settings
from app.routers.github_webhooks import MAX_GITHUB_WEBHOOK_BYTES, receive_github_webhook, router
from app.services.github_webhook_store import GitHubWebhookStore, WebhookDelivery, WebhookQueueFull


SECRET = "synthetic-webhook-secret"
INSTALLATION_ID = 123456
REPOSITORY_ID = 7654321
SHA_BEFORE = "1" * 40
SHA_AFTER = "2" * 40


def signed_headers(body: bytes, delivery="delivery-123", event="push"):
    digest = hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    return {
        "X-Hub-Signature-256": f"sha256={digest}",
        "X-GitHub-Delivery": delivery,
        "X-GitHub-Event": event,
    }


def push_payload():
    return {
        "installation": {"id": INSTALLATION_ID},
        "repository": {
            "id": REPOSITORY_ID,
            "full_name": "acme/synthetic-repo",
            "private": False,
            "visibility": "public",
        },
        "ref": "refs/heads/main",
        "before": SHA_BEFORE,
        "after": SHA_AFTER,
        "deleted": False,
        "commits": [{"message": "synthetic leaked value must never be stored"}],
    }


class GitHubWebhookRouteTests(unittest.TestCase):
    def setUp(self):
        self.settings_patch = patch(
            "app.routers.github_webhooks.get_settings",
            return_value=Settings(github_webhook_secret=SECRET),
        )
        self.settings_patch.start()
        self.addCleanup(self.settings_patch.stop)

    @unittest.skipIf(os.name == "nt", "ASGI socket event loop is verified in the Linux Docker suite")
    def test_mounted_route_accepts_signed_delivery_over_asgi(self):
        app = FastAPI()
        app.include_router(router)
        body = json.dumps(push_payload()).encode()

        class FakeStore:
            def accept(self, delivery):
                return True

        with patch(
            "app.routers.github_webhooks.get_settings",
            return_value=Settings(github_webhook_secret=SECRET),
        ), patch("app.routers.github_webhooks.get_github_webhook_store", return_value=FakeStore()):
            response = TestClient(app).post("/webhooks/github", content=body, headers=signed_headers(body))
        self.assertEqual(response.status_code, 202)
        self.assertFalse(response.json()["duplicate"])

    def call_route(self, body: bytes, headers: dict[str, str]):
        class RequestStub:
            def __init__(self):
                self.headers = Headers(headers)

            async def stream(self):
                yield body

        try:
            coroutine = receive_github_webhook(RequestStub())
            try:
                coroutine.send(None)
            except StopIteration as completed:
                return 202, completed.value
            raise AssertionError("Test request unexpectedly awaited an external ASGI event")
        except HTTPException as exc:
            return exc.status_code, exc.detail

    def test_bad_signature_is_rejected_before_json_parsing_or_queueing(self):
        with patch("app.routers.github_webhooks.get_github_webhook_store") as get_store:
            status, _ = self.call_route(
                b"not json", {"X-Hub-Signature-256": "sha256=" + "0" * 64},
            )
        self.assertEqual(status, 401)
        get_store.assert_not_called()

    def test_valid_push_persists_only_allowlisted_metadata(self):
        body = json.dumps(push_payload()).encode()
        captured = []

        class FakeStore:
            def accept(self, delivery):
                captured.append(delivery)
                return True

        with patch("app.routers.github_webhooks.get_github_webhook_store", return_value=FakeStore()):
            status, response = self.call_route(body, signed_headers(body))
        self.assertEqual(status, 202)
        self.assertEqual(response, {"accepted": True, "duplicate": False})
        self.assertEqual(len(captured), 1)
        delivery = captured[0]
        self.assertEqual(delivery.installation_id, INSTALLATION_ID)
        self.assertEqual(delivery.repository_full_name, "acme/synthetic-repo")
        self.assertEqual(delivery.visibility, "public")
        self.assertEqual(delivery.after_sha, SHA_AFTER)
        self.assertFalse(hasattr(delivery, "commits"))

    def test_duplicate_delivery_is_acknowledged_without_requeueing(self):
        body = json.dumps(push_payload()).encode()

        class DuplicateStore:
            def accept(self, delivery):
                return False

        with patch("app.routers.github_webhooks.get_github_webhook_store", return_value=DuplicateStore()):
            status, response = self.call_route(body, signed_headers(body))
        self.assertEqual(status, 202)
        self.assertTrue(response["duplicate"])

    def test_replay_with_changed_delivery_id_is_still_idempotent(self):
        body = json.dumps(push_payload()).encode()
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            store = GitHubWebhookStore(Path(directory) / "webhooks.sqlite3")
            with patch("app.routers.github_webhooks.get_github_webhook_store", return_value=store):
                first_status, first = self.call_route(
                    body, signed_headers(body, delivery="delivery-original"),
                )
                replay_status, replay = self.call_route(
                    body, signed_headers(body, delivery="delivery-changed"),
                )
        self.assertEqual(first_status, 202)
        self.assertFalse(first["duplicate"])
        self.assertEqual(replay_status, 202)
        self.assertTrue(replay["duplicate"])

    def test_unconfigured_secret_and_oversized_body_are_rejected(self):
        with patch(
            "app.routers.github_webhooks.get_settings",
            return_value=Settings(github_webhook_secret=""),
        ):
            status, _ = self.call_route(b"{}", {})
        self.assertEqual(status, 503)
        body = b"x" * (MAX_GITHUB_WEBHOOK_BYTES + 1)
        status, _ = self.call_route(body, signed_headers(body))
        self.assertEqual(status, 413)

    def test_invalid_push_fields_and_invalid_signed_json_are_rejected(self):
        invalid = push_payload()
        invalid["after"] = "not-a-sha"
        body = json.dumps(invalid).encode()
        status, _ = self.call_route(body, signed_headers(body))
        self.assertEqual(status, 400)
        invalid = push_payload()
        invalid["deleted"] = "false"
        body = json.dumps(invalid).encode()
        status, _ = self.call_route(body, signed_headers(body))
        self.assertEqual(status, 400)
        body = b"{"
        status, _ = self.call_route(body, signed_headers(body))
        self.assertEqual(status, 400)


class GitHubWebhookStoreTests(unittest.TestCase):
    def test_delivery_dedupe_persists_safe_metadata_and_claim_lifecycle(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            db_path = Path(directory) / "webhooks.sqlite3"
            store = GitHubWebhookStore(db_path)
            delivery = WebhookDelivery(
                delivery_id="delivery-123", event_type="push", action=None,
                installation_id=INSTALLATION_ID, idempotency_key="synthetic-hmac-digest",
                repository_id=REPOSITORY_ID,
                repository_full_name="acme/synthetic-repo", visibility="public",
                ref="refs/heads/main", before_sha=SHA_BEFORE, after_sha=SHA_AFTER,
            )
            self.assertTrue(store.accept(delivery))
            self.assertFalse(GitHubWebhookStore(db_path).accept(delivery))
            replay = WebhookDelivery(
                delivery_id="delivery-replayed", event_type="push", action=None,
                installation_id=INSTALLATION_ID, idempotency_key="synthetic-hmac-digest",
            )
            self.assertFalse(store.accept(replay))
            claimed = GitHubWebhookStore(db_path).claim_next()
            self.assertEqual(claimed.delivery_id, "delivery-123")
            self.assertTrue(store.finish("delivery-123"))
            self.assertIsNone(store.claim_next())
            connection = sqlite3.connect(db_path)
            try:
                columns = {row[1] for row in connection.execute("PRAGMA table_info(github_webhook_deliveries)")}
                row = connection.execute("SELECT * FROM github_webhook_deliveries").fetchone()
            finally:
                connection.close()
            self.assertNotIn("payload", columns)
            self.assertNotIn("commits", columns)
            self.assertEqual(row[0], "delivery-123")

    def test_processing_delivery_is_requeued_after_restart(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            store = GitHubWebhookStore(Path(directory) / "webhooks.sqlite3")
            store.accept(WebhookDelivery(
                delivery_id="restart-delivery", event_type="installation", action="created",
                installation_id=INSTALLATION_ID,
            ))
            self.assertIsNotNone(store.claim_next())
            restarted = GitHubWebhookStore(store.path)
            self.assertEqual(restarted.recover_processing(), 1)
            self.assertEqual(restarted.claim_next().delivery_id, "restart-delivery")

    def test_queue_capacity_rejects_new_work_but_still_deduplicates_existing_delivery(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            store = GitHubWebhookStore(Path(directory) / "webhooks.sqlite3")
            delivery = WebhookDelivery(
                delivery_id="capacity-delivery", event_type="installation", action="created",
                installation_id=INSTALLATION_ID,
            )
            store.accept(delivery)
            with patch("app.services.github_webhook_store.MAX_QUEUED_WEBHOOKS", 0):
                self.assertFalse(store.accept(delivery))
                with self.assertRaises(WebhookQueueFull):
                    store.accept(WebhookDelivery(
                        delivery_id="new-delivery", event_type="installation", action="created",
                        installation_id=INSTALLATION_ID,
                    ))


if __name__ == "__main__":
    unittest.main()
