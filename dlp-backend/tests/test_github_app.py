import base64
import json
import unittest

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.services.github_app import (
    GITHUB_API_VERSION,
    INSTALLATION_PERMISSIONS,
    GitHubAppError,
    create_github_app_jwt,
    create_installation_access_token,
    verify_github_webhook_signature,
)


def decode_part(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


class GitHubAppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.private_pem = cls.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def test_app_jwt_has_clock_skew_claims_and_valid_rs256_signature(self):
        token = create_github_app_jwt("client-123", self.private_pem, now=1_800_000_000)
        header_part, payload_part, signature_part = token.split(".")
        header = json.loads(decode_part(header_part))
        payload = json.loads(decode_part(payload_part))
        self.private_key.public_key().verify(
            decode_part(signature_part),
            f"{header_part}.{payload_part}".encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        self.assertEqual(header, {"alg": "RS256", "typ": "JWT"})
        self.assertEqual(payload, {"iat": 1_799_999_940, "exp": 1_800_000_540, "iss": "client-123"})
        self.assertLessEqual(payload["exp"] - payload["iat"], 600)

    def test_app_jwt_rejects_invalid_key_or_too_long_expiry(self):
        with self.assertRaisesRegex(ValueError, "PEM key"):
            create_github_app_jwt("client-123", b"not a PEM", now=100)
        with self.assertRaisesRegex(ValueError, "between 1 and 540"):
            create_github_app_jwt("client-123", self.private_pem, now=100, lifetime_seconds=541)

    def test_webhook_signature_uses_raw_bytes_and_sha256_constant_time_check(self):
        body = b'{"action":"opened","message":"hello \xe2\x9c\x93"}'
        secret = "synthetic-webhook-secret"
        import hashlib
        import hmac

        digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        self.assertTrue(verify_github_webhook_signature(body, f"sha256={digest}", secret))
        self.assertFalse(verify_github_webhook_signature(body + b" ", f"sha256={digest}", secret))
        self.assertFalse(verify_github_webhook_signature(body, f"sha1={digest}", secret))
        self.assertFalse(verify_github_webhook_signature(body, None, secret))
        self.assertFalse(verify_github_webhook_signature(body, f"sha256={digest}", ""))

    def test_installation_token_request_uses_jwt_least_privilege_and_optional_repo_scope(self):
        requests = []

        def handler(request: httpx.Request):
            requests.append(request)
            return httpx.Response(
                201,
                json={
                    "token": "synthetic-installation-token",
                    "expires_at": "2026-10-11T10:00:00Z",
                    "permissions": INSTALLATION_PERMISSIONS,
                    "repository_selection": "selected",
                },
                request=request,
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        result = create_installation_access_token(
            12345,
            "client-123",
            self.private_pem,
            repository_ids=[111, 222],
            client=client,
        )
        request = requests[0]
        sent = json.loads(request.content)
        self.assertEqual(request.method, "POST")
        self.assertEqual(str(request.url), "https://api.github.com/app/installations/12345/access_tokens")
        self.assertEqual(request.headers["Accept"], "application/vnd.github+json")
        self.assertEqual(request.headers["X-GitHub-Api-Version"], GITHUB_API_VERSION)
        self.assertTrue(request.headers["Authorization"].startswith("Bearer eyJ"))
        self.assertEqual(sent["repository_ids"], [111, 222])
        self.assertEqual(sent["permissions"], INSTALLATION_PERMISSIONS)
        self.assertEqual(result.token, "synthetic-installation-token")
        self.assertEqual(result.repository_selection, "selected")
        self.assertNotIn("synthetic-installation-token", repr(result))
        client.close()

    def test_installation_token_errors_are_sanitized_and_bad_ids_are_rejected(self):
        client = httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(401, text="sensitive provider response", request=request)
            )
        )
        with self.assertRaisesRegex(GitHubAppError, "HTTP 401") as error:
            create_installation_access_token(12345, "client-123", self.private_pem, client=client)
        self.assertNotIn("sensitive provider response", str(error.exception))
        with self.assertRaisesRegex(ValueError, "positive integer"):
            create_installation_access_token(-1, "client-123", self.private_pem, client=client)
        client.close()


if __name__ == "__main__":
    unittest.main()
