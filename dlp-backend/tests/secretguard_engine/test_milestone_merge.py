import base64
import json
import unittest

from secretguard.detectors import default_detectors
from secretguard.scanner import Scanner


def scan(text, hint="source.txt"):
    return Scanner(default_detectors()).scan_text(text, name=hint)


class MilestoneMergeTests(unittest.TestCase):
    def test_milestone_two_credentials_are_recognized_and_redacted(self):
        text = "aws=AKIA1234567890ABCDEF\nstripe=sk_live_abcdefghijklmnop1234\ngh=github_pat_" + "A1" * 20
        findings = scan(text)
        rules = {item.rule_id for item in findings}
        self.assertIn("secret.aws_access_key", rules)
        self.assertIn("secret.stripe_live_key", rules)
        self.assertIn("secret.github_token", rules)
        self.assertTrue(all("sha256:" in item.evidence for item in findings))
        self.assertNotIn("AKIA1234567890ABCDEF", str(findings))

    def test_database_uri_and_supabase_service_role_jwt(self):
        payload = base64.urlsafe_b64encode(json.dumps({"role": "service_role"}).encode()).decode().rstrip("=")
        token = "eyJhbGciOiJub25lIn0." + payload + ".signaturevalue12345678"
        findings = scan("DATABASE_URL=postgres://user:pass123456@db.example.test:5432/app\n" + token)
        self.assertIn("secret.database_uri", {item.rule_id for item in findings})
        self.assertIn("secret.supabase_service_role_jwt", {item.rule_id for item in findings})
        self.assertNotIn("pass123456", str(findings))
        self.assertNotIn(token, str(findings))

    def test_entropy_finding_avoids_uuid_hash_and_lockfile_noise(self):
        candidate = "aB3dEf7hJk9mNp2qRs4tUv6wXy8z"
        findings = scan("credential=" + candidate)
        self.assertTrue({item.rule_id for item in findings} & {"secret.high_entropy", "secret.entropy_generic"})
        self.assertEqual(scan(candidate, "package-lock.json"), [])


if __name__ == "__main__":
    unittest.main()
