import json
import unittest

import httpx

from app.models.finding import DataType, Finding
from app.routers.github_webhooks import _delivery_from_payload
from fastapi import HTTPException
from app.services.github_app import GitHubAppError
from app.services.pr_check import (
    MAX_ANNOTATIONS,
    default_gate,
    evaluate_diff,
    parse_added_lines,
    pull_request_target,
    run_pr_check,
    validate_target,
)

SHA = "a" * 40
CARD = "4111" + "1111" + "1111" + "1111"
TOKEN = "ghs_" + "synthetictokenvalue000000000000000000"

DIFF = f"""diff --git a/app/pay.py b/app/pay.py
index 111..222 100644
--- a/app/pay.py
+++ b/app/pay.py
@@ -3,2 +3,4 @@ def pay():
 context line
-old = 1
+ok = 1
+card = "{CARD}"
 tail
diff --git a/old.py b/old.py
deleted file mode 100644
--- a/old.py
+++ /dev/null
@@ -1 +0,0 @@
-card = "{CARD}"
diff --git a/docs/a b.md b/docs/a b.md
new file mode 100644
--- /dev/null
+++ b/docs/a b.md\t
@@ -0,0 +1,2 @@
+hello
+contact someone@example.test
"""


def finding(kind=DataType.CREDIT_CARD, confidence=0.9, snippet="41***11"):
    return Finding(data_type=kind, confidence=confidence, matched_snippet=snippet)


def fake_detect(text):
    return [finding()] if CARD in text else ([finding(DataType.EMAIL_PII, 0.6, "so***st")] if "@" in text else [])


class EvaluateDiffTests(unittest.TestCase):
    def test_parser_gives_new_file_line_numbers_and_skips_deletions(self):
        lines = [(a.path, a.line, a.text) for a in parse_added_lines(DIFF)]
        self.assertEqual(lines, [
            ("app/pay.py", 4, "ok = 1"), ("app/pay.py", 5, f'card = "{CARD}"'),
            ("docs/a b.md", 1, "hello"), ("docs/a b.md", 2, "contact someone@example.test"),
        ])

    def test_blocking_value_is_annotated_on_the_right_line(self):
        result = evaluate_diff(DIFF, detect_fn=fake_detect)
        self.assertEqual(result.conclusion, "failure")
        by_path = {(a["path"], a["start_line"]): a for a in result.annotations}
        self.assertEqual(set(by_path), {("app/pay.py", 5), ("docs/a b.md", 2)})
        self.assertEqual(by_path[("app/pay.py", 5)]["annotation_level"], "failure")
        self.assertEqual(by_path[("docs/a b.md", 2)]["annotation_level"], "warning")
        self.assertNotIn(CARD, json.dumps(result.annotations))  # masked only
        self.assertEqual((result.blocked, result.warned, result.lines_scanned), (1, 1, 4))

    def test_warnings_only_is_neutral_and_clean_is_success(self):
        warn_only = "+++ b/x.md\n@@ -0,0 +1 @@\n+mail someone@example.test\n"
        self.assertEqual(evaluate_diff(warn_only, detect_fn=fake_detect).conclusion, "neutral")
        self.assertEqual(evaluate_diff("+++ b/x\n@@ -0,0 +1 @@\n+hello\n", detect_fn=fake_detect).conclusion, "success")
        self.assertEqual(evaluate_diff("", detect_fn=fake_detect).conclusion, "success")

    def test_annotation_cap_sets_partial_notice(self):
        body = "".join(f'+card = "{CARD}"\n' for _ in range(MAX_ANNOTATIONS + 5))
        diff = f"+++ b/big.py\n@@ -0,0 +1,{MAX_ANNOTATIONS + 5} @@\n{body}"
        result = evaluate_diff(diff, detect_fn=fake_detect)
        self.assertEqual(len(result.annotations), MAX_ANNOTATIONS)
        self.assertTrue(result.partial)
        self.assertEqual(result.blocked, MAX_ANNOTATIONS + 5)

    def test_default_detector_and_gate_catch_a_real_card(self):
        result = evaluate_diff(DIFF)
        self.assertEqual(result.conclusion, "failure")
        self.assertIn(("app/pay.py", 5), {(a["path"], a["start_line"]) for a in result.annotations})

    def test_gate_is_injectable(self):
        result = evaluate_diff(DIFF, detect_fn=fake_detect, gate_fn=lambda f: "allow")
        self.assertEqual((result.conclusion, result.annotations), ("success", []))
        self.assertEqual(default_gate([]), "allow")


class GitHubIoTests(unittest.TestCase):
    def make_client(self, diff_status=200, diff_body=DIFF, check_status=201):
        self.calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            self.calls.append(request)
            if request.method == "GET":
                return httpx.Response(diff_status, text=diff_body)
            return httpx.Response(check_status, json={"id": 77})

        return httpx.Client(transport=httpx.MockTransport(handler))

    def test_full_run_creates_failing_check_with_annotation(self):
        with self.make_client() as client:
            result = run_pr_check(token=TOKEN, repo_full_name="acme/repo", pr_number=12, head_sha=SHA,
                                  client=client, detect_fn=fake_detect)
        self.assertEqual(result.conclusion, "failure")
        get, post = self.calls
        self.assertEqual(get.url.path, "/repos/acme/repo/pulls/12")
        self.assertEqual(get.headers["accept"], "application/vnd.github.diff")
        self.assertEqual(post.url.path, "/repos/acme/repo/check-runs")
        sent = json.loads(post.content)
        self.assertEqual((sent["head_sha"], sent["conclusion"], sent["status"]), (SHA, "failure", "completed"))
        self.assertEqual(sent["output"]["annotations"][0]["start_line"], 5)
        self.assertTrue(all(TOKEN not in str(c.url) for c in self.calls))
        self.assertNotIn(CARD, post.content.decode())

    def test_annotations_are_sent_in_batches_of_fifty(self):
        body = "".join(f'+card = "{CARD}"\n' for _ in range(120))
        diff = f"+++ b/big.py\n@@ -0,0 +1,120 @@\n{body}"
        with self.make_client(diff_body=diff) as client:
            run_pr_check(token=TOKEN, repo_full_name="acme/repo", pr_number=1, head_sha=SHA,
                         client=client, detect_fn=fake_detect)
        posts = [c for c in self.calls if c.method != "GET"]
        self.assertEqual([c.method for c in posts], ["POST", "PATCH", "PATCH"])
        self.assertEqual([len(json.loads(c.content)["output"]["annotations"]) for c in posts], [50, 50, 20])
        self.assertEqual(posts[1].url.path, "/repos/acme/repo/check-runs/77")

    def test_diff_failure_publishes_fail_closed_check_and_raises(self):
        with self.make_client(diff_status=404) as client:
            with self.assertRaises(GitHubAppError):
                run_pr_check(token=TOKEN, repo_full_name="acme/repo", pr_number=1, head_sha=SHA,
                             client=client, detect_fn=fake_detect)
        sent = json.loads(self.calls[-1].content)
        self.assertEqual(sent["conclusion"], "failure")
        self.assertIn("could not scan", sent["output"]["title"])

    def test_oversized_diff_is_rejected(self):
        from app.services import pr_check

        old = pr_check.MAX_DIFF_BYTES
        pr_check.MAX_DIFF_BYTES = 100
        try:
            with self.make_client(diff_body="x" * 500) as client:
                with self.assertRaises(GitHubAppError):
                    run_pr_check(token=TOKEN, repo_full_name="acme/repo", pr_number=1, head_sha=SHA, client=client)
        finally:
            pr_check.MAX_DIFF_BYTES = old

    def test_check_run_http_error_is_sanitised(self):
        with self.make_client(check_status=403) as client:
            with self.assertRaises(GitHubAppError) as ctx:
                run_pr_check(token=TOKEN, repo_full_name="acme/repo", pr_number=1, head_sha=SHA,
                             client=client, detect_fn=fake_detect)
        self.assertNotIn(TOKEN, str(ctx.exception))

    def test_target_validation(self):
        for bad in (("acme", 1, SHA), ("acme/repo", 0, SHA), ("acme/repo", True, SHA), ("acme/repo", 1, "xyz"),
                    ("../etc/passwd", 1, SHA)):
            with self.assertRaises(ValueError):
                validate_target(*bad)
        validate_target("acme/repo", 1, SHA)


class WebhookIntakeTests(unittest.TestCase):
    payload = {
        "action": "synchronize", "installation": {"id": 5},
        "repository": {"id": 9, "full_name": "acme/repo"},
        "pull_request": {"number": 3, "head": {"sha": SHA.upper()}},
    }

    def test_target_extracted_and_lowercased(self):
        self.assertEqual(pull_request_target(self.payload), ("acme/repo", 3, SHA))
        self.assertIsNone(pull_request_target({**self.payload, "action": "closed"}))
        self.assertIsNone(pull_request_target({**self.payload, "pull_request": {"number": 3, "head": {"sha": "bad"}}}))

    def test_delivery_carries_pr_ref_and_head_sha_only(self):
        delivery = _delivery_from_payload("d-1", "pull_request", self.payload, "k")
        self.assertEqual((delivery.ref, delivery.after_sha, delivery.repository_full_name),
                         ("refs/pull/3/head", SHA, "acme/repo"))

    def test_invalid_pr_metadata_is_400(self):
        with self.assertRaises(HTTPException) as ctx:
            _delivery_from_payload("d-1", "pull_request", {**self.payload, "pull_request": {}}, "k")
        self.assertEqual(ctx.exception.status_code, 400)


if __name__ == "__main__":
    unittest.main()
