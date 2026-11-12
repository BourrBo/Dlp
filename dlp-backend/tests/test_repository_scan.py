import base64
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.services.repository_scan import (
    RepositoryScanError,
    _git_environment,
    clone_and_scan_github_repository,
    scan_checkout,
)


class RepositoryScanTests(unittest.TestCase):
    def make_repo(self, root: Path) -> Path:
        root.mkdir()
        (root / "README.md").write_text("contact person@example.com\n", encoding="utf-8")
        (root / "src").mkdir()
        (root / "src" / "app.py").write_text("support support@example.com\n", encoding="utf-8")
        (root / "credentials.txt").write_text("hidden@example.com\n", encoding="utf-8")
        (root / "vendor").mkdir()
        (root / "vendor" / "bundled.txt").write_text("vendor@example.com", encoding="utf-8")
        (root / "node_modules").mkdir()
        (root / "node_modules" / "module.txt").write_text("module@example.com", encoding="utf-8")
        (root / "application.lock").write_text("lock@example.com", encoding="utf-8")
        (root / ".dlpignore").write_text("credentials.txt\n", encoding="utf-8")
        return root

    def test_scan_checkout_applies_defaults_and_dlpignore_and_returns_locations(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = self.make_repo(Path(directory) / "repo")
            scanned = []
            result = scan_checkout(
                root,
                repository="owner/repo",
                ref="main",
                scan_chunk=lambda text, location: scanned.append((text, location)) or "finding",
            )
        paths = {file.path for file in result.files}
        self.assertEqual(paths, {"README.md", "src/app.py"})
        self.assertEqual(len(scanned), 2)
        self.assertIn("person@example.com", scanned[0][0])
        self.assertTrue(scanned[0][1].startswith('README.md:{"'))
        self.assertEqual(result.findings, ["finding", "finding"])
        self.assertFalse(result.partial)

    def test_scan_stops_at_file_limit_and_marks_partial_results(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = self.make_repo(Path(directory) / "repo")
            result = scan_checkout(
                root, repository="owner/repo", ref="main", scan_chunk=lambda text, location: None,
                max_files=1,
            )
        self.assertTrue(result.partial)
        self.assertEqual(result.partial_reason, "Repository file limit reached")
        self.assertEqual(result.files_scanned, 1)

    def test_unsafe_ignore_pattern_fails_closed(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = self.make_repo(Path(directory) / "repo")
            (root / ".dlpignore").write_text("../outside.txt\n", encoding="utf-8")
            with self.assertRaises(RepositoryScanError):
                scan_checkout(root, repository="owner/repo", ref="main", scan_chunk=lambda *_: None)

    def test_git_token_is_passed_as_header_configuration_not_remote_url(self):
        env = _git_environment("installation-secret")
        self.assertEqual(env["GIT_CONFIG_KEY_0"], "http.https://github.com/.extraheader")
        self.assertEqual(
            env["GIT_CONFIG_VALUE_0"],
            "AUTHORIZATION: basic " + base64.b64encode(b"x-access-token:installation-secret").decode(),
        )
        self.assertNotIn("installation-secret", env["GIT_CONFIG_VALUE_0"])
        with self.assertRaises(ValueError):
            _git_environment("bad\ntoken")

    def test_repository_and_ref_inputs_reject_option_injection(self):
        with self.assertRaises(ValueError):
            clone_and_scan_github_repository("owner", "../repo", "token", scan_chunk=lambda *_: None)
        with self.assertRaises(ValueError):
            clone_and_scan_github_repository("owner", "repo", "token", ref="--upload-pack=bad", scan_chunk=lambda *_: None)

    def test_shallow_clone_lifecycle_scans_then_removes_checkout(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            parent = Path(directory)

            def fake_git(args, *, cwd, env, timeout):
                self.assertIsNone(cwd)
                self.assertEqual(args[:3], ["clone", "--depth", "1"])
                self.assertNotIn("token", " ".join(args))
                checkout = Path(args[-1])
                (checkout / "README.md").write_text("person@example.com", encoding="utf-8")

            with patch("app.services.repository_scan._run_git", side_effect=fake_git), patch(
                "app.services.repository_scan._read_head_sha", return_value="a" * 40,
            ):
                result = clone_and_scan_github_repository(
                    "owner", "repo", "token", scan_chunk=lambda text, location: "scanned",
                    ref="HEAD", temp_root=parent,
                )
            self.assertEqual(result.repository, "owner/repo")
            self.assertEqual(result.commit_sha, "a" * 40)
            self.assertEqual(result.files_scanned, 1)
            self.assertEqual(result.findings, ["scanned"])
            self.assertEqual(list(parent.iterdir()), [])

    def test_failed_clone_also_removes_checkout(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            parent = Path(directory)
            with patch("app.services.repository_scan._run_git", side_effect=RepositoryScanError("clone failed")):
                with self.assertRaises(RepositoryScanError):
                    clone_and_scan_github_repository(
                        "owner", "repo", "token", scan_chunk=lambda *_: None, temp_root=parent,
                    )
            self.assertEqual(list(parent.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
