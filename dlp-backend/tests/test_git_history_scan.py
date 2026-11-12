from pathlib import Path
import subprocess
import tempfile
import unittest

from app.services.git_history_scan import scan_git_history


class GitHistoryScanTests(unittest.TestCase):
    def create_repository(self, root: Path) -> Path:
        root.mkdir()
        self.git(root, "init", "--initial-branch=main")
        self.git(root, "config", "user.name", "Synthetic Test Author")
        self.git(root, "config", "user.email", "synthetic@example.invalid")
        return root

    def git(self, root: Path, *args: str) -> str:
        completed = subprocess.run(
            ["git", *args], cwd=root, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True,
        )
        return completed.stdout.strip()

    def commit_file(self, root: Path, filename: str, content: str, message: str) -> str:
        path = root / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        self.git(root, "add", "--", filename)
        self.git(root, "commit", "-m", message)
        return self.git(root, "rev-parse", "HEAD")

    def test_finds_deleted_secret_at_first_added_line_with_commit_metadata(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = self.create_repository(Path(directory) / "repo")
            first = self.commit_file(root, "src/settings.py", "safe = True\nSYNTHETIC_SECRET=alpha\n", "add synthetic secret")
            self.commit_file(root, "src/settings.py", "safe = True\nSYNTHETIC_SECRET=alpha\nupdated = True\n", "unrelated edit")
            (root / "src/settings.py").unlink()
            self.git(root, "add", "-u")
            self.git(root, "commit", "-m", "delete synthetic secret")
            calls = []

            def detector(text, location):
                calls.append((text, location))
                return ["synthetic finding"] if "SYNTHETIC_SECRET" in text else []

            result = scan_git_history(root, repository="acme/repo", scan_added_text=detector)

        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.commit_sha, first)
        self.assertEqual(finding.author, "Synthetic Test Author")
        self.assertEqual(finding.file_path, "src/settings.py")
        self.assertEqual(finding.line_start, 2)
        self.assertFalse(finding.blob_version_in_head)
        self.assertEqual(finding.findings, ["synthetic finding"])
        self.assertNotIn("SYNTHETIC_SECRET", repr(finding))
        self.assertFalse(result.partial)

    def test_commit_limit_returns_resumable_cursor_without_skipping_commits(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = self.create_repository(Path(directory) / "repo")
            self.commit_file(root, "one.txt", "one\n", "one")
            self.commit_file(root, "two.txt", "two\n", "two")
            self.commit_file(root, "three.txt", "three\n", "three")
            first_page = scan_git_history(
                root, repository="acme/repo", scan_added_text=lambda *_: [], max_commits=1,
            )
            second_page = scan_git_history(
                root, repository="acme/repo", scan_added_text=lambda *_: [], max_commits=10,
                resume_after=first_page.resume_after,
            )
        self.assertTrue(first_page.partial)
        self.assertEqual(first_page.partial_reason, "Git history commit limit reached")
        self.assertIsNotNone(first_page.resume_after)
        self.assertEqual(first_page.commits_scanned, 1)
        self.assertEqual(second_page.commits_scanned, 2)
        self.assertFalse(second_page.partial)

    def test_force_push_cursor_restarts_history_and_reports_rewrite(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = self.create_repository(Path(directory) / "repo")
            self.commit_file(root, "one.txt", "one\n", "one")
            result = scan_git_history(
                root, repository="acme/repo", scan_added_text=lambda *_: [],
                resume_after="f" * 40,
            )
        self.assertTrue(result.force_push_detected)
        self.assertEqual(result.commits_scanned, 1)

    def test_lfs_pointer_and_dlpignore_content_are_not_scanned(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = self.create_repository(Path(directory) / "repo")
            self.commit_file(root, ".dlpignore", "ignored.txt\n", "configure ignore")
            self.commit_file(root, "ignored.txt", "SYNTHETIC_SECRET=ignored\n", "add ignored file")
            self.commit_file(
                root, "assets/large.dat",
                "version https://git-lfs.github.com/spec/v1\n"
                "oid sha256:" + "a" * 64 + "\nsize 99999999\n",
                "add LFS pointer",
            )
            scanned = []
            result = scan_git_history(
                root, repository="acme/repo",
                scan_added_text=lambda text, location: scanned.append((text, location)) or [],
            )
        self.assertFalse(result.findings)
        self.assertFalse(any("SYNTHETIC_SECRET" in text for text, _ in scanned))


if __name__ == "__main__":
    unittest.main()
