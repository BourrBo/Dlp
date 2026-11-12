import subprocess
from pathlib import Path

import pytest

from dlp_cli.detectors import verhoeff_ok


def make_aadhaar(prefix11: str) -> str:
    for check in "0123456789":
        if verhoeff_ok(prefix11 + check):
            return prefix11 + check
    raise AssertionError


def make_card() -> str:
    return "4111" + "1111" + "1111" + "1111"  # documented Visa test number


def make_aws_key() -> str:
    return "AKIA" + "IOSFODNN7" + "EXAMPLE"


def make_github_token() -> str:
    return "ghp_" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jL5"


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout


@pytest.fixture
def repo(tmp_path: Path):
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.email", "t@example.test")
    git(tmp_path, "config", "user.name", "Test")
    git(tmp_path, "config", "commit.gpgsign", "false")
    return tmp_path
