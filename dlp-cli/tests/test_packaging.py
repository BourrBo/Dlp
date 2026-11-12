import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RUN_SH = ROOT / "dlp-cli" / "action" / "run.sh"


def version_of(pyproject: Path) -> str:
    return re.search(r'^version = "([^"]+)"', pyproject.read_text(encoding="utf-8"), re.M).group(1)


def test_root_shim_and_package_versions_match_and_match_module():
    from dlp_cli import __version__

    assert version_of(ROOT / "pyproject.toml") == version_of(ROOT / "dlp-cli" / "pyproject.toml") == __version__


def test_pre_commit_hook_definition():
    text = (ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8")
    assert "id: dlp-scan" in text and "pass_filenames: false" in text and "dlp scan --staged" in text


def test_action_yaml_is_valid_and_uses_env_not_inline_inputs():
    yaml = pytest.importorskip("yaml")
    doc = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    assert doc["runs"]["using"] == "composite"
    scan = next(s for s in doc["runs"]["steps"] if s.get("id") == "scan")
    assert "${{" not in scan["run"] and scan["env"]["DLP_FAIL_ON"] == "${{ inputs.fail-on }}"
    assert set(doc["inputs"]) >= {"mode", "path", "fail-on", "sarif-file", "upload-sarif"}


@pytest.mark.skipif(os.name == "nt", reason="bash script")
class TestActionScript:
    def run(self, cwd, **env):
        full = {**os.environ, **env, "GITHUB_OUTPUT": str(cwd / "gh_output")}
        return subprocess.run(["bash", str(RUN_SH)], cwd=cwd, env=full, capture_output=True, text=True)

    def test_path_mode_fails_on_finding_and_writes_sarif_and_outputs(self, tmp_path):
        (tmp_path / "a.py").write_text('k = "' + "AKIA" + "IOSFODNN7" + 'EXAMPLE"\n')
        proc = self.run(tmp_path, DLP_MODE="path", DLP_PATH=".")
        assert proc.returncode == 1
        assert '"version": "2.1.0"' in (tmp_path / "dlp.sarif").read_text()
        assert "exit-code=1" in (tmp_path / "gh_output").read_text()

    def test_clean_path_passes(self, tmp_path):
        (tmp_path / "a.py").write_text("print(1)\n")
        assert self.run(tmp_path).returncode == 0

    def test_rejects_bad_inputs(self, tmp_path):
        assert self.run(tmp_path, DLP_FAIL_ON="nope").returncode == 2
        assert self.run(tmp_path, DLP_MODE="range", DLP_BASE_SHA="; rm -rf /").returncode == 2
        assert self.run(tmp_path, DLP_MODE="weird").returncode == 2

    def test_range_mode_scans_pr_commits(self, tmp_path):
        def git(*a):
            return subprocess.run(["git", *a], cwd=tmp_path, check=True, capture_output=True, text=True).stdout.strip()

        git("init", "-q"); git("config", "user.email", "t@e.test"); git("config", "user.name", "T"); git("config", "commit.gpgsign", "false")
        (tmp_path / "a.txt").write_text("base\n"); git("add", "."); git("commit", "-qm", "base")
        base = git("rev-parse", "HEAD")
        (tmp_path / "a.txt").write_text("card 4111 1111 1111 1111\n"); git("commit", "-qam", "pr")
        head = git("rev-parse", "HEAD")
        assert self.run(tmp_path, DLP_MODE="range", DLP_BASE_SHA=base, DLP_HEAD_SHA=head).returncode == 1
        assert self.run(tmp_path, DLP_MODE="range", DLP_BASE_SHA=head, DLP_HEAD_SHA=head).returncode == 0
