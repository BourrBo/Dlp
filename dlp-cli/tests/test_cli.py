import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import jsonschema
import pytest

from conftest import git, make_aadhaar, make_aws_key, make_card, make_github_token
from dlp_cli.cli import main

SCHEMA = json.loads((Path(__file__).parent / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))


def run(args, cwd, capsys):
    old = Path.cwd()
    os.chdir(cwd)
    try:
        code = main(args)
    finally:
        os.chdir(old)
    out = capsys.readouterr()
    return code, out.out, out.err


def test_commit_with_fake_card_is_blocked_and_clean_commit_passes(repo, capsys):
    (repo / "ok.py").write_text("print('hello')\n")
    git(repo, "add", "ok.py")
    code, out, _ = run(["scan", "--staged"], repo, capsys)
    assert code == 0 and "0 finding(s)" in out

    (repo / "pay.py").write_text(f'card = "{make_card()}"\n')
    git(repo, "add", "pay.py")
    code, out, _ = run(["scan", "--staged"], repo, capsys)
    assert code == 1 and "pay.py:1:9" in out and "DLP009" in out
    assert make_card() not in out


def test_staged_scan_only_reports_added_lines_and_is_fast(repo, capsys):
    (repo / "big.py").write_text("".join(f"x{i} = {i}\n" for i in range(3000)) + f'k = "{make_aws_key()}"\n')
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "base", "--no-verify")  # old secret already in history
    with (repo / "big.py").open("a") as fh:
        fh.write("y = 1\n")
    git(repo, "add", ".")
    started = time.perf_counter()
    code, out, _ = run(["scan", "--staged"], repo, capsys)
    assert time.perf_counter() - started < 2.0
    assert code == 0 and "1 line(s) scanned" in out


def test_git_range_finds_secret_added_then_deleted_with_commit(repo, capsys):
    (repo / "a.txt").write_text("start\n")
    git(repo, "add", "."); git(repo, "commit", "-qm", "c0")
    base = git(repo, "rev-parse", "HEAD").strip()
    (repo / "a.txt").write_text(f"token={make_github_token()}\n")
    git(repo, "commit", "-qam", "oops")
    leaked = git(repo, "rev-parse", "HEAD").strip()
    (repo / "a.txt").write_text("clean\n")
    git(repo, "commit", "-qam", "remove it")
    code, out, _ = run(["scan", "--git-range", f"{base}..HEAD", "--format", "json"], repo, capsys)
    data = json.loads(out)
    assert code == 1
    [f] = data["findings"]
    assert f["commit"] == leaked and f["path"] == "a.txt" and f["line"] == 1 and f["rule_id"] == "DLP004"
    assert make_github_token() not in out


def test_path_scan_defaults_and_ignore_file(repo, capsys):
    secret = f'k = "{make_aws_key()}"\n'
    (repo / "src").mkdir(); (repo / "src" / "app.py").write_text(secret)
    (repo / "node_modules" / "x").mkdir(parents=True); (repo / "node_modules" / "x" / "i.js").write_text(secret)
    (repo / "package-lock.json").write_text(secret)
    (repo / "app.min.js").write_text(secret)
    (repo / "logo.png").write_bytes(b"\x89PNG\x00" + secret.encode())
    (repo / "blob.dat").write_bytes(b"\x00\x01" + secret.encode())
    (repo / "legacy").mkdir(); (repo / "legacy" / "old.py").write_text(secret)
    (repo / ".dlpignore").write_text("legacy/\n")
    (repo / "utf16.txt").write_bytes(b"\xff\xfe" + secret.encode("utf-16-le"))
    (repo / "huge.txt").write_text("a" * 50 + secret)
    code, out, _ = run(["scan", "--path", ".", "--format", "json"], repo, capsys)
    data = json.loads(out)
    assert code == 1
    assert sorted(f["path"] for f in data["findings"]) == ["huge.txt", "src/app.py", "utf16.txt"]
    reasons = {s["path"]: s["reason"] for s in data["skipped"]}
    assert "lockfile" in reasons["package-lock.json"]
    assert "minified" in reasons["app.min.js"]
    assert "binary" in reasons["logo.png"] and reasons["blob.dat"] == "binary file"
    assert reasons["legacy/"].startswith("excluded by .dlpignore")
    assert "node_modules/" in reasons


def test_size_limit_and_symlink_skipped(repo, capsys):
    (repo / "big.txt").write_text(f'{make_aws_key()}\n' + "z" * 5000)
    (repo / ".dlp.toml").write_text("max_file_bytes = 1000\n")
    real = repo / "real.txt"; real.write_text(make_aws_key())
    try:
        (repo / "link.txt").symlink_to(real)
    except OSError:
        pytest.skip("symlinks unavailable")
    code, out, _ = run(["scan", "--path", ".", "--format", "json"], repo, capsys)
    data = json.loads(out)
    assert {f["path"] for f in data["findings"]} == {"real.txt"}
    reasons = {s["path"]: s["reason"] for s in data["skipped"]}
    assert "larger than 1000" in reasons["big.txt"] and reasons["link.txt"] == "symbolic link"


def test_allowlist_inline_fingerprint_and_path(repo, capsys):
    (repo / "a.py").write_text(f'x = "{make_aws_key()}"  # dlp:allow\n')
    (repo / "fixtures").mkdir(); (repo / "fixtures" / "b.py").write_text(f'x = "{make_aws_key()}"\n')
    (repo / ".dlp.toml").write_text('[allowlist]\npaths = ["fixtures/"]\n')
    code, out, _ = run(["scan", "--path", "."], repo, capsys)
    assert code == 0
    (repo / "c.py").write_text(f'x = "{make_card()}"\n')
    code, out, _ = run(["scan", "--path", "c.py", "--format", "json"], repo, capsys)
    fp = json.loads(out)["findings"][0]["fingerprint"]
    (repo / ".dlp.toml").write_text(f'[allowlist]\nfingerprints = ["{fp}"]\n')
    code, _, _ = run(["scan", "--path", "c.py"], repo, capsys)
    assert code == 0


def test_fail_on_threshold_and_disable_rules(repo, capsys):
    (repo / "m.txt").write_text("mail someone@example.test\n")
    assert run(["scan", "--path", "m.txt"], repo, capsys)[0] == 0          # low < medium
    assert run(["scan", "--path", "m.txt", "--fail-on", "low"], repo, capsys)[0] == 1
    (repo / ".dlp.toml").write_text('fail_on = "low"\ndisable_rules = ["DLP012"]\n')
    assert run(["scan", "--path", "m.txt"], repo, capsys)[0] == 0


def test_sarif_validates_and_contains_no_raw_values(repo, capsys):
    (repo / "a.py").write_text(f'k = "{make_aws_key()}"\nc = "{make_card()}"\nm = "x@example.test"\n')
    out_file = repo / "out.sarif"
    code, _, _ = run(["scan", "--path", "a.py", "--format", "sarif", "--output", str(out_file)], repo, capsys)
    assert code == 1
    doc = json.loads(out_file.read_text(encoding="utf-8"))
    jsonschema.validate(doc, SCHEMA)
    results = doc["runs"][0]["results"]
    assert {(r["ruleId"], r["locations"][0]["physicalLocation"]["region"]["startLine"]) for r in results} == {
        ("DLP002", 1), ("DLP009", 2), ("DLP012", 3)}
    assert {r["level"] for r in results} == {"error", "note"}
    text = out_file.read_text()
    assert make_aws_key() not in text and make_card() not in text


def test_sarif_for_empty_scan_is_valid(repo, capsys):
    (repo / "a.txt").write_text("nothing here\n")
    code, out, _ = run(["scan", "--path", "a.txt", "--format", "sarif"], repo, capsys)
    assert code == 0
    jsonschema.validate(json.loads(out), SCHEMA)


def test_aadhaar_in_file(repo, capsys):
    (repo / "kyc.csv").write_text(f"name,id\nA,{make_aadhaar('23456789012')}\n")
    code, out, _ = run(["scan", "--path", "kyc.csv", "--format", "json"], repo, capsys)
    assert code == 1 and json.loads(out)["findings"][0]["line"] == 2


def test_errors_use_documented_exit_codes(repo, tmp_path_factory, capsys):
    (repo / ".dlp.toml").write_text("nonsense = 1\n")
    assert run(["scan", "--path", "."], repo, capsys)[0] == 2
    (repo / ".dlp.toml").write_text('fail_on = "extreme"\n')
    assert run(["scan", "--path", "."], repo, capsys)[0] == 2
    (repo / ".dlp.toml").unlink()
    outside = tmp_path_factory.mktemp("not_a_repo")
    code, _, err = run(["scan", "--staged"], outside, capsys)
    assert code == 3 and "git error" in err
    (repo / "t.txt").write_text("x")
    assert run(["scan", "--git-range", "doesnotexist..HEAD"], repo, capsys)[0] == 3


def test_missing_path_is_reported_not_crashing(repo, capsys):
    code, out, _ = run(["scan", "--path", "nope.txt", "--format", "json"], repo, capsys)
    assert code == 0 and json.loads(out)["skipped"][0]["reason"] == "path does not exist"


def test_quiet_prints_nothing_when_clean(repo, capsys):
    (repo / "a.txt").write_text("fine\n")
    code, out, _ = run(["scan", "--path", "a.txt", "--quiet"], repo, capsys)
    assert code == 0 and out == ""


def test_sync_allowlist_from_local_server(repo, capsys):
    class Handler(BaseHTTPRequestHandler):
        seen_auth = None

        def do_GET(self):
            Handler.seen_auth = self.headers.get("Authorization")
            body = json.dumps({"fingerprints": ["0123456789abcdef", "not-valid", 5]}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        code, out, _ = run(["sync-allowlist", "--server", f"http://127.0.0.1:{server.server_port}", "--api-key", "k1"], repo, capsys)
    finally:
        server.shutdown()
    assert code == 0 and Handler.seen_auth == "Bearer k1"
    cache = json.loads((repo / ".dlp-allowlist.json").read_text())
    assert cache["fingerprints"] == ["0123456789abcdef"]


def test_sync_allowlist_refuses_plain_http_and_missing_key(repo, capsys, monkeypatch):
    monkeypatch.delenv("DLP_API_KEY", raising=False)
    assert run(["sync-allowlist", "--server", "https://dlp.example.test"], repo, capsys)[0] == 2
    assert run(["sync-allowlist", "--server", "http://dlp.example.test", "--api-key", "k"], repo, capsys)[0] == 2


def test_runs_as_module_and_scan_never_touches_network(repo, monkeypatch):
    (repo / "a.txt").write_text("fine\n")
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).parents[1])}
    proc = subprocess.run([sys.executable, "-m", "dlp_cli", "scan", "--path", "a.txt"], cwd=repo, env=env,
                          capture_output=True, text=True)
    assert proc.returncode == 0
    src = (Path(__file__).parents[1] / "dlp_cli" / "scanner.py").read_text()
    assert "urllib" not in src and "socket" not in src and "requests" not in src
