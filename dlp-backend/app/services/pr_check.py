"""Pull-request check run: scan added lines and annotate the exact line.

Flow: fetch the PR diff -> parse added lines with new-file line numbers ->
detect (P1 detector, via the injectable ``detect_fn``) -> decide (P2 gate, via
the injectable ``gate_fn``) -> create a GitHub check run with annotations.

Only masked snippets leave this module. Installation tokens are passed in by
the caller, used for the two API calls and never stored, logged or put in URLs.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Iterable, Iterator

import httpx

from app.models.finding import Finding
from app.services.github_app import GITHUB_API_BASE, GITHUB_API_VERSION, GitHubAppError

CHECK_NAME = "DLP scan"
MAX_DIFF_BYTES = 5 * 1024 * 1024
MAX_SCANNED_LINES = 200_000
MAX_ANNOTATIONS = 500
ANNOTATIONS_PER_REQUEST = 50  # GitHub limit per create/update call
_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_SHA = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_HUNK = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

DetectFn = Callable[[str], list[Finding]]
GateFn = Callable[[list[Finding]], str]  # returns "block" | "warn" | "allow"


@dataclass(frozen=True)
class AddedLine:
    path: str
    line: int
    text: str


@dataclass
class PrCheckResult:
    conclusion: str  # success | neutral | failure
    annotations: list[dict] = field(default_factory=list)
    blocked: int = 0
    warned: int = 0
    lines_scanned: int = 0
    partial: bool = False


def default_gate(findings: list[Finding]) -> str:
    """Conservative stand-in until P2's gate API is wired in (plan W6)."""
    if any(f.confidence >= 0.85 for f in findings):
        return "block"
    return "warn" if findings else "allow"


def default_detect(text: str) -> list[Finding]:
    from app.services.detection_service import detect

    return detect(text)


def parse_added_lines(diff_text: str) -> Iterator[AddedLine]:
    """Added lines of a unified diff (any context size) with new-file numbers."""
    path: str | None = None
    new_line = old_left = new_left = 0
    for raw in diff_text.split("\n"):
        if old_left <= 0 and new_left <= 0:
            if raw.startswith("diff --git "):
                path = None
            elif raw.startswith("+++ "):
                target = raw[4:].rstrip("\t").rstrip("\r")
                path = None if target == "/dev/null" else (target[2:] if target.startswith("b/") else target.strip('"'))
            else:
                m = _HUNK.match(raw)
                if m:
                    old_left = int(m.group(1)) if m.group(1) is not None else 1
                    new_line = int(m.group(2))
                    new_left = int(m.group(3)) if m.group(3) is not None else 1
            continue
        if raw.startswith("\\"):
            continue
        if raw.startswith("+"):
            if path is not None:
                yield AddedLine(path, new_line, raw[1:].rstrip("\r"))
            new_line += 1
            new_left -= 1
        elif raw.startswith("-"):
            old_left -= 1
        else:
            new_line += 1
            new_left -= 1
            old_left -= 1


def evaluate_diff(
    diff_text: str,
    *,
    detect_fn: DetectFn = default_detect,
    gate_fn: GateFn = default_gate,
) -> PrCheckResult:
    per_line: dict[tuple[str, int], list[Finding]] = defaultdict(list)
    scanned = 0
    partial = False
    for added in parse_added_lines(diff_text):
        if scanned >= MAX_SCANNED_LINES:
            partial = True
            break
        scanned += 1
        found = detect_fn(added.text)
        if found:
            per_line[(added.path, added.line)].extend(found)

    annotations: list[dict] = []
    blocked = warned = 0
    for (path, line), findings in sorted(per_line.items()):
        decision = gate_fn(findings)
        if decision == "allow":
            continue
        if decision == "block":
            blocked += 1
        else:
            warned += 1
        if len(annotations) >= MAX_ANNOTATIONS:
            partial = True
            continue
        kinds = ", ".join(sorted({f.data_type.value for f in findings}))
        masked = ", ".join(sorted({f.matched_snippet for f in findings}))
        annotations.append({
            "path": path,
            "start_line": line,
            "end_line": line,
            "annotation_level": "failure" if decision == "block" else "warning",
            "title": f"DLP: {kinds}",
            "message": f"Sensitive data detected ({masked}). Remove it or use synthetic data; "
                       "a value that reached a branch must be treated as exposed and rotated.",
        })
    conclusion = "failure" if blocked else ("neutral" if warned else "success")
    return PrCheckResult(conclusion, annotations, blocked, warned, scanned, partial)


# ---------------------------------------------------------------- GitHub I/O


def _headers(token: str, accept: str = "application/vnd.github+json") -> dict[str, str]:
    return {"Accept": accept, "Authorization": f"Bearer {token}", "X-GitHub-Api-Version": GITHUB_API_VERSION}


def validate_target(repo_full_name: str, pr_number: int, head_sha: str) -> None:
    if not isinstance(repo_full_name, str) or not _REPO.fullmatch(repo_full_name):
        raise ValueError("Invalid repository name")
    if isinstance(pr_number, bool) or not isinstance(pr_number, int) or pr_number <= 0:
        raise ValueError("Invalid pull request number")
    if not isinstance(head_sha, str) or not _SHA.fullmatch(head_sha):
        raise ValueError("Invalid head SHA")


def fetch_pr_diff(client: httpx.Client, token: str, repo_full_name: str, pr_number: int) -> str:
    url = f"{GITHUB_API_BASE}/repos/{repo_full_name}/pulls/{pr_number}"
    try:
        with client.stream("GET", url, headers=_headers(token, "application/vnd.github.diff")) as response:
            if response.status_code != 200:
                raise GitHubAppError(f"GitHub pull-request diff request failed with HTTP {response.status_code}")
            body = bytearray()
            for part in response.iter_bytes():
                body.extend(part)
                if len(body) > MAX_DIFF_BYTES:
                    raise GitHubAppError("Pull-request diff is larger than the scan limit")
    except httpx.HTTPError as exc:
        raise GitHubAppError("GitHub pull-request diff request failed") from exc
    return body.decode("utf-8", "replace")


def _summary(result: PrCheckResult) -> str:
    text = (f"Scanned {result.lines_scanned} added line(s): {result.blocked} blocking, "
            f"{result.warned} warning(s). Values are masked.")
    if result.partial:
        text += " Partial results: scan limits were reached."
    return text


def _post(client: httpx.Client, method: str, url: str, token: str, payload: dict) -> dict:
    try:
        response = client.request(method, url, headers=_headers(token), json=payload)
    except httpx.HTTPError as exc:
        raise GitHubAppError("GitHub check-run request failed") from exc
    if response.status_code not in (200, 201):
        raise GitHubAppError(f"GitHub check-run request failed with HTTP {response.status_code}")
    try:
        return response.json()
    except ValueError as exc:
        raise GitHubAppError("GitHub returned an invalid check-run response") from exc


def publish_check_run(
    client: httpx.Client, token: str, repo_full_name: str, head_sha: str, result: PrCheckResult
) -> int:
    """Create the completed check run, adding annotations 50 at a time."""
    chunks = [result.annotations[i:i + ANNOTATIONS_PER_REQUEST]
              for i in range(0, len(result.annotations), ANNOTATIONS_PER_REQUEST)] or [[]]
    title = {"failure": "Sensitive data found", "neutral": "Warnings only", "success": "No sensitive data found"}[result.conclusion]

    def output(batch: list[dict]) -> dict:
        return {"title": title, "summary": _summary(result), "annotations": batch}

    base = f"{GITHUB_API_BASE}/repos/{repo_full_name}/check-runs"
    created = _post(client, "POST", base, token, {
        "name": CHECK_NAME, "head_sha": head_sha, "status": "completed",
        "conclusion": result.conclusion, "output": output(chunks[0]),
    })
    run_id = created.get("id")
    if isinstance(run_id, bool) or not isinstance(run_id, int):
        raise GitHubAppError("GitHub returned an invalid check-run response")
    for batch in chunks[1:]:
        _post(client, "PATCH", f"{base}/{run_id}", token, {"output": output(batch)})
    return run_id


def publish_scan_failure(client: httpx.Client, token: str, repo_full_name: str, head_sha: str) -> int:
    """Fail closed with a generic message when the scan itself could not run."""
    failed = PrCheckResult("failure")
    failed.partial = True
    base = f"{GITHUB_API_BASE}/repos/{repo_full_name}/check-runs"
    created = _post(client, "POST", base, token, {
        "name": CHECK_NAME, "head_sha": head_sha, "status": "completed", "conclusion": "failure",
        "output": {"title": "DLP could not scan this pull request",
                   "summary": "The scan did not complete, so this change is treated as unchecked. Re-run the check."},
    })
    return int(created.get("id", 0))


def run_pr_check(
    *,
    token: str,
    repo_full_name: str,
    pr_number: int,
    head_sha: str,
    client: httpx.Client | None = None,
    detect_fn: DetectFn = default_detect,
    gate_fn: GateFn = default_gate,
) -> PrCheckResult:
    validate_target(repo_full_name, pr_number, head_sha)
    owned = client is None
    http = client or httpx.Client(timeout=20.0)
    try:
        try:
            diff = fetch_pr_diff(http, token, repo_full_name, pr_number)
            result = evaluate_diff(diff, detect_fn=detect_fn, gate_fn=gate_fn)
        except GitHubAppError:
            publish_scan_failure(http, token, repo_full_name, head_sha)
            raise
        publish_check_run(http, token, repo_full_name, head_sha, result)
        return result
    finally:
        if owned:
            http.close()


def pull_request_target(payload: dict) -> tuple[str, int, str] | None:
    """(repo, number, head_sha) for opened/synchronize/reopened events, else None."""
    if payload.get("action") not in {"opened", "synchronize", "reopened"}:
        return None
    pr, repo = payload.get("pull_request"), payload.get("repository")
    if not isinstance(pr, dict) or not isinstance(repo, dict):
        return None
    head = pr.get("head")
    sha = head.get("sha") if isinstance(head, dict) else None
    number, name = pr.get("number"), repo.get("full_name")
    try:
        validate_target(name, number, sha.lower() if isinstance(sha, str) else sha)
    except ValueError:
        return None
    return name, number, sha.lower()
