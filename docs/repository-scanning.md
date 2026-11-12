# GitHub repository working-tree scanning

## Implemented service slice

`dlp-backend/app/services/repository_scan.py` owns a shallow GitHub clone,
working-tree enumeration, safe extraction, and cleanup. The caller supplies a
`scan_chunk(text, location)` callback so the authenticated P2 pipeline remains
the only place that resolves organization identity, runs policy, and records
events. This module does not expose an API route or persist integration tokens.

The clone uses the GitHub installation token in a temporary Git HTTP header
configuration passed through the child process environment. It is not included
in the remote URL, command arguments, output, or repository files. Git output is
discarded and failures return generic messages. Clones are shallow, have a
120-second Git operation timeout, and are deleted in a `finally` block. Cleanup
handles read-only `.git` files on Windows and reports failure if the checkout
still remains. The resulting metadata includes the resolved commit SHA.

The scanner skips `.git`, common generated/dependency directories, common lock
files, minified assets, symlinks, and unsupported/binary content. A repository
root `.dlpignore` adds newline-separated glob patterns; comments and blank lines
are ignored. Negation, absolute patterns, and parent traversal are rejected.
Each extracted file is parsed in the existing killable extraction subprocess.
Defaults cap a scan at 1,000 files, 200 MiB of working-tree file content, 25 MiB
per file, five minutes, and 10 seconds per file parser. Hitting the repository
file, byte, or time cap returns partial results with a reason.

## P2 and P4 integration still required

Before wiring this to a user-facing route, the route must authenticate and
resolve the organization server-side, authorize the repository against the
organization's GitHub installation, retrieve the installation token from P2's
vault, and pass the agreed repository channel/destination and principal into
P2's shared `scan()` callback. P2 owns the `dlp_integrations` schema and token
vault. P4 owns the repository-page components. A webhook must use durable,
idempotent delivery acceptance and the P4 incident handler before push events
can create incidents.

No live GitHub installation or clone has been attempted because this workspace
does not have a test App, installation token, or the required P2/P4 contracts.
The unit tests use synthetic repository contents and mocked clone transport.

Run from `dlp-backend/`:

```powershell
python -m unittest tests.test_repository_scan -v
```
