# Git history scanning (P3 W20-21)

## Implemented scanner slice

`dlp-backend/app/services/git_history_scan.py` scans an existing local Git
working tree in chronological commit order. It requests zero-context diffs,
passes added lines to an injected detector callback, and records only callback
findings plus masked provenance metadata: blob SHA, commit SHA, sanitized author,
authored date, file path, and added line. It deduplicates identical file blobs
within a scan. Deleted content is still examined at the commit where it was
added. `.dlpignore` and the repository scanner's default exclusions apply.

The callback must return masked detector results only. This module does not
persist raw patch text or call policy itself. Binary blobs, symlinks,
submodules, oversized files, and Git LFS pointer files are skipped. Rename/copy
diffs are enabled. A resume cursor is a commit SHA. If the cursor is no longer
an ancestor of the requested ref, the scanner reports a history rewrite and
starts again. A shallow clone is explicitly reported as incomplete because it
does not contain older commits.

Limits are 10,000 commits, 10,000 files, 1,000 changed files per commit,
200 MiB of unique blobs, 25 MiB per blob, five minutes total, and 15 seconds per
Git command. A bounded run returns a `resume_after` commit cursor and a partial
reason. The result's `blob_version_in_head` flag is deliberately exact: it says
the same blob SHA still exists at the same path in the selected ref. It does not
prove that a masked secret remains in a later-edited file; that needs P1's
stable detector fingerprint contract.

## Integration handoffs still open

- P1 must provide the frozen offline detector/fingerprint package so secret
  identity can be deduplicated across different blob versions and `still in
  HEAD` can refer to the finding rather than an exact file blob.
- P2 must provide the authenticated repository principal, repository channel
  and destination contract, and the shared scan/gate adapter. Do not pass an
  organization ID from a browser request.
- P4 must connect the completed push scan to the incident handler. The
  webhook's durable queue is not consumed yet, so this history service does not
  currently run after pushes.
- The GitHub App clone path is shallow today. Full history needs a bounded
  deepen/fetch strategy and an authenticated live integration test before the
  service can claim complete history coverage.

Run `python -m unittest tests.test_git_history_scan -v` from `dlp-backend/` for
synthetic added/deleted secrets, first-seen provenance, resume, force-push,
`.dlpignore`, and Git LFS pointer coverage.
