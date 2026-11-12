# dlp-cli

Offline DLP scanner for developers. No network access during a scan.

    pip install .
    dlp scan --staged            # what you are about to commit
    dlp scan --path src/         # files or folders
    dlp scan --git-range origin/main..HEAD   # every commit in a range
    dlp scan --path . --format sarif --output dlp.sarif

Full reference: `docs/cli.md` at the repository root.
