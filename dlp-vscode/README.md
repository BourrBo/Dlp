# DLP Scanner for VS Code

Runs the offline `dlp` CLI when you save a file and shows findings as problems
on the exact line and columns. Values are always masked.

Setup: `pip install dlp-cli`, then install this extension. Commands: **DLP: Scan current file**,
**DLP: Scan workspace**, **DLP: Clear diagnostics**. Settings: `dlp.cliPath`, `dlp.scanOnSave`,
`dlp.failOn`, `dlp.timeoutSeconds`.

Package with `npx @vscode/vsce package` (no build step; plain CommonJS).
