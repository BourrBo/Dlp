#!/usr/bin/env bash
# Runs the DLP scan for the GitHub Action. All inputs arrive as environment
# variables (never interpolated into the script) to avoid expression injection.
set -uo pipefail

MODE="${DLP_MODE:-path}"
SCAN_PATH="${DLP_PATH:-.}"
FAIL_ON="${DLP_FAIL_ON:-medium}"
SARIF="${DLP_SARIF:-dlp.sarif}"
BASE="${DLP_BASE_SHA:-}"
HEAD="${DLP_HEAD_SHA:-HEAD}"

case "$FAIL_ON" in low|medium|high|critical) ;; *) echo "::error::fail-on must be low, medium, high or critical"; exit 2 ;; esac
case "$MODE" in path|range) ;; *) echo "::error::mode must be path or range"; exit 2 ;; esac

if [ "$MODE" = "range" ]; then
  if ! [[ "$BASE" =~ ^[0-9a-fA-F]{7,64}$ ]] || ! [[ "$HEAD" =~ ^[0-9a-zA-Z._/-]{1,200}$ ]]; then
    echo "::error::range mode needs a base commit SHA (pull_request events provide one)"; exit 2
  fi
  target=(--git-range "${BASE}..${HEAD}")
else
  target=(--path "$SCAN_PATH")
fi

dlp scan "${target[@]}" --fail-on "$FAIL_ON" --format sarif --output "$SARIF"
code=$?
# Human-readable log lines (masked values only), same scan again is cheap and offline.
dlp scan "${target[@]}" --fail-on "$FAIL_ON" || true

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "exit-code=$code" >> "$GITHUB_OUTPUT"
  echo "sarif-file=$SARIF" >> "$GITHUB_OUTPUT"
fi
exit "$code"
