# Endpoint agent

Python agent for Windows laptops (plan W26-33), source in `dlp-agent/`. It watches folders and
removable drives, extracts text with the shared extractors, asks the platform to decide, and
quarantines blocked files. Backend routes are in `dlp-backend/app/routers/devices.py`.

## Honest limits (read first)

- **Detection happens after a file is written.** The agent cannot block a write; it moves the
  file into quarantine within seconds (poll interval plus the stability wait). Pre-write blocking
  needs a signed kernel mini-filter driver, which is a separate project.
- The agent **sends extracted text to the platform** for detection; files themselves stay on the
  laptop. Extracted text is held in memory only: it is never queued or logged.
- Tamper detection stops casual tampering. A local administrator can stop the service, read
  the device key and edit files. Revocation on the server is the control that cannot be bypassed.
- The **Windows-specific code** (service wrapper, removable drive detection, clipboard) is written
  with ctypes/pywin32 but was **only exercised through fakes on Linux**. The Windows 10/11 test
  matrix (plan W32-33) is still to be run before release.

## What is implemented

| Plan block | Implemented | Evidence |
| --- | --- | --- |
| W26-27 core | Polling watcher (Downloads, Desktop, Documents by default, server-configured), stability wait, locked-file handling, shared extractors, scan call, offline queue with retry and backoff, local log without content, clipboard monitor | 42 tests against a live test server |
| W28-29 fleet | Enrolment with a single-use token, per-device key (hashed server side), heartbeat, config sync, revocation, devices admin API | revoked device rejected on its next request; tests |
| W30-31 USB and quarantine | Removable drive detection (Windows ctypes, Linux mounts), quarantine with restore, tamper flags (unplanned stop, config edit, stale watchdog), unscannable-file action allow/warn/block | tests; Windows run pending |
| W32-33 hardening | 100,000-file folder test, long path and Unicode names, network-drive skip, bounded queue | Linux only; Windows matrix, resource budget on a laptop, update channel and macOS review pending |

## Install and enrol (development)

    pip install ./dlp-agent
    set DLP_EXTRACTORS_PATH=C:\path\to\dlp-backend      # until P4 bundles the extractors
    dlp-agent enrol --server https://dlp.example.com --token dlpe_...
    dlp-agent run                                        # foreground
    python -m dlp_agent.winservice install && python -m dlp_agent.winservice start   # Windows service
    sc failure DLPAgent reset= 86400 actions= restart/5000/restart/5000/restart/30000

Create the token as an admin: `POST /devices/enrolment-tokens` with header `X-DLP-Admin-Key`
and `{"org_id": "<uuid>"}`. Tokens are single use and expire (default 24 hours). `https` is
required except for localhost.

State lives in `%PROGRAMDATA%\DLPAgent` (or `~/.dlp-agent`, override with `--home` or
`DLP_AGENT_HOME`): `identity.json` (server URL, device ID, key), `config.json` (signed),
`queue.sqlite3`, `quarantine\`, `logs\agent.log`. Restrict the folder to SYSTEM and Administrators
(done with mode 700 on POSIX; set the ACL during installation on Windows).

## Configuration (managed on the server)

`PUT /devices/config/{org_id}` (admin). Agents pick it up on their next heartbeat.

| Key | Default | Meaning |
| --- | --- | --- |
| `watch_folders` | Downloads, Desktop, Documents | 1-20 folders; `~` and `%VARS%` expand |
| `stable_seconds` | 3 | Size and modified time must stay unchanged this long |
| `max_file_bytes` | 26214400 | Larger files are "unscannable" |
| `unscannable_action` | `warn` | `allow`, `warn` or `block` for files that cannot be read or are too large |
| `scan_removable_drives` | true | Watch USB drives; a file copied there is scanned, and quarantined if blocked |
| `quarantine_on_block` | true | Move blocked files to quarantine |
| `clipboard_monitoring` | false | Windows only; a blocked clipboard is cleared |
| `heartbeat_seconds` | 60 | 30-3600 |

The agent accepts only these keys with the right types; anything else keeps its default.

## Behaviour

- **Baseline:** files that existed when the agent started are not scanned; new and changed files are.
  A newly inserted USB drive also scans files created in the previous two minutes, so a fast copy is not missed.
- **Skipped:** temp downloads (`.crdownload`, `.part`, `.tmp`, `~$*`), symlinks, `$RECYCLE.BIN`, folders deeper than 8
  levels, and network drives (UNC or mapped) on Windows.
- **Locked or growing files** wait up to 10 minutes, then are abandoned with an `error` event.
- **Offline:** a file whose scan cannot reach the server is queued as a *path reference* (never content)
  and rescanned after backoff (5 s doubling to 15 min, jittered). Events queue the same way. Queue is capped at 100,000.
- **Revoked:** on the first 401 the agent stops scanning and keeps files in place.
- **Unchanged clean files** are remembered by path hash and signature and not rescanned.

## Quarantine

    dlp-agent quarantine list
    dlp-agent quarantine restore <id> [--to C:\absolute\path]
    dlp-agent quarantine purge <id>

Files move (not copy) to a random ID with a JSON sidecar (original path, SHA-256, data types). Restore
never overwrites (adds ` (restored N)`), refuses relative paths and the quarantine folder itself. Restore is
local and needs access to the state folder; a server-approved restore flow is a P4 item.

## Tamper behaviour

| Flag | Raised when |
| --- | --- |
| `service_stop` | The agent ended without a planned-stop marker (service stop, kill, crash, power loss) |
| `config_edit` | `config.json` fails its HMAC check. The agent falls back to safe defaults and re-syncs from the server |
| `watchdog` | `dlp-agent watchdog` (run it from a scheduled task every few minutes) finds the heartbeat file stale and reports directly |

Flags persist until a heartbeat delivers them, so a tamper noticed offline still reaches
the dashboard (`GET /devices` shows `tamper_flags` and `tamper_at`; an admin clears them with
`POST /devices/{id}/tamper/acknowledge`). The update channel must create `planned-stop` in the state folder
before stopping the service.

## Privacy

Events contain a file name (basename only), folder class, decision, data type names, counts and a short fixed
detail. The server schema rejects any other field, so content and matched values cannot be stored. The local
log has an allowlist of fields; tests assert seeded card numbers never appear in it.

## Server API

| Route | Auth | Purpose |
| --- | --- | --- |
| `POST /agent/enrol` | enrolment token | Returns device ID, one-time device key, config |
| `POST /agent/heartbeat` | device key | Version, queue depth, tamper flags; returns config if changed |
| `GET /agent/config` | device key | Current config |
| `POST /agent/events` | device key | Up to 100 masked events |
| `POST /agent/scan` | device key | Extracted chunks in, strictest decision and masked findings out. Org comes from the key |
| `POST /devices/enrolment-tokens`, `GET /devices`, `POST /devices/{id}/revoke`, `GET /devices/{id}/events`, `PUT /devices/config/{org}` | `X-DLP-Admin-Key` | Fleet administration |

Contract gap: `Channel` has no `endpoint` value, so `/agent/scan` records the channel as `api` with
destination `endpoint`. Adding `Channel.ENDPOINT` is a frozen-contract change that needs all four owners.

## Test matrix still to run (W32-33)

Windows 10 and 11, standard and administrator user, laptop sleep and resume, files locked by Office, network
drive roots, real USB sticks, service recovery after kill, resource use (CPU, memory, disk) on a 100,000-file
Documents folder, and the signed installer from P4.
