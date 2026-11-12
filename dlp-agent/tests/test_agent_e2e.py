import json
import os
import threading
import time
from pathlib import Path

import pytest

from conftest import CARD, EMAIL, Harness
from dlp_agent.agent import Agent, sanitise_config
from dlp_agent.cli import main as cli_main
from dlp_agent.client import AuthRejected, ServerClient


# ------------------------------------------------------------------ enrolment
def test_cli_enrol_saves_identity_and_signed_config(tmp_path, server, capsys):
    home = tmp_path / "home"
    code = cli_main(["--home", str(home), "enrol", "--server", server.url, "--token", server.new_token()])
    assert code == 0
    out = capsys.readouterr().out
    identity = json.loads((home / "identity.json").read_text())
    assert identity["device_key"].startswith("dlpd_") and identity["device_key"] not in out
    assert "mac" in json.loads((home / "config.json").read_text())
    assert [d["hostname"] for d in server.devices()] != []
    if os.name != "nt":
        assert oct((home / "identity.json").stat().st_mode & 0o777) == "0o600"
    # token is single use
    assert cli_main(["--home", str(tmp_path / "h2"), "enrol", "--server", server.url, "--token", "dlpe_nope0123456789"]) == 2


def test_enrol_refuses_plain_http_to_remote_host(tmp_path):
    assert cli_main(["--home", str(tmp_path), "enrol", "--server", "http://dlp.example.test", "--token", "dlpe_x" * 3]) == 2


# ---------------------------------------------------------------- file reports
def test_sensitive_file_in_downloads_is_reported_and_quarantined(harness: Harness, server):
    agent = harness.start()
    old = harness.write("old.txt", f"card {CARD}")  # created after baseline => new
    clean = harness.write("notes.txt", "meeting notes, nothing sensitive")
    harness.settle()
    assert not old.exists() and clean.exists()
    [event] = harness.server_events()
    assert (event["kind"], event["decision"], event["folder_class"], event["filename"]) == ("quarantine", "block", "downloads", "old.txt")
    assert event["quarantined"] and "credit_card" in event["data_types"]
    items = agent.quarantine.list()
    assert len(items) == 1 and items[0].original_name == "old.txt"
    log = harness.state.log_path.read_text()
    assert CARD not in log and "4111" not in log


def test_files_that_existed_before_start_are_not_scanned(tmp_path, server):
    h = Harness(tmp_path, server)
    pre = h.write("pre.txt", f"card {CARD}")
    os.utime(pre, (time.time() - 3600, time.time() - 3600))
    # make ctime old too is impossible; cutoff uses start time, so start the clock after the file exists
    h.clock.advance(10)
    h.start()
    h.settle()
    assert pre.exists() and h.server_events() == []


def test_file_still_being_written_waits_until_stable(harness: Harness):
    harness.start()
    path = harness.write("big.txt", "a" * 10)
    harness.clock.advance(1)
    first = harness.agent.tick()
    assert first["processed"] == 0
    path.write_text("a" * 10 + f" card {CARD}")  # still growing
    harness.clock.advance(2)
    assert harness.agent.tick()["processed"] == 0
    harness.clock.advance(4)
    assert harness.agent.tick()["processed"] == 1
    assert not path.exists()


def test_locked_file_is_abandoned_with_an_event(harness: Harness):
    harness.start()
    harness.agent.gate.can_read = lambda p: False
    harness.write("locked.txt", f"card {CARD}")
    harness.settle(ticks=1)
    harness.clock.advance(700)
    summary = harness.agent.tick()
    assert summary["abandoned"] == 1 and (harness.downloads / "locked.txt").exists()
    assert [e["kind"] for e in harness.server_events()] == ["error"]


def test_temp_download_files_are_ignored(harness: Harness):
    harness.start()
    harness.write("movie.crdownload", f"card {CARD}")
    harness.write("~$report.docx", f"card {CARD}")
    harness.settle()
    assert harness.server_events() == []


def test_unchanged_clean_file_is_not_rescanned(harness: Harness, server):
    harness.start()
    path = harness.write("a.txt", "hello world")
    harness.settle()
    first = server.scan_calls
    assert first == 1
    harness.agent.watcher._seen.clear()  # force the watcher to report it again
    harness.settle()
    assert server.scan_calls == first


def test_unicode_and_deep_paths(harness: Harness):
    harness.start()
    deep = harness.downloads
    for part in ("très-long-" + "d" * 60, "日本語-" + "e" * 60, "f" * 60, "g" * 60):
        deep = deep / part
    path = harness.write("résumé_ファイル.txt", f"card {CARD}", folder=deep)
    assert len(str(path)) > 240
    harness.settle()
    assert not path.exists()
    [event] = harness.server_events()
    assert event["filename"] == "résumé_ファイル.txt"


# ------------------------------------------------------------ unscannable files
@pytest.mark.parametrize("action,quarantined,kept,events", [("allow", False, True, 0), ("warn", False, True, 1), ("block", True, False, 1)])
def test_unscannable_action(harness: Harness, action, quarantined, kept, events):
    harness.set_config(unscannable_action=action)
    harness.start()
    path = harness.downloads / "tool.exe"
    path.write_bytes(b"MZ\x00\x01binary")
    harness.settle()
    assert path.exists() == kept
    evs = harness.server_events()
    assert len(evs) == events
    if events:
        assert evs[0]["kind"] == "unscannable" and evs[0]["quarantined"] == quarantined


# -------------------------------------------------------------------- offline
def test_offline_queue_replays_after_reconnect(harness: Harness, server):
    agent = harness.start()
    real_base = agent.client.base
    agent.client.base = "http://127.0.0.1:9"  # nothing listens here
    path = harness.write("offline.txt", f"card {CARD}")
    harness.settle(ticks=2)
    assert path.exists() and agent.queue.depth() >= 1  # deferred, not lost
    assert harness.server_events() == []
    agent.client.base = real_base
    harness.clock.advance(1000)  # past any backoff
    harness.settle(ticks=3)
    assert not path.exists()
    assert [e["kind"] for e in harness.server_events()] == ["quarantine"]
    assert agent.queue.depth() == 0


def test_events_queued_offline_are_delivered_later(harness: Harness):
    from dlp_agent.client import Offline

    agent = harness.start()
    harness.write("mail.txt", f"reach me at {EMAIL}")
    original = agent.client.events
    down = {"on": True}

    def flaky(events):
        if down["on"]:
            raise Offline("down")  # the scan call worked, then the network dropped
        return original(events)

    agent.client.events = flaky
    harness.settle(ticks=2)
    assert harness.server_events() == [] and agent.queue.depth() == 1
    down["on"] = False
    harness.clock.advance(1000)
    harness.settle(ticks=2)
    assert [e["decision"] for e in harness.server_events()] == ["warn"] and agent.queue.depth() == 0


def test_backoff_is_exponential_and_capped():
    from dlp_agent.queue import MAX_DELAY, backoff_delay

    delays = [backoff_delay(n, rng=lambda: 1.0) for n in range(1, 12)]
    assert delays[0] == 5 and delays[1] == 10 and all(b >= a for a, b in zip(delays, delays[1:])) and delays[-1] == MAX_DELAY
    assert backoff_delay(3, rng=lambda: 0.0) == 10  # jitter floor is half the delay


def test_queue_is_bounded_and_drops_file_refs_before_events(tmp_path, monkeypatch):
    from dlp_agent import queue as q

    monkeypatch.setattr(q, "MAX_ITEMS", 5)
    queue = q.OfflineQueue(tmp_path / "q.sqlite3")
    queue.put("event", {"n": 0})
    for i in range(10):
        queue.put("file", {"path": str(i)})
    assert queue.depth() == 5 and len(queue.due("event")) == 1


# ------------------------------------------------------------------------ USB
def test_copy_to_usb_is_detected_and_quarantined(harness: Harness):
    usb = harness.tmp / "usb"
    usb.mkdir()
    present = []

    class Provider:
        def list_roots(self):
            return list(present)

    harness.start(removable=Provider())
    present.append(usb)
    harness.agent.tick()  # drive appears, baseline
    copied = harness.write("payroll.txt", f"card {CARD}", folder=usb)
    harness.settle()
    assert not copied.exists()
    [event] = harness.server_events()
    assert (event["kind"], event["folder_class"], event["quarantined"]) == ("usb_copy", "removable", True)


def test_file_already_copied_when_drive_is_detected_is_still_caught(harness: Harness):
    usb = harness.tmp / "usb2"
    usb.mkdir()
    copied = harness.write("fast.txt", f"card {CARD}", folder=usb)  # copied before the next poll
    present = [usb]

    class Provider:
        def list_roots(self):
            return list(present)

    harness.start(removable=Provider())
    harness.settle()
    assert not copied.exists() and [e["kind"] for e in harness.server_events()] == ["usb_copy"]


def test_removable_scanning_can_be_turned_off_by_config(harness: Harness):
    usb = harness.tmp / "usb3"
    usb.mkdir()
    harness.set_config(scan_removable_drives=False)

    class Provider:
        def list_roots(self):
            return [usb]

    harness.start(removable=Provider())
    f = harness.write("x.txt", f"card {CARD}", folder=usb)
    harness.settle()
    assert f.exists()


# ------------------------------------------------------------------- tamper
def test_unplanned_stop_is_reported_as_tamper_planned_stop_is_not(harness: Harness, server):
    harness.start()
    harness.agent.stop(planned=False)
    harness.start()  # restart
    harness.settle(ticks=1)
    [dev] = server.devices()
    assert dev["tamper_flags"] == ["service_stop"] and dev["tamper_at"]
    server.admin("POST", f"/devices/{dev['device_id']}/tamper/acknowledge")
    harness.agent.stop(planned=True)
    harness.start()
    harness.settle(ticks=1)
    assert server.devices()[0]["tamper_flags"] == []


def test_config_edit_is_detected_reset_and_resynced(harness: Harness, server):
    harness.start()
    cfg = json.loads(harness.state.config_path.read_text())
    cfg["config"]["watch_folders"] = ["/"]  # attacker widens or narrows scope by hand
    harness.state.config_path.write_text(json.dumps(cfg))
    server.admin("PUT", "/devices/config/11111111-1111-1111-1111-111111111111",
                 {"stable_seconds": 7, "watch_folders": [str(harness.downloads)]})
    harness.settle(ticks=2)
    [dev] = server.devices()
    assert "config_edit" in dev["tamper_flags"]
    assert harness.agent.config["watch_folders"] == [str(harness.downloads)] and harness.agent.config["stable_seconds"] == 7
    _, _, tampered = harness.state.load_config(harness.identity.device_key)
    assert not tampered  # file was re-signed with the server's config


def test_missing_config_file_is_not_tamper(tmp_path):
    from dlp_agent.state import AgentState

    _, config, tampered = AgentState(tmp_path).load_config("k")
    assert not tampered and config["unscannable_action"] == "warn"


def test_watchdog_reports_stale_agent(harness: Harness, server, capsys):
    harness.start()
    harness.agent.stop(planned=True)
    old = time.time() - 10_000
    os.utime(harness.state.watchdog_path, (old, old))
    harness.state.watchdog_path.write_text(json.dumps({"ts": old}))
    assert cli_main(["--home", str(harness.home), "watchdog"]) == 1
    assert "watchdog" in server.devices()[0]["tamper_flags"]
    harness.start()
    assert cli_main(["--home", str(harness.home), "watchdog"]) == 0


# ---------------------------------------------------------------- revocation
def test_revoked_device_stops_scanning_immediately(harness: Harness, server):
    agent = harness.start()
    server.admin("POST", f"/devices/{harness.identity.device_id}/revoke")
    path = harness.write("after.txt", f"card {CARD}")
    summaries = harness.settle()
    assert summaries[-1]["revoked"] is True
    assert path.exists() and server.scan_calls == 0
    with pytest.raises(AuthRejected):
        ServerClient(server.url, harness.identity.device_key).heartbeat(0, 0, [])


# ----------------------------------------------------------------- clipboard
def test_clipboard_with_card_is_cleared_and_reported(harness: Harness):
    class Clip:
        def __init__(self):
            self.seq, self.text = 1, "hello"

        def sequence(self):
            return self.seq

        def read_text(self):
            return self.text

        def clear(self):
            self.text, self.seq = "", self.seq + 1

    clip = Clip()
    harness.set_config(clipboard_monitoring=True)
    harness.start(clipboard=clip)
    clip.seq, clip.text = 2, f"pay with {CARD}"
    harness.settle(ticks=1)
    assert clip.text == ""
    [event] = harness.server_events()
    assert (event["folder_class"], event["decision"]) == ("clipboard", "block")
    clip.seq, clip.text = 5, "just a note"
    harness.settle(ticks=1)
    assert len(harness.server_events()) == 1


def test_clipboard_off_by_default(harness: Harness):
    class Clip:
        calls = 0

        def sequence(self):
            Clip.calls += 1
            return Clip.calls

        def read_text(self):
            return f"card {CARD}"

        def clear(self):
            raise AssertionError("must not clear")

    harness.start(clipboard=Clip())
    harness.settle()
    assert Clip.calls == 0


# --------------------------------------------------------------- hardening
def test_server_config_is_sanitised():
    clean = sanitise_config({"stable_seconds": "evil", "unscannable_action": "rm -rf", "watch_folders": [1, 2],
                             "heartbeat_seconds": -5, "quarantine_on_block": "yes", "extra": 1})
    assert clean["stable_seconds"] == 3 and clean["unscannable_action"] == "warn"
    assert clean["watch_folders"][0].endswith("Downloads") and clean["heartbeat_seconds"] == 60
    assert clean["quarantine_on_block"] is True and "extra" not in clean


def test_network_drives_are_skipped(harness: Harness, monkeypatch):
    from dlp_agent import agent as agent_module

    monkeypatch.setattr(agent_module, "is_network_path", lambda p: True)
    harness.start()
    harness.write("n.txt", f"card {CARD}")
    harness.settle()
    assert harness.server_events() == []


def test_extractor_crash_does_not_stop_the_agent(harness: Harness):
    def boom(*a, **k):
        raise RuntimeError("parser bug with secret " + CARD)

    harness.start(extract_file=boom)
    p = harness.write("x.txt", "hello")
    harness.settle()
    assert p.exists() and CARD not in harness.state.log_path.read_text()
    assert [e["kind"] for e in harness.server_events()] == ["unscannable"]


def test_status_command_shows_state_without_secrets(harness: Harness, capsys):
    harness.start()
    assert cli_main(["--home", str(harness.home), "status"]) == 0
    out = capsys.readouterr().out
    assert harness.identity.device_id in out and harness.identity.device_key not in out and "queue depth:   0" in out


def test_run_forever_survives_tick_errors_and_stops_cleanly(harness: Harness):
    agent = harness.start()
    calls = {"n": 0}
    original = agent.tick

    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        return original()

    agent.tick = flaky
    stop = threading.Event()
    stop.planned = True
    t = threading.Thread(target=agent.run_forever, args=(stop, 0.01))
    t.start()
    time.sleep(0.3)
    stop.set()
    t.join(timeout=5)
    assert not t.is_alive() and calls["n"] > 1
