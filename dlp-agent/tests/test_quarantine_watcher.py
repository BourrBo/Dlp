import os
import resource
import time

import pytest

from dlp_agent.quarantine import Quarantine, QuarantineError
from dlp_agent.watcher import Change, PollingWatcher, StabilityGate, WatchRoot, is_temp_name


def test_quarantine_moves_restores_and_never_overwrites(tmp_path):
    q = Quarantine(tmp_path / "q")
    src = tmp_path / "docs" / "a.txt"
    src.parent.mkdir()
    src.write_text("secret")
    meta = q.add(src, ["credit_card"])
    assert not src.exists() and meta.size == 6 and len(meta.sha256) == 64
    assert [i.id for i in q.list()] == [meta.id]
    src.write_text("new file with the same name")
    restored = q.restore(meta.id)
    assert restored.name == "a (restored 1).txt" and restored.read_text() == "secret"
    assert src.read_text() == "new file with the same name" and q.list() == []


def test_restore_validates_ids_and_destination(tmp_path):
    q = Quarantine(tmp_path / "q")
    f = tmp_path / "a.txt"
    f.write_text("x")
    meta = q.add(f, [])
    for bad in ("../../etc/passwd", "ZZ", "", "a" * 31):
        with pytest.raises(QuarantineError):
            q.restore(bad)
    with pytest.raises(QuarantineError):
        q.restore(meta.id, tmp_path / "q" / "inside.txt")
    with pytest.raises(QuarantineError):
        q.restore(meta.id, __import__("pathlib").Path("relative/path.txt"))
    assert q.restore(meta.id, tmp_path / "elsewhere" / "ok.txt").read_text() == "x"


def test_quarantine_permissions_and_purge(tmp_path):
    q = Quarantine(tmp_path / "q")
    f = tmp_path / "a.txt"
    f.write_text("x")
    meta = q.add(f, [])
    if os.name != "nt":
        assert oct((tmp_path / "q").stat().st_mode & 0o777) == "0o700"
        assert oct((tmp_path / "q" / f"{meta.id}.dlpq").stat().st_mode & 0o777) == "0o600"
    q.purge(meta.id)
    assert q.list() == [] and not list((tmp_path / "q").iterdir())


def test_watcher_baseline_then_new_and_modified(tmp_path):
    (tmp_path / "pre.txt").write_text("1")
    w = PollingWatcher([WatchRoot(tmp_path, "downloads")])
    assert w.poll() == []
    (tmp_path / "new.txt").write_text("2")
    (tmp_path / "pre.txt").write_text("changed!")
    assert sorted(c.path.name for c in w.poll()) == ["new.txt", "pre.txt"]
    assert w.poll() == []
    (tmp_path / "new.txt").unlink()
    assert w.poll() == []


def test_watcher_skips_symlinks_temp_files_and_deep_trees(tmp_path):
    w = PollingWatcher([WatchRoot(tmp_path, "other")], max_depth=2)
    w.poll()
    (tmp_path / "real.txt").write_text("x")
    try:
        (tmp_path / "link.txt").symlink_to(tmp_path / "real.txt")
        (tmp_path / "linkdir").symlink_to(tmp_path, target_is_directory=True)
    except OSError:
        pass
    (tmp_path / "a.crdownload").write_text("x")
    deep = tmp_path / "1" / "2" / "3" / "4"
    deep.mkdir(parents=True)
    (deep / "too_deep.txt").write_text("x")
    assert sorted(c.path.name for c in w.poll()) == ["real.txt"]
    assert is_temp_name("~$x.docx") and is_temp_name("A.PART") and not is_temp_name("report.pdf")


def test_unreadable_folder_does_not_break_polling(tmp_path):
    if os.name == "nt" or os.geteuid() == 0:
        pytest.skip("permission test needs a non-root POSIX user")
    locked = tmp_path / "locked"
    locked.mkdir()
    w = PollingWatcher([WatchRoot(tmp_path, "other")])
    w.poll()
    (tmp_path / "ok.txt").write_text("x")
    locked.chmod(0)
    try:
        assert [c.path.name for c in w.poll()] == ["ok.txt"]
    finally:
        locked.chmod(0o700)


def test_100k_file_folder_does_not_crash_and_stays_in_budget(tmp_path):
    root = tmp_path / "big"
    for d in range(100):
        folder = root / f"d{d:03d}"
        folder.mkdir(parents=True)
        for i in range(1000):
            (folder / f"f{i}.dat").touch()
    w = PollingWatcher([WatchRoot(root, "documents")])
    start = time.perf_counter()
    assert w.poll() == []
    first = time.perf_counter() - start
    (root / "d050" / "fresh.txt").write_text("x")
    start = time.perf_counter()
    changes = w.poll()
    second = time.perf_counter() - start
    assert [c.path.name for c in changes] == ["fresh.txt"]
    assert first < 30 and second < 30
    rss_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1024 if os.name != "darwin" else 1024 * 1024)
    assert rss_mb < 500


def test_file_cap_marks_root_truncated(tmp_path):
    for i in range(20):
        (tmp_path / f"{i}.txt").write_text("x")
    w = PollingWatcher([WatchRoot(tmp_path, "other")], max_files_per_root=10)
    w.poll()
    assert str(tmp_path) in w.truncated_roots


def test_stability_gate_requires_quiet_period_and_readability(tmp_path):
    now = [1000.0]
    f = tmp_path / "a.txt"
    f.write_text("1")
    st = f.stat()
    gate = StabilityGate(stable_seconds=3, give_up_seconds=60, clock=lambda: now[0])
    gate.add(Change(f, "other", st.st_size, st.st_mtime_ns))
    assert gate.ready() == ([], [])
    now[0] += 4
    ready, abandoned = gate.ready()
    assert [c.path for c in ready] == [f] and abandoned == [] and len(gate) == 0


def test_stability_gate_drops_vanished_files_and_gives_up_on_locked(tmp_path):
    now = [0.0]
    a, b = tmp_path / "a.txt", tmp_path / "b.txt"
    a.write_text("1"); b.write_text("1")
    gate = StabilityGate(stable_seconds=1, give_up_seconds=30, clock=lambda: now[0], can_read=lambda p: p != b)
    for p in (a, b):
        s = p.stat()
        gate.add(Change(p, "other", s.st_size, s.st_mtime_ns))
    a.unlink()
    now[0] += 5
    assert gate.ready() == ([], [])  # a vanished, b is locked
    now[0] += 40
    ready, abandoned = gate.ready()
    assert ready == [] and [c.path for c in abandoned] == [b]


def test_parse_proc_mounts():
    from dlp_agent.platform_support import parse_proc_mounts

    text = "/dev/sda1 / ext4 rw 0 0\n/dev/sdb1 /media/user/USB\\040STICK vfat rw 0 0\n/dev/sdc1 /run/media/u/disk exfat rw 0 0\n"
    assert [str(p) for p in parse_proc_mounts(text)] == ["/media/user/USB STICK", "/run/media/u/disk"]


def test_log_drops_unlisted_fields_and_truncates(tmp_path):
    from dlp_agent.log import AgentLog

    log = AgentLog(tmp_path / "l" / "agent.log")
    log.info("x", file="a.txt", content="4111 1111 1111 1111", snippet="41***11", reason="r" * 500)
    log.close()
    text = (tmp_path / "l" / "agent.log").read_text()
    assert "4111" not in text and "snippet" not in text and len(text) < 600
