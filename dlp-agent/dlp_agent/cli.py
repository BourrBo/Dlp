"""``dlp-agent`` command line: enrol, run, status, quarantine, watchdog.

Exit codes: 0 ok, 1 attention needed (watchdog stale, nothing to restore),
2 usage or setup error, 3 runtime error.
"""

from __future__ import annotations

import argparse
import platform
import signal
import sys
import threading
from pathlib import Path
from typing import Optional

from dlp_agent import __version__
from dlp_agent.agent import Agent, local_hostname, sanitise_config
from dlp_agent.client import AuthRejected, Offline, Rejected, ServerClient, validate_server_url
from dlp_agent.extract import ExtractorsUnavailable, load_extract_file
from dlp_agent.platform_support import default_clipboard, default_removable_provider
from dlp_agent.quarantine import Quarantine, QuarantineError
from dlp_agent.queue import OfflineQueue
from dlp_agent.state import AgentState, Identity
from dlp_agent.tamper import TamperMonitor


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dlp-agent", description="DLP endpoint agent")
    parser.add_argument("--version", action="version", version=f"dlp-agent {__version__}")
    parser.add_argument("--home", type=Path, help="state folder (default: %%PROGRAMDATA%%\\DLPAgent or ~/.dlp-agent)")
    sub = parser.add_subparsers(dest="command", required=True)
    enrol = sub.add_parser("enrol", help="enrol this device with an enrolment token")
    enrol.add_argument("--server", required=True)
    enrol.add_argument("--token", required=True)
    sub.add_parser("run", help="run in the foreground (the Windows service calls this loop)")
    sub.add_parser("status", help="show device, config and queue state")
    sub.add_parser("watchdog", help="report to the server if the agent heartbeat file is stale")
    q = sub.add_parser("quarantine", help="list or restore quarantined files")
    qs = q.add_subparsers(dest="qcommand", required=True)
    qs.add_parser("list")
    restore = qs.add_parser("restore")
    restore.add_argument("id")
    restore.add_argument("--to", type=Path, help="absolute destination (default: original location)")
    purge = qs.add_parser("purge")
    purge.add_argument("id")
    return parser


def _identity_or_exit(state: AgentState) -> Optional[Identity]:
    identity = state.load_identity()
    if identity is None:
        print("error: this device is not enrolled; run 'dlp-agent enrol' first", file=sys.stderr)
    return identity


def cmd_enrol(state: AgentState, args: argparse.Namespace) -> int:
    try:
        server = validate_server_url(args.server)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        reply = ServerClient(server).enrol(args.token, local_hostname(), platform.platform())
    except AuthRejected:
        print("error: enrolment token is invalid, expired or already used", file=sys.stderr)
        return 2
    except (Offline, Rejected) as exc:
        print(f"error: could not enrol: {exc}", file=sys.stderr)
        return 3
    identity = Identity(server, reply["device_id"], reply["device_key"])
    state.save_identity(identity)
    state.save_config(int(reply.get("config_version", 0)), sanitise_config(reply.get("config", {})), identity.device_key)
    print(f"enrolled as device {identity.device_id}")
    return 0


def cmd_run(state: AgentState) -> int:
    identity = _identity_or_exit(state)
    if identity is None:
        return 2
    try:
        extract_file = load_extract_file()
    except ExtractorsUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    agent = Agent(state, identity, extract_file=extract_file,
                  removable=default_removable_provider(), clipboard=default_clipboard())
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    agent.run_forever(stop)
    return 0


def cmd_status(state: AgentState) -> int:
    identity = _identity_or_exit(state)
    if identity is None:
        return 2
    version, config, tampered = state.load_config(identity.device_key)
    queue = OfflineQueue(state.queue_path)
    print(f"device:        {identity.device_id}")
    print(f"server:        {identity.server_url}")
    print(f"config:        version {version}{' (TAMPERED, using defaults)' if tampered else ''}")
    print(f"watching:      {', '.join(config['watch_folders'])}")
    print(f"queue depth:   {queue.depth()}")
    print(f"quarantined:   {len(Quarantine(state.quarantine_dir).list())}")
    print(f"tamper flags:  {', '.join(TamperMonitor(state).pending()) or 'none'}")
    return 0


def cmd_watchdog(state: AgentState) -> int:
    identity = _identity_or_exit(state)
    if identity is None:
        return 2
    monitor = TamperMonitor(state)
    _, config, _ = state.load_config(identity.device_key)
    if not monitor.watchdog_stale(3 * config["heartbeat_seconds"]):
        return 0
    monitor.flag("watchdog")
    try:
        ServerClient(identity.server_url, identity.device_key).heartbeat(OfflineQueue(state.queue_path).depth(), 0, ["watchdog"])
        monitor.mark_reported(["watchdog"])
    except (Offline, AuthRejected, Rejected):
        pass  # the flag stays pending and the agent reports it when it next runs
    print("agent heartbeat is stale", file=sys.stderr)
    return 1


def cmd_quarantine(state: AgentState, args: argparse.Namespace) -> int:
    quarantine = Quarantine(state.quarantine_dir)
    if args.qcommand == "list":
        for item in quarantine.list():
            print(f"{item.id}  {item.original_name}  {item.size} bytes  {','.join(item.data_types) or '-'}")
        return 0
    try:
        if args.qcommand == "restore":
            print(f"restored to {quarantine.restore(args.id, args.to)}")
        else:
            quarantine.purge(args.id)
            print("purged")
    except QuarantineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    state = AgentState(args.home)
    try:
        if args.command == "enrol":
            return cmd_enrol(state, args)
        if args.command == "run":
            return cmd_run(state)
        if args.command == "status":
            return cmd_status(state)
        if args.command == "watchdog":
            return cmd_watchdog(state)
        return cmd_quarantine(state, args)
    except Exception as exc:
        print(f"internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
