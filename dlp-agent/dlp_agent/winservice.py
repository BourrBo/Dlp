"""Windows service wrapper (requires pywin32; Windows only).

    python -m dlp_agent.winservice install
    python -m dlp_agent.winservice start

A stop that is not preceded by the ``planned-stop`` marker (written by the
update channel) is reported as tamper ``service_stop`` on the next start.
Configure service recovery to restart on failure:
    sc failure DLPAgent reset= 86400 actions= restart/5000/restart/5000/restart/30000
"""

from __future__ import annotations

import sys
import threading

if sys.platform != "win32":  # pragma: no cover - module is importable but inert elsewhere
    raise ImportError("dlp_agent.winservice only runs on Windows")

import servicemanager  # type: ignore[import-not-found]  # noqa: E402
import win32event  # type: ignore[import-not-found]  # noqa: E402
import win32service  # type: ignore[import-not-found]  # noqa: E402
import win32serviceutil  # type: ignore[import-not-found]  # noqa: E402

from dlp_agent.agent import Agent  # noqa: E402
from dlp_agent.extract import load_extract_file  # noqa: E402
from dlp_agent.platform_support import default_clipboard, default_removable_provider  # noqa: E402
from dlp_agent.state import AgentState  # noqa: E402


class DlpAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = "DLPAgent"
    _svc_display_name_ = "DLP Endpoint Agent"
    _svc_description_ = "Detects sensitive files and clipboard data and reports to the DLP platform."

    def __init__(self, args):
        super().__init__(args)
        self._stop_event = threading.Event()
        self._halt = win32event.CreateEvent(None, 0, 0, None)
        self.state = AgentState()

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        marker = self.state.home / "planned-stop"
        self._stop_event.planned = marker.exists()  # type: ignore[attr-defined]
        if marker.exists():
            marker.unlink()
        self._stop_event.set()
        win32event.SetEvent(self._halt)

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE, servicemanager.PYS_SERVICE_STARTED, (self._svc_name_, ""))
        identity = self.state.load_identity()
        if identity is None:
            servicemanager.LogErrorMsg("DLP agent is not enrolled; run 'dlp-agent enrol'")
            return
        agent = Agent(self.state, identity, extract_file=load_extract_file(),
                      removable=default_removable_provider(), clipboard=default_clipboard())
        agent.run_forever(self._stop_event)


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(DlpAgentService)
