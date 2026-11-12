import json
import os
import sys
import threading
import time
import urllib.request
from pathlib import Path
from unittest.mock import patch

import pytest

BACKEND = Path(__file__).resolve().parents[2] / "dlp-backend"
sys.path.insert(0, str(BACKEND))
os.environ.setdefault("DLP_EXTRACTORS_PATH", str(BACKEND))

import uvicorn  # noqa: E402
from fastapi import FastAPI  # noqa: E402

from app.config import Settings  # noqa: E402
from app.models.finding import Decision, ScanResult  # noqa: E402
from app.routers import devices  # noqa: E402
from app.services.detection_service import detect  # noqa: E402
from app.services.device_store import DeviceStore  # noqa: E402

from dlp_agent.agent import Agent  # noqa: E402
from dlp_agent.client import ServerClient  # noqa: E402
from dlp_agent.extract import load_extract_file  # noqa: E402
from dlp_agent.state import AgentState, Identity  # noqa: E402

ORG = "11111111-1111-1111-1111-111111111111"
ADMIN_KEY = "admin-secret"
CARD = "4111" + "1111" + "1111" + "1111"  # documented Visa test number
EMAIL = "someone@example.test"


class FakeClock:
    def __init__(self, start=None):
        self.now = start if start is not None else time.time()

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class LiveServer:
    def __init__(self, store, port, uvicorn_server):
        self.store, self.port, self._server = store, port, uvicorn_server
        self.url = f"http://127.0.0.1:{port}"
        self.scan_calls = 0

    def admin(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method,
                                     headers={"X-DLP-Admin-Key": ADMIN_KEY, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as res:
            return json.loads(res.read() or b"{}")

    def new_token(self):
        return self.admin("POST", "/devices/enrolment-tokens", {"org_id": ORG})["enrolment_token"]

    def devices(self):
        return self.admin("GET", f"/devices?org_id={ORG}")["devices"]

    def events(self, device_id):
        return self.admin("GET", f"/devices/{device_id}/events")["events"]


@pytest.fixture
def server(tmp_path):
    store = DeviceStore(tmp_path / "server.sqlite3")
    app = FastAPI()
    app.include_router(devices.agent_router)
    app.include_router(devices.admin_router)
    app.dependency_overrides[devices.get_device_store] = lambda: store
    holder = {}

    def fake_scan(request):
        holder["live"].scan_calls += 1
        findings = detect(request.content)
        if any(f.confidence >= 0.85 for f in findings):
            return ScanResult(findings=findings, decision=Decision.BLOCK, reason="blocked")
        return ScanResult(findings=findings, decision=Decision.WARN if findings else Decision.ALLOW, reason="policy")

    uv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error"))
    thread = threading.Thread(target=uv.run, daemon=True)
    with patch("app.routers.classifications.get_settings", return_value=Settings(dlp_admin_api_key=ADMIN_KEY)), \
         patch.object(devices, "run_scan", fake_scan):
        thread.start()
        deadline = time.time() + 10
        while not uv.started and time.time() < deadline:
            time.sleep(0.02)
        port = uv.servers[0].sockets[0].getsockname()[1]
        live = LiveServer(store, port, uv)
        holder["live"] = live
        yield live
        uv.should_exit = True
        thread.join(timeout=10)


class Harness:
    """An enrolled agent against the live test server, with a fake clock."""

    def __init__(self, tmp_path, server, **agent_kwargs):
        self.tmp, self.server = tmp_path, server
        self.home = tmp_path / "agent-home"
        self.downloads = tmp_path / "user" / "Downloads"
        self.downloads.mkdir(parents=True)
        self.clock = FakeClock()
        self.state = AgentState(self.home)
        reply = ServerClient(server.url).enrol(server.new_token(), "TEST-PC", "TestOS")
        self.identity = Identity(server.url, reply["device_id"], reply["device_key"])
        self.state.save_identity(self.identity)
        config = {**reply["config"], "watch_folders": [str(self.downloads)], "stable_seconds": 3}
        version = server.admin("PUT", f"/devices/config/{ORG}", config)["config_version"]
        self.state.save_config(version, config, self.identity.device_key)
        self.kwargs = agent_kwargs
        self.agent = None

    def set_config(self, **overrides):
        """Change the org config on the server (the source of truth) and cache it locally."""
        _, config, _ = self.state.load_config(self.identity.device_key)
        merged = {**config, **overrides}
        version = self.server.admin("PUT", f"/devices/config/{ORG}", merged)["config_version"]
        self.state.save_config(version, merged, self.identity.device_key)

    def start(self, **overrides):
        kwargs = {"extract_file": load_extract_file(), "clock": self.clock, **self.kwargs, **overrides}
        self.agent = Agent(self.state, self.identity, **kwargs)
        self.agent.start()
        self.agent.tick()  # baseline pass
        return self.agent

    def settle(self, ticks=2, seconds=4):
        """Let files become stable, then run enough ticks to process them."""
        summaries = []
        for _ in range(ticks):
            self.clock.advance(seconds)
            summaries.append(self.agent.tick())
        return summaries

    def write(self, name, text, folder=None):
        path = (folder or self.downloads) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def server_events(self):
        return self.server.events(self.identity.device_id)


@pytest.fixture
def harness(tmp_path, server):
    return Harness(tmp_path, server)
