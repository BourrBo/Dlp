from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.routers import allowlist, channels, classifications, detect, devices, events, findings, github_webhooks, incidents, overview, platform, policy, scan_jobs, scans
from app.services.scan_job_store import get_scan_job_store
from app.services.scan_job_worker import ScanJobWorker
from app.services.github_webhook_store import get_github_webhook_store
from app.extractors.limits import MAX_FILE_BYTES
from app.middleware import UploadRequestBodyLimitMiddleware

settings = get_settings()
platform_mounted = bool(settings.platform_database_url)

@asynccontextmanager
async def lifespan(app: FastAPI):
    get_github_webhook_store().recover_processing()
    worker = None
    # Upload submissions now bind org and user ownership to a verified Supabase
    # principal; processing can therefore run in production as well.
    if settings.supabase_service_role_key:
        worker = ScanJobWorker(get_scan_job_store())
        worker.start()
    app.state.scan_job_worker = worker
    if platform_mounted:
        from dlp_platform.main import lifespan as platform_lifespan

        async with platform_lifespan(app):
            yield
    else:
        yield
    if worker:
        worker.stop()


app = FastAPI(title="DLP Backend", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(
    UploadRequestBodyLimitMiddleware,
    max_bytes=MAX_FILE_BYTES + 1024 * 1024,
)

app.include_router(detect.router)
app.include_router(scans.router)
app.include_router(scan_jobs.router)
app.include_router(findings.router)
app.include_router(allowlist.router)
app.include_router(github_webhooks.router)
app.include_router(devices.agent_router)
app.include_router(devices.admin_router)
app.include_router(overview.router)
app.include_router(incidents.router)
app.include_router(events.router)
app.include_router(policy.router)
app.include_router(platform.router)
app.include_router(channels.router)
app.include_router(classifications.router)


@app.get("/health")
def health():
    return {"status": "ok"}

# Optional P2 platform: API keys, policies, connectors, vault, SSO/SCIM, audit, public API.
from app.platform_bridge import mount_platform  # noqa: E402

mount_platform(app)
