from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.routers import channels, classifications, detect, events, incidents, overview, policy

settings = get_settings()

app = FastAPI(title="DLP Backend", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(detect.router)
app.include_router(events.router)
app.include_router(incidents.router)
app.include_router(overview.router)
app.include_router(policy.router)
app.include_router(channels.router)
app.include_router(classifications.router)


@app.get("/health")
def health():
    return {"status": "ok"}
