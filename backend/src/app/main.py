"""Backend FastAPI Phase 2 — Detection & Remediation API."""

import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.repo_paths import find_repo_root

_repo_root = find_repo_root()
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from app.config import settings
from app.routers import detections, health, remediation


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(
    title="CND Phase 2 — Detection & Remediation API",
    description="Backend pour la detection d'attaques et la remediation AWS",
    version=settings.api_version,
    lifespan=lifespan,
)

_default_cors = [
    "http://localhost:3000",
    "http://localhost:8501",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:8501",
]
_cors = list(dict.fromkeys(_default_cors + settings.cors_origins_list))
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(detections.router)
app.include_router(remediation.router)


@app.get("/")
async def root():
    return {
        "service": "CND Phase 2 — Detection & Remediation API",
        "version": settings.api_version,
        "status": "operational",
        "docs": "/docs",
    }
