"""Healthcheck endpoint."""

from fastapi import APIRouter

from app.config import settings

router = APIRouter(tags=["health"])


@router.get("/health")
async def health():
    return {
        "status": "ok",
        "version": settings.api_version,
        "env": settings.env,
        "components": {
            "api": "healthy",
            "pipeline": "available",
        },
    }
