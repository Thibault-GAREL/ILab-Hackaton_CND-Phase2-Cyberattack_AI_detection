"""Routes pour les detections Phase 2."""

from typing import Optional

from fastapi import APIRouter, Body, HTTPException, Query

from app.config import settings
from app.schemas.detection import (
    DetectionStats,
    DetectionSummary,
    DetectionsResponse,
    PipelineRunRequest,
    TimelineEntry,
)
from app.services.pipeline_bridge import load_detections, run_pipeline_job, to_api_format

router = APIRouter(prefix="/v1/detections", tags=["detections"])


@router.get("", response_model=DetectionsResponse)
async def list_detections(
    attack_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
):
    raw = load_detections()
    items = to_api_format(raw)
    if attack_type:
        items = [d for d in items if d["attack_type"] == attack_type]
    if severity:
        items = [d for d in items if d["severity"] == severity]
    return DetectionsResponse(
        total=len(items),
        detections=[DetectionSummary(**d) for d in items],
    )


@router.get("/stats/summary", response_model=DetectionStats)
async def detections_stats():
    raw = load_detections()
    items = to_api_format(raw)
    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    all_ips: set[str] = set()
    all_under_300 = True
    for d in items:
        by_type[d["attack_type"]] = by_type.get(d["attack_type"], 0) + 1
        by_severity[d["severity"]] = by_severity.get(d["severity"], 0) + 1
        all_ips.update(d["attacker_ips"])
        if d["detection_time_seconds"] >= 300:
            all_under_300 = False
    return DetectionStats(
        total_detections=len(items),
        by_attack_type=by_type,
        by_severity=by_severity,
        unique_attacker_ips=len(all_ips),
        all_under_300s=all_under_300,
    )


@router.get("/timeline")
async def detections_timeline():
    raw = load_detections()
    items = to_api_format(raw)
    return [
        TimelineEntry(
            challenge_id=d["challenge_id"],
            attack_type=d["attack_type"],
            start_time=d["start_time"],
            end_time=d["end_time"],
            severity=d["severity"],
            attacker_ips=d["attacker_ips"],
        )
        for d in items
    ]


@router.get("/{detection_id}", response_model=DetectionSummary)
async def get_detection(detection_id: int):
    raw = load_detections()
    items = to_api_format(raw)
    if detection_id < 0 or detection_id >= len(items):
        raise HTTPException(404, "Detection not found")
    return DetectionSummary(**items[detection_id])


@router.post("/pipeline/run")
async def trigger_pipeline(
    payload: PipelineRunRequest | None = Body(default=None),
):
    """
    Lance une analyse : OpenSearch (`python -m pipeline`) ou script Parquet bench.

    Body : `source`, `max_lines`, options curseur / dedup / soumission, Bedrock, etc.
    La soumission live (`submit: true`) exige `PIPELINE_ALLOW_SUBMIT=1` sur le backend.
    """
    p = payload or PipelineRunRequest()
    if p.submit and not settings.pipeline_allow_submit:
        raise HTTPException(
            status_code=403,
            detail="Soumission live vers l'API de scoring désactivée. Définir PIPELINE_ALLOW_SUBMIT=1.",
        )
    return run_pipeline_job(p)
