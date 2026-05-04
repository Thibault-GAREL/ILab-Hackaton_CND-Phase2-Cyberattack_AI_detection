"""Routes pour la remediation et les garde-fous anti-hallucination."""

from typing import Any

from fastapi import APIRouter, HTTPException

from app.schemas.remediation import (
    GuardrailValidationRequest,
    GuardrailValidationResponse,
    RemediationAction,
    RemediationPlan,
)
from app.services.guardrails import (
    get_allowed_actions_catalog,
    get_blocked_actions_catalog,
    validate_remediation,
)
from app.services.pipeline_bridge import load_detections, to_api_format

router = APIRouter(prefix="/v1/remediation", tags=["remediation"])


@router.get("/catalog")
async def remediation_catalog():
    """Catalogue des playbooks AWS par type d'attaque."""
    try:
        from pipeline.remediation import remediation_playbooks_catalog
        return remediation_playbooks_catalog()
    except ImportError:
        return {"error": "Pipeline module not available"}


@router.get("/guardrails")
async def guardrails_info():
    """Information sur les garde-fous anti-hallucination."""
    return {
        "allowed_actions": get_allowed_actions_catalog(),
        "blocked_actions": get_blocked_actions_catalog(),
        "description": (
            "Chaque action de remediation proposee par Bedrock est filtree "
            "par un dictionnaire statique d'actions AWS autorisees. "
            "Les actions dangereuses (suppression, escalade) sont bloquees."
        ),
    }


@router.post("/validate", response_model=GuardrailValidationResponse)
async def validate_remediation_plan(request: GuardrailValidationRequest):
    """Valide un plan de remediation via les garde-fous."""
    result = validate_remediation(request.remediation_plan)
    return GuardrailValidationResponse(
        validated=result["validated"],
        total_actions=result["total_actions"],
        approved=result["approved"],
        blocked=result["blocked"],
        needs_review=result["needs_review"],
        actions=[RemediationAction(**a) for a in result["actions"]],
    )


@router.get("/{challenge_id}")
async def get_remediation_for_challenge(challenge_id: str):
    """Remediation plan pour un challenge specifique."""
    raw = load_detections()
    items = to_api_format(raw)

    for d in items:
        if d["challenge_id"] == challenge_id and d.get("remediation"):
            plan = d["remediation"]
            validated = validate_remediation(plan)
            return {
                "challenge_id": challenge_id,
                "plan": plan,
                "guardrail_validation": validated,
            }

    raise HTTPException(404, f"No remediation found for challenge '{challenge_id}'")
