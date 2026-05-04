"""Schemas Pydantic pour la remediation."""

from typing import Any

from pydantic import BaseModel


class RemediationAction(BaseModel):
    id: str
    category: str
    aws_service: str
    title: str
    description: str
    automation_hint: str
    parameters: dict[str, Any] = {}
    guardrail_status: str = "pending"
    blocked_reason: str | None = None


class RemediationPlan(BaseModel):
    version: str
    challenge_id: str
    attack_type: str
    summary: str
    actions: list[RemediationAction]


class GuardrailValidationRequest(BaseModel):
    remediation_plan: dict[str, Any]


class GuardrailValidationResponse(BaseModel):
    validated: bool
    total_actions: int
    approved: int
    blocked: int
    needs_review: int
    actions: list[RemediationAction]
