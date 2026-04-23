"""
Bridge API entre la pipeline de détection Phase 2 et le backend/frontend Phase 1.

Expose les détections via un router FastAPI compatible avec le backend existant,
et fournit des fonctions de conversion pour le frontend Streamlit.

Usage standalone :
    uvicorn detection_api:app --port 8081

Usage intégré au backend Phase 1 :
    from detection_api import detections_router
    app.include_router(detections_router)
"""

import json
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, APIRouter, Query
from pydantic import BaseModel

DETECTIONS_FILE = Path("detections.json")

# ---------------------------------------------------------------------------
# Pydantic schemas (format compatible frontend Streamlit)
# ---------------------------------------------------------------------------

class DetectionSummary(BaseModel):
    id: int
    challenge_id: str
    attack_type: str
    attacker_ips: list[str]
    victim_accounts: list[str]
    start_time: str
    end_time: str
    severity: str
    indicators: dict

class DetectionsResponse(BaseModel):
    total: int
    detections: list[DetectionSummary]


# ---------------------------------------------------------------------------
# Conversion pipeline → API
# ---------------------------------------------------------------------------

def _severity_from_detection(det: dict) -> str:
    """Déduit la sévérité depuis les indicateurs."""
    indicators = det.get("detection", {}).get("indicators", {})
    # Sévérité explicite (ajoutée par Bedrock)
    if "severity" in indicators:
        return indicators["severity"]
    # Heuristique basée sur le type
    attack = det.get("detection", {}).get("attack_type", "")
    if attack in ("ssh_brute_force", "credential_stuffing"):
        return "critical"
    if attack in ("sql_injection", "ssrf"):
        return "high"
    return "medium"


def load_detections(path: Path = DETECTIONS_FILE) -> list[dict]:
    """Charge les détections brutes depuis le JSON."""
    if not path.exists():
        return []
    with open(path) as f:
        return json.load(f)


def to_api_format(raw: list[dict]) -> list[DetectionSummary]:
    """Convertit les détections pipeline en format API."""
    out = []
    for i, d in enumerate(raw):
        det = d.get("detection", {})
        out.append(DetectionSummary(
            id=i,
            challenge_id=d.get("challenge_id", ""),
            attack_type=det.get("attack_type", ""),
            attacker_ips=det.get("attacker_ips", []),
            victim_accounts=det.get("victim_accounts", []),
            start_time=det.get("attack_start_time", ""),
            end_time=det.get("attack_end_time", ""),
            severity=_severity_from_detection(d),
            indicators=det.get("indicators", {}),
        ))
    return out


# ---------------------------------------------------------------------------
# FastAPI router (branchable sur le backend Phase 1)
# ---------------------------------------------------------------------------

detections_router = APIRouter(prefix="/v1/detections", tags=["detections"])


@detections_router.get("", response_model=DetectionsResponse)
async def list_detections(
    attack_type: Optional[str] = Query(None, description="Filtrer par type d'attaque"),
    severity: Optional[str] = Query(None, description="Filtrer par sévérité"),
):
    """Liste toutes les détections, avec filtres optionnels."""
    raw = load_detections()
    items = to_api_format(raw)
    if attack_type:
        items = [d for d in items if d.attack_type == attack_type]
    if severity:
        items = [d for d in items if d.severity == severity]
    return DetectionsResponse(total=len(items), detections=items)


@detections_router.get("/{detection_id}", response_model=DetectionSummary)
async def get_detection(detection_id: int):
    """Récupère une détection par son index."""
    raw = load_detections()
    items = to_api_format(raw)
    if detection_id < 0 or detection_id >= len(items):
        from fastapi import HTTPException
        raise HTTPException(404, "Detection not found")
    return items[detection_id]


@detections_router.get("/stats/summary")
async def detections_stats():
    """Statistiques agrégées des détections (pour le dashboard Streamlit)."""
    raw = load_detections()
    items = to_api_format(raw)
    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    all_ips: set[str] = set()
    for d in items:
        by_type[d.attack_type] = by_type.get(d.attack_type, 0) + 1
        by_severity[d.severity] = by_severity.get(d.severity, 0) + 1
        all_ips.update(d.attacker_ips)
    return {
        "total_detections": len(items),
        "by_attack_type": by_type,
        "by_severity": by_severity,
        "unique_attacker_ips": len(all_ips),
    }


# ---------------------------------------------------------------------------
# Standalone app (pour tester sans le backend Phase 1)
# ---------------------------------------------------------------------------

app = FastAPI(title="CND Phase 2 — Detection API", version="0.1.0")
app.include_router(detections_router)
