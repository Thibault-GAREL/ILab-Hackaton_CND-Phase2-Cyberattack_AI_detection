"""
Bridge entre le backend FastAPI et le module pipeline/.

Charge les detections depuis detections.json (genere par la pipeline)
et expose les fonctions de conversion pour les routes API.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from app.repo_paths import find_repo_root
from app.config import settings
from app.schemas.detection import (
    DEFAULT_TIMEOUT_S,
    PipelineRunRequest,
    MAX_TIMEOUT_S,
)

logger = logging.getLogger(__name__)

_DETECTIONS_CACHE: list[dict] | None = None
_DETECTIONS_MTIME: float = 0.0

_LOG_TAIL = 6000


def _repo_root() -> Path:
    return find_repo_root()


def _detections_path() -> Path:
    p = Path(settings.detections_json_path)
    if p.is_absolute():
        return p
    return _repo_root() / p


def load_detections(force_reload: bool = False) -> list[dict]:
    global _DETECTIONS_CACHE, _DETECTIONS_MTIME

    path = _detections_path()
    if not path.exists():
        return []

    mtime = path.stat().st_mtime
    if not force_reload and _DETECTIONS_CACHE is not None and mtime == _DETECTIONS_MTIME:
        return _DETECTIONS_CACHE

    try:
        data = json.loads(path.read_text())
        _DETECTIONS_CACHE = data if isinstance(data, list) else []
        _DETECTIONS_MTIME = mtime
        return _DETECTIONS_CACHE
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Failed to load %s: %s", path, e)
        return _DETECTIONS_CACHE or []


def severity_from_detection(det: dict) -> str:
    indicators = det.get("detection", {}).get("indicators", {})
    if "severity" in indicators:
        return indicators["severity"]
    attack = det.get("detection", {}).get("attack_type", "")
    if attack in ("ssh_brute_force", "credential_stuffing"):
        return "critical"
    if attack in ("sql_injection", "ssrf"):
        return "high"
    return "medium"


def to_api_format(raw: list[dict]) -> list[dict[str, Any]]:
    out = []
    for i, d in enumerate(raw):
        det = d.get("detection", {})
        out.append({
            "id": i,
            "challenge_id": d.get("challenge_id", ""),
            "attack_type": det.get("attack_type", ""),
            "attacker_ips": det.get("attacker_ips", []),
            "victim_accounts": det.get("victim_accounts", []),
            "start_time": det.get("attack_start_time", ""),
            "end_time": det.get("attack_end_time", ""),
            "severity": severity_from_detection(d),
            "detection_time_seconds": d.get("detection_time_seconds", 0),
            "indicators": det.get("indicators", {}),
            "remediation": d.get("remediation"),
        })
    return out


def _tail(text: str | None, n: int = _LOG_TAIL) -> str:
    if not text:
        return ""
    t = text.strip()
    if len(t) <= n:
        return t
    return "…\n" + t[-n:]


def _resolve_parquet_path(raw: str | None) -> Path:
    root = _repo_root()
    if not raw or not str(raw).strip():
        return root / "data" / "opensearch-export" / "logs-raw-merged.parquet"
    p = Path(raw.strip())
    if not p.is_absolute():
        p = (root / p).resolve()
    else:
        p = p.resolve()
    root_r = root.resolve()
    try:
        p.relative_to(root_r)
    except ValueError as e:
        raise ValueError("parquet_path doit rester sous la racine du dépôt") from e
    return p


def _build_opensearch_cmd(req: PipelineRunRequest) -> list[str]:
    cmd: list[str] = [sys.executable, "-m", "pipeline"]
    if req.max_lines is not None:
        cmd.extend(["--max-docs", str(req.max_lines)])
    if req.no_dedup:
        cmd.append("--no-dedup")
    if req.reset_state:
        cmd.append("--reset-state")
    if req.dry_run_state:
        cmd.append("--dry-run-state")
    if req.accumulate:
        cmd.append("--accumulate")
    if req.submit:
        cmd.append("--submit")
    if req.submit_dry_run:
        cmd.append("--submit-dry-run")
    return cmd


def _build_parquet_cmd(req: PipelineRunRequest) -> list[str]:
    pq = _resolve_parquet_path(req.parquet_path)
    cmd: list[str] = [
        sys.executable,
        str(_repo_root() / "scripts" / "run_pipeline_full_parquet.py"),
        "--parquet",
        str(pq),
        "--batch-rows",
        str(req.parquet_batch_rows),
    ]
    if req.max_lines is not None:
        cmd.extend(["--max-total-rows", str(req.max_lines)])
    return cmd


def _pipeline_env(req: PipelineRunRequest) -> dict[str, str]:
    env = os.environ.copy()
    # Complète os.environ (ECS / shell) avec les clés optionnelles du backend (.env chargé par Pydantic).
    _OS_FROM_SETTINGS: tuple[tuple[str, str], ...] = (
        ("opensearch_auth", "OPENSEARCH_AUTH"),
        ("opensearch_basic_user", "OPENSEARCH_BASIC_USER"),
        ("opensearch_basic_password", "OPENSEARCH_BASIC_PASSWORD"),
        ("opensearch_host", "OPENSEARCH_HOST"),
    )
    for attr, key in _OS_FROM_SETTINGS:
        val = getattr(settings, attr, None)
        if val is not None and str(val).strip():
            env[key] = str(val).strip()
    if req.bedrock_enabled is not None:
        env["BEDROCK_ENABLED"] = "1" if req.bedrock_enabled else "0"
    if req.model_id and str(req.model_id).strip():
        env["BEDROCK_MODEL_ID"] = str(req.model_id).strip()
    return env


def _default_timeout(req: PipelineRunRequest) -> int:
    if req.timeout_seconds is not None:
        return min(req.timeout_seconds, MAX_TIMEOUT_S)
    if req.source == "parquet":
        if (req.max_lines or 0) > 50_000:
            return min(3600, MAX_TIMEOUT_S)
        return DEFAULT_TIMEOUT_S
    return DEFAULT_TIMEOUT_S


def run_pipeline_job(req: PipelineRunRequest) -> dict[str, Any]:
    """Lance OpenSearch (`python -m pipeline`) ou le script Parquet selon `source`."""
    root = _repo_root()
    try:
        if req.source == "parquet":
            pq_path = _resolve_parquet_path(req.parquet_path)
        else:
            pq_path = None
    except ValueError as e:
        return {
            "status": "error",
            "detections_count": len(load_detections()),
            "message": str(e),
            "source": req.source,
            "stdout_tail": "",
            "stderr_tail": "",
        }

    if req.source == "parquet" and pq_path is not None:
        if not pq_path.is_file():
            return {
                "status": "error",
                "detections_count": len(load_detections()),
                "message": f"Fichier Parquet introuvable : {pq_path}",
                "source": "parquet",
                "stdout_tail": "",
                "stderr_tail": "",
            }
        cmd = _build_parquet_cmd(req)
    else:
        cmd = _build_opensearch_cmd(req)

    timeout = _default_timeout(req)
    env = _pipeline_env(req)

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(root),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        load_detections(force_reload=True)
        n = len(load_detections())
        out_msg = (proc.stdout or "").strip()
        err_msg = (proc.stderr or "").strip()
        ok = proc.returncode == 0
        msg = (
            f"{n} détection(s) — terminé (code {proc.returncode})."
            if ok
            else ((err_msg or out_msg)[:2000] or f"exit code {proc.returncode}")
        )
        return {
            "status": "success" if ok else "error",
            "detections_count": n,
            "message": msg,
            "source": req.source,
            "stdout_tail": _tail(proc.stdout),
            "stderr_tail": _tail(proc.stderr),
        }
    except subprocess.TimeoutExpired:
        logger.exception("Pipeline timeout source=%s", req.source)
        return {
            "status": "error",
            "detections_count": len(load_detections()),
            "message": f"Timeout (>{timeout}s)",
            "source": req.source,
            "stdout_tail": "",
            "stderr_tail": "",
        }
    except Exception as e:
        logger.exception("Pipeline failed source=%s", req.source)
        return {
            "status": "error",
            "detections_count": len(load_detections()),
            "message": str(e),
            "source": req.source,
            "stdout_tail": "",
            "stderr_tail": "",
        }


def run_pipeline_poll(
    *,
    bedrock_enabled: bool | None = None,
    model_id: str | None = None,
) -> dict[str, Any]:
    """Compat : lancement pipeline OpenSearch sans options avancées."""
    req = PipelineRunRequest(bedrock_enabled=bedrock_enabled, model_id=model_id)
    return run_pipeline_job(req)
