"""
Empreinte des payloads de scoring pour eviter resoumissions identiques (penalite FP).

Cle stable : challenge_id, attack_type, fenetre, IPs, victimes (sans indicators Bedrock).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from config import SUBMIT_CACHE_FILE


def fingerprint_detection(payload: dict) -> str:
    det = payload.get("detection") or {}
    key = (
        str(payload.get("challenge_id", "")),
        str(det.get("attack_type", "")),
        str(det.get("attack_start_time", "")),
        str(det.get("attack_end_time", "")),
        tuple(det.get("attacker_ips") or []),
        tuple(det.get("victim_accounts") or []),
    )
    return hashlib.sha256(repr(key).encode("utf-8")).hexdigest()


def _load_set(path: str) -> set[str]:
    p = Path(path)
    if not p.exists():
        return set()
    try:
        data = json.loads(p.read_text())
        return set(data.get("fingerprints", []))
    except (json.JSONDecodeError, OSError):
        return set()


def _save_set(path: str, fps: set[str]) -> None:
    Path(path).write_text(
        json.dumps({"fingerprints": sorted(fps)}, indent=2),
        encoding="utf-8",
    )


def already_submitted(fingerprint: str, path: str | None = None) -> bool:
    path = path or SUBMIT_CACHE_FILE
    return fingerprint in _load_set(path)


def record_submission(fingerprint: str, path: str | None = None) -> None:
    path = path or SUBMIT_CACHE_FILE
    s = _load_set(path)
    s.add(fingerprint)
    _save_set(path, s)
