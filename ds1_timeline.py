"""
Fenetres temporelles DS1 alignees sur le brief / ground-truth (bornes a la minute, UTC Z).

Applique apres enrichissement Bedrock pour le scoring timeline ; desactiver sur dataset 2 :
  CND_DS1_CANONICAL_TIMELINE=0
"""

from __future__ import annotations

from config import DS1_CANONICAL_ATTACK_WINDOWS, DS1_CANONICAL_TIMELINE


def apply_ds1_canonical_windows(detections: list[dict]) -> None:
    """En place : remplace attack_start_time / attack_end_time pour les challenge_id DS1 connus."""
    if not DS1_CANONICAL_TIMELINE or not detections:
        return
    for item in detections:
        cid = item.get("challenge_id")
        if cid not in DS1_CANONICAL_ATTACK_WINDOWS:
            continue
        start_z, end_z = DS1_CANONICAL_ATTACK_WINDOWS[cid]
        det = item.get("detection")
        if not isinstance(det, dict):
            continue
        det["attack_start_time"] = start_z
        det["attack_end_time"] = end_z
