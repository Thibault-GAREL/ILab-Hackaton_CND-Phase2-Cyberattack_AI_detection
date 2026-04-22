"""
Deduplication des detections qui se chevauchent (meme IP, fenetres temporelles qui
se recoupent). Trois strategies configurables via DEDUP_STRATEGY dans config.py :

  "none"               -> aucune dedup, tout est soumis tel quel
  "keep_most_specific" -> une detection par (IP, fenetre), la plus specifique gagne
  "merge"              -> fusion en une seule detection multi-vecteur par (IP, fenetre)
"""

from __future__ import annotations
import copy
from datetime import datetime, timezone
from config import DEDUP_STRATEGY, DEDUP_OVERLAP_MINUTES

# Ordre de specificite : plus l'indice est bas, plus le type est prioritaire
SPECIFICITY = {
    "ssh_brute_force":     0,
    "credential_stuffing": 1,
    "sql_injection":       2,
    "directory_traversal": 3,
    "ssrf":                4,
}


def _parse_ts(ts_str: str) -> datetime:
    return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _overlap(a: dict, b: dict, window_minutes: int) -> bool:
    """Retourne True si les deux detections de la meme IP se chevauchent."""
    a_ips = set(a["detection"]["attacker_ips"])
    b_ips = set(b["detection"]["attacker_ips"])
    if not a_ips & b_ips:
        return False

    a_start = _parse_ts(a["detection"]["attack_start_time"])
    a_end   = _parse_ts(a["detection"]["attack_end_time"])
    b_start = _parse_ts(b["detection"]["attack_start_time"])
    b_end   = _parse_ts(b["detection"]["attack_end_time"])

    from datetime import timedelta
    margin = timedelta(minutes=window_minutes)

    # Chevauchement si l'un commence avant que l'autre (+ marge) ne finisse
    return a_start <= b_end + margin and b_start <= a_end + margin


def _merge_two(a: dict, b: dict) -> dict:
    """Fusionne deux detections en une detection multi-vecteur."""
    merged = copy.deepcopy(a)
    det_a = a["detection"]
    det_b = b["detection"]

    # Types combines
    types = sorted({det_a["attack_type"], det_b["attack_type"]})
    merged["detection"]["attack_type"] = "+".join(types)

    # Union des IPs et comptes
    merged["detection"]["attacker_ips"] = sorted(
        set(det_a["attacker_ips"]) | set(det_b["attacker_ips"])
    )
    merged["detection"]["victim_accounts"] = sorted(
        set(det_a["victim_accounts"]) | set(det_b["victim_accounts"])
    )

    # Timeline elargie
    starts = [_parse_ts(det_a["attack_start_time"]), _parse_ts(det_b["attack_start_time"])]
    ends   = [_parse_ts(det_a["attack_end_time"]),   _parse_ts(det_b["attack_end_time"])]
    merged["detection"]["attack_start_time"] = min(starts).strftime("%Y-%m-%dT%H:%M:%SZ")
    merged["detection"]["attack_end_time"]   = max(ends).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Fusion des indicateurs (prefixe par type pour eviter les collisions)
    merged_indicators = {f"{det_a['attack_type']}_{k}": v
                         for k, v in det_a["indicators"].items()}
    merged_indicators.update({f"{det_b['attack_type']}_{k}": v
                               for k, v in det_b["indicators"].items()})
    merged["detection"]["indicators"] = merged_indicators

    return merged


def _keep_most_specific(group: list[dict]) -> dict:
    """Retourne la detection la plus specifique du groupe."""
    return min(
        group,
        key=lambda d: SPECIFICITY.get(d["detection"]["attack_type"], 99),
    )


def deduplicate(detections: list[dict]) -> list[dict]:
    """
    Applique la strategie de deduplication configuree.
    Retourne la liste dedupliquee.
    """
    if DEDUP_STRATEGY == "none" or len(detections) <= 1:
        return detections

    # Regrouper les detections qui se chevauchent en clusters
    clusters: list[list[dict]] = []
    used = [False] * len(detections)

    for i, det in enumerate(detections):
        if used[i]:
            continue
        cluster = [det]
        used[i] = True
        for j in range(i + 1, len(detections)):
            if not used[j] and _overlap(det, detections[j], DEDUP_OVERLAP_MINUTES):
                cluster.append(detections[j])
                used[j] = True
        clusters.append(cluster)

    result = []
    for cluster in clusters:
        if len(cluster) == 1:
            result.append(cluster[0])
        elif DEDUP_STRATEGY == "keep_most_specific":
            result.append(_keep_most_specific(cluster))
        elif DEDUP_STRATEGY == "merge":
            merged = cluster[0]
            for other in cluster[1:]:
                merged = _merge_two(merged, other)
            result.append(merged)
        else:
            result.extend(cluster)  # fallback = none

    n_before = len(detections)
    n_after  = len(result)
    if n_before != n_after:
        print(f"[Dedup] {n_before} -> {n_after} detections (strategy={DEDUP_STRATEGY})")

    return result
