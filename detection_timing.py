"""
Bonus rapidite : detection_time_seconds = delai depuis la preuve dans les logs (batch courant).

Utilise le plus ancien timestamp parmi les lignes dont source_ip est dans attacker_ips ;
sinon min(timestamp) du batch.
"""

from __future__ import annotations

import pandas as pd


def apply_detection_latency_seconds(
    detections: list[dict], batch_df: pd.DataFrame
) -> None:
    """En place : met a jour detection_time_seconds pour chaque detection."""
    if not detections:
        return
    T = pd.Timestamp.now(tz="UTC")
    if batch_df.empty or "timestamp" not in batch_df.columns:
        for d in detections:
            d["detection_time_seconds"] = 0
        return

    ts_all = pd.to_datetime(batch_df["timestamp"], utc=True, errors="coerce")
    batch_floor = ts_all.min()
    if pd.isna(batch_floor):
        batch_floor = T

    for d in detections:
        det = d.get("detection")
        if not isinstance(det, dict):
            d["detection_time_seconds"] = 0
            continue
        ips = det.get("attacker_ips") or []
        evidence = None
        if ips and "source_ip" in batch_df.columns:
            m = batch_df["source_ip"].astype(str).isin([str(x) for x in ips])
            sub = ts_all.loc[m]
            if not sub.empty:
                evidence = sub.min()
        if evidence is None or pd.isna(evidence):
            evidence = batch_floor
        if pd.isna(evidence):
            evidence = T
        if getattr(evidence, "tzinfo", None) is None:
            evidence = evidence.tz_localize("UTC")
        else:
            evidence = evidence.tz_convert("UTC")
        delta = (T - evidence).total_seconds()
        d["detection_time_seconds"] = max(0, int(delta))
