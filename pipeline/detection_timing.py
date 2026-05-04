"""
detection_time_seconds : en mode slices (défaut), forcé à 0.

Si SCORING_BONUS_RAPIDITE_ENABLED=1 : délai depuis la preuve dans le batch ou wall-clock
selon les arguments passés à apply_detection_latency_seconds.
"""

from __future__ import annotations

import pandas as pd

from .config import SCORING_BONUS_RAPIDITE_ENABLED


def apply_detection_latency_seconds(
    detections: list[dict],
    batch_df: pd.DataFrame,
    pipeline_start_time: pd.Timestamp | None = None,
) -> None:
    """En place : met a jour detection_time_seconds pour chaque detection.

    Si SCORING_BONUS_RAPIDITE_ENABLED est désactivé (défaut, mode slices finale), force 0 partout.
    Sinon, si ``pipeline_start_time`` est fourni, mesure le wall-clock écoulé.
    """
    if not detections:
        return

    if not SCORING_BONUS_RAPIDITE_ENABLED:
        for d in detections:
            d["detection_time_seconds"] = 0
        return

    T = pd.Timestamp.now(tz="UTC")

    if pipeline_start_time is not None:
        wall_seconds = max(0, int((T - pipeline_start_time).total_seconds()))
        for d in detections:
            d["detection_time_seconds"] = wall_seconds
        return

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
