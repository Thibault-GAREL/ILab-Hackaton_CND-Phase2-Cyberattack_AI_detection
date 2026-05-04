"""
Fetch OpenSearch supplementaire pour le contexte Bedrock (realtime).

Le batch pollé seul est souvent trop petit pour couvrir attack_start..attack_end+lookahead.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pandas as pd

from .config import (
    BEDROCK_OS_CONTEXT_MAX_DOCS,
    BEDROCK_OS_CONTEXT_PAD_MINUTES,
    BEDROCK_TIMELINE_LOOKAHEAD_MINUTES,
)
from .opensearch_connector import OpenSearchConnector


def _parse_attack_ts(s: str) -> datetime | None:
    try:
        s = str(s).strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s).astimezone(timezone.utc)
    except Exception:
        return None


def _fmt_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _merge_intervals(
    intervals: list[tuple[datetime, datetime]],
) -> list[tuple[datetime, datetime]]:
    if not intervals:
        return []
    s = sorted(intervals, key=lambda x: x[0])
    out: list[tuple[datetime, datetime]] = [s[0]]
    for a, b in s[1:]:
        la, lb = out[-1]
        if a <= lb:
            out[-1] = (la, max(lb, b))
        else:
            out.append((a, b))
    return out


def detection_time_windows(detections: list[dict]) -> list[tuple[datetime, datetime]]:
    pad = timedelta(minutes=BEDROCK_OS_CONTEXT_PAD_MINUTES)
    look = timedelta(minutes=BEDROCK_TIMELINE_LOOKAHEAD_MINUTES)
    intervals: list[tuple[datetime, datetime]] = []
    for d in detections:
        det = d.get("detection") or {}
        st = _parse_attack_ts(str(det.get("attack_start_time", "")))
        en = _parse_attack_ts(str(det.get("attack_end_time", "")))
        if st is None or en is None:
            continue
        intervals.append((st - pad, en + look))
    return _merge_intervals(intervals)


def _dedupe_subset_cols(df: pd.DataFrame) -> pd.DataFrame:
    cols = [
        "timestamp",
        "log_source",
        "source_ip",
        "destination_ip",
        "uri",
        "message",
        "auth_method",
        "status",
        "hostname",
    ]
    use = [c for c in cols if c in df.columns]
    if not use:
        return df.drop_duplicates()
    return df.drop_duplicates(subset=use, ignore_index=True)


def fetch_bedrock_context(
    connector: OpenSearchConnector,
    detections: list[dict],
    batch_df: pd.DataFrame,
) -> pd.DataFrame:
    """Union du batch courant et des logs OS sur les fenetres d attaque (dedupe)."""
    if not detections:
        return batch_df
    windows = detection_time_windows(detections)
    if not windows:
        return batch_df
    n = len(windows)
    per = max(1, BEDROCK_OS_CONTEXT_MAX_DOCS // n)
    dfs: list[pd.DataFrame] = []
    for w0, w1 in windows:
        gte, lte = _fmt_iso(w0), _fmt_iso(w1)
        try:
            chunk = connector.fetch_time_range(gte, lte, max_docs=per)
        except Exception as e:
            print(f"[Bedrock:OS context] fetch skip {gte}..{lte}: {e}")
            continue
        if not chunk.empty:
            dfs.append(chunk)
    parts = [batch_df] + dfs
    non_empty = [p for p in parts if not p.empty]
    if not non_empty:
        return batch_df
    out = pd.concat(non_empty, ignore_index=True)
    return _dedupe_subset_cols(out)
