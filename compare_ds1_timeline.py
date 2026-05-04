#!/usr/bin/env python3
"""
Compare timelines in detections.json vs Dataset_log/ground-truth-ds1.json.
Buckets hackathon-oriented: <=300s, 300-600s, >600s (absolute delta on start/end vs GT).
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def _parse_concat_json(filepath: Path) -> list[dict]:
    raw = filepath.read_text().strip()
    parts: list[str] = []
    depth = 0
    start: int | None = None
    for i, ch in enumerate(raw):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                parts.append(raw[start : i + 1])
                start = None
    return [json.loads(p) for p in parts]


def _ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def _bucket(delta_s: float) -> str:
    a = abs(delta_s)
    if a <= 300:
        return "<=5min"
    if a <= 600:
        return "5-10min"
    return ">10min"


def main() -> int:
    root = Path(__file__).resolve().parent
    det_path = root / "detections.json"
    gt_path = root / "Dataset_log" / "ground-truth-ds1.json"
    if not det_path.exists():
        print("Missing detections.json", file=sys.stderr)
        return 1
    if not gt_path.exists():
        print("Missing ground-truth-ds1.json", file=sys.stderr)
        return 1

    detections = json.loads(det_path.read_text())
    gt_objs = _parse_concat_json(gt_path)
    gt = {o["_source"]["challenge_id"]: o["_source"] for o in gt_objs}

    for d in detections:
        cid = d["challenge_id"]
        g = gt[cid]
        ds = d["detection"]
        gt_s = _ts(g["attack_window"]["start"])
        gt_e = _ts(g["attack_window"]["end"])
        pd_s = _ts(ds["attack_start_time"])
        pd_e = _ts(ds["attack_end_time"])
        sd = (pd_s - gt_s).total_seconds()
        ed = (pd_e - gt_e).total_seconds()
        print(
            f"{cid}: start_delta_s={int(sd)} ({_bucket(sd)}), "
            f"end_delta_s={int(ed)} ({_bucket(ed)})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
