#!/usr/bin/env python3
"""Benchmark Parquet + charge/détecteurs/dedup (sans appel Bedrock — mesure perf). Run complet : `python pipeline.py`."""

from __future__ import annotations

import argparse
import json
import resource
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pandas as pd
import pyarrow.parquet as pq

from pipeline import config  # noqa: E402
from pipeline import pipeline_core  # noqa: E402
from pipeline.detectors.dedup import deduplicate  # noqa: E402
from pipeline.pipeline_core import split_logs_frame  # noqa: E402


def _rss_mb() -> float:
    ru = resource.getrusage(resource.RUSAGE_SELF)
    rss = ru.ru_maxrss
    if sys.platform == "darwin":
        return rss / (1024 * 1024)
    return rss / 1024


def analyze_parquet_chunks(path: Path, batch_size: int) -> dict:
    pf = pq.ParquetFile(path)
    meta = pf.metadata
    num_rows = meta.num_rows
    schema_cols = [meta.schema.column(i).name for i in range(meta.num_columns)]
    log_counts: Counter[str] = Counter()
    t_min: pd.Timestamp | None = None
    t_max: pd.Timestamp | None = None
    chunks = 0
    t0 = time.perf_counter()
    for batch in pf.iter_batches(batch_size=batch_size, columns=["timestamp", "log_source"]):
        chunks += 1
        df = batch.to_pandas()
        if "log_source" in df.columns:
            log_counts.update(df["log_source"].dropna().astype(str))
        if "timestamp" in df.columns:
            ts = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
            valid = ts.dropna()
            if not valid.empty:
                lo, hi = valid.min(), valid.max()
                t_min = lo if t_min is None or lo < t_min else t_min
                t_max = hi if t_max is None or hi > t_max else t_max
    elapsed = time.perf_counter() - t0
    return {
        "num_rows": num_rows,
        "num_columns": len(schema_cols),
        "schema_columns": schema_cols,
        "log_source_counts": dict(log_counts),
        "timestamp_min": str(t_min) if t_min is not None else None,
        "timestamp_max": str(t_max) if t_max is not None else None,
        "scan_chunks": chunks,
        "scan_wall_s": round(elapsed, 2),
        "rss_after_scan_mb": round(_rss_mb(), 1),
    }


def _load_logs_parquet(parquet_path: str, batch_size: int):
    """Charge un Parquet par chunks (bench local uniquement)."""
    auth_chunks, auth_fail_chunks = [], []
    app_chunks, net_chunks, sys_chunks = [], [], []
    pf = pq.ParquetFile(parquet_path)
    for batch in pf.iter_batches(batch_size=batch_size):
        df = batch.to_pandas()
        aa, af, app, net, sys = split_logs_frame(df)
        auth_chunks.append(aa)
        auth_fail_chunks.append(af)
        app_chunks.append(app)
        net_chunks.append(net)
        sys_chunks.append(sys)
    auth_all = pd.concat(auth_chunks, ignore_index=True)
    auth_failures = pd.concat(auth_fail_chunks, ignore_index=True)
    app_all = pd.concat(app_chunks, ignore_index=True)
    net_all = pd.concat(net_chunks, ignore_index=True)
    sys_all = pd.concat(sys_chunks, ignore_index=True)
    return auth_all, auth_failures, app_all, net_all, sys_all


def run_pipeline_benchmark_detectors(parquet_path: Path, batch_size: int) -> dict:
    rss0 = _rss_mb()
    t_load0 = time.perf_counter()
    auth_all, auth_failures, app_all, net_all, sys_all = _load_logs_parquet(
        str(parquet_path), batch_size
    )
    t_load = time.perf_counter() - t_load0
    t_det0 = time.perf_counter()
    attacks = pipeline_core.run_detectors(
        auth_failures, app_all, net_all, sys_all, auth_all=auth_all
    )
    t_det = time.perf_counter() - t_det0
    t_ded0 = time.perf_counter()
    attacks_dedup = deduplicate(attacks)
    t_ded = time.perf_counter() - t_ded0
    rss1 = _rss_mb()
    return {
        "load_s": round(t_load, 2),
        "detectors_s": round(t_det, 2),
        "dedup_s": round(t_ded, 2),
        "total_pipeline_s": round(t_load + t_det + t_ded, 2),
        "rss_start_mb": round(rss0, 1),
        "rss_peak_after_mb": round(rss1, 1),
        "frame_rows": {
            "auth_all": len(auth_all),
            "auth_failures": len(auth_failures),
            "app_all": len(app_all),
            "net_all": len(net_all),
            "sys_all": len(sys_all),
        },
        "detections_raw": len(attacks),
        "detections_after_dedup": len(attacks_dedup),
        "detections": attacks_dedup,
    }


def render_markdown(parquet_path: Path, scan: dict, run: dict, bedrock_cfg: bool) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        "# Rapport benchmark — scan Parquet + détecteurs + dedup (sans Bedrock)",
        "",
        f"- **Généré (UTC)** : {now}",
        f"- **Fichier Parquet** : `{parquet_path}`",
        f"- **BEDROCK_ENABLED (config)** : `{bedrock_cfg}` — ce benchmark n'appelle pas Bedrock ; run complet : `python pipeline.py`.",
        "",
        "## 1. Synthèse dataset (scan `timestamp` + `log_source`)",
        "",
        f"- **Lignes** : {scan['num_rows']:,}",
        f"- **Colonnes** : {scan['num_columns']}",
        f"- **Période** : `{scan['timestamp_min']}` → `{scan['timestamp_max']}`",
        f"- **Durée scan** : {scan['scan_wall_s']} s ({scan['scan_chunks']} chunks)",
        f"- **RSS après scan (approx.)** : {scan['rss_after_scan_mb']} MiB",
        "",
        "### Répartition `log_source`",
        "",
    ]
    for k, v in sorted(scan["log_source_counts"].items(), key=lambda x: -x[1]):
        pct = 100.0 * v / scan["num_rows"] if scan["num_rows"] else 0
        lines.append(f"- `{k}` : {v:,} ({pct:.2f} %)")
    lines += ["", "### Colonnes Parquet", "", "```", ", ".join(scan["schema_columns"]), "```", ""]
    lines += [
        "## 2. Pipeline — performance (load + détecteurs + dedup uniquement)",
        "",
        f"- **Chargement Parquet** : {run['load_s']} s",
        f"- **run_detectors** : {run['detectors_s']} s",
        f"- **deduplicate** : {run['dedup_s']} s",
        f"- **Total** : {run['total_pipeline_s']} s",
        f"- **RSS** : {run['rss_start_mb']} → {run['rss_peak_after_mb']} MiB",
        "",
        "### Frames",
        "",
    ]
    for k, v in run["frame_rows"].items():
        lines.append(f"- **{k}** : {v:,}")
    lines += [
        "",
        f"- **Détections brutes** : {run['detections_raw']}",
        f"- **Après dedup** : {run['detections_after_dedup']}",
        "",
        "## 3. Détections (JSON)",
        "",
        "```json",
        json.dumps(run["detections"], indent=2, ensure_ascii=False),
        "```",
        "",
        "## 4. Analyse",
        "",
        "- Scan léger : volume et plage temporelle sans charger les 33 colonnes.",
        "- Goulot typique : **chargement Parquet** (concat pandas). Détecteurs en RAM.",
        "- Ce script ne mesure pas Bedrock ni `apply_ds1_canonical_windows` ; utiliser `python pipeline.py` pour la chaîne complète.",
        "",
        "## 5. Commandes",
        "",
        "```bash",
        ".venv/bin/python scripts/benchmark_and_report.py",
        ".venv/bin/python pipeline.py",
        "```",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--parquet",
        type=Path,
        default=ROOT / "data" / "opensearch-export" / "logs-raw-merged.parquet",
        help="Parquet local (bench charge+détecteurs uniquement)",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=ROOT / "benchmark_pipeline_report.md",
    )
    ap.add_argument("--batch-size", type=int, default=config.PARQUET_BATCH_SIZE)
    args = ap.parse_args()
    if not args.parquet.exists():
        print(f"Introuvable: {args.parquet}", file=sys.stderr)
        return 1
    print("[1/3] Scan...")
    scan = analyze_parquet_chunks(args.parquet, args.batch_size)
    print("[2/3] Pipeline...")
    run = run_pipeline_benchmark_detectors(args.parquet, args.batch_size)
    print("[3/3] MD...")
    args.out.write_text(render_markdown(args.parquet.resolve(), scan, run, config.BEDROCK_ENABLED), encoding="utf-8")
    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
