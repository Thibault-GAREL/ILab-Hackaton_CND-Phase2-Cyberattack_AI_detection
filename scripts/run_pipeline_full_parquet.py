#!/usr/bin/env python3
"""
Parcourt l'intégralité d'un export Parquet (logs-raw), reconstruit auth/app/net/sys,
puis exécute la même chaîne que le poll OpenSearch : détecteurs → dedup → Bedrock →
DS1 → timing → remédiation, et écrit detections.json + detections_api.json.

Usage (depuis la racine du dépôt) :
  .venv/bin/python scripts/run_pipeline_full_parquet.py
  .venv/bin/python scripts/run_pipeline_full_parquet.py --parquet data/opensearch-export/logs-raw-merged.parquet --batch-rows 400000

La lecture est par lots pour limiter la mémoire ; le résultat concaténé peut être
lourd (~21M lignes) — prévoir suffisamment de RAM.
"""

from __future__ import annotations

import argparse
import gc
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pandas as pd
import pyarrow.parquet as pq

from pipeline.detection_run import run_detection_chain
from pipeline.pipeline import write_detection_files
from pipeline.pipeline_core import (
    AUTH_COLS,
    APP_COLS,
    NET_COLS,
    SYS_COLS,
    split_logs_frame,
)


def _needed_columns(schema_names: list[str]) -> list[str]:
    want = set(AUTH_COLS) | set(APP_COLS) | set(NET_COLS) | set(SYS_COLS) | {"log_source"}
    return [c for c in schema_names if c in want]


def load_full_parquet_split(
    parquet_path: Path,
    batch_rows: int,
    max_total_rows: int | None = None,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    pf = pq.ParquetFile(parquet_path)
    meta = pf.metadata
    total = meta.num_rows
    if max_total_rows is not None:
        total = min(total, max_total_rows)
    names = [meta.schema.column(i).name for i in range(meta.num_columns)]
    cols = _needed_columns(names)
    if "log_source" not in cols:
        raise SystemExit("Colonne log_source absente du Parquet.")

    auth_chunks: list[pd.DataFrame] = []
    auth_fail_chunks: list[pd.DataFrame] = []
    app_chunks: list[pd.DataFrame] = []
    net_chunks: list[pd.DataFrame] = []
    sys_chunks: list[pd.DataFrame] = []

    t0 = time.perf_counter()
    read = 0
    for batch in pf.iter_batches(batch_size=batch_rows, columns=cols):
        df = batch.to_pandas()
        if max_total_rows is not None:
            remain = max_total_rows - read
            if remain <= 0:
                break
            if len(df) > remain:
                df = df.iloc[:remain].copy()
        read += len(df)
        aa, af, app, net, sys = split_logs_frame(df)
        del df
        if not aa.empty:
            auth_chunks.append(aa)
        if not af.empty:
            auth_fail_chunks.append(af)
        if not app.empty:
            app_chunks.append(app)
        if not net.empty:
            net_chunks.append(net)
        if not sys.empty:
            sys_chunks.append(sys)
        elapsed = time.perf_counter() - t0
        cap = f"{read:,} / {total:,}"
        if max_total_rows is not None:
            cap = f"{read:,} / {min(max_total_rows, meta.num_rows):,} (plafond)"
        print(f"[Parquet] {cap} lignes lues ({elapsed:.1f}s)", flush=True)
        gc.collect()
        if max_total_rows is not None and read >= max_total_rows:
            break

    def _cat(parts: list[pd.DataFrame], name: str) -> pd.DataFrame:
        if not parts:
            return pd.DataFrame()
        print(f"[Parquet] concat {name} ({len(parts)} fragments)...", flush=True)
        return pd.concat(parts, ignore_index=True)

    auth_all = _cat(auth_chunks, "auth_all")
    auth_failures = _cat(auth_fail_chunks, "auth_failures")
    app_all = _cat(app_chunks, "app_all")
    net_all = _cat(net_chunks, "net_all")
    sys_all = _cat(sys_chunks, "sys_all")

    print(
        f"[Parquet] Terminé en {time.perf_counter() - t0:.1f}s — "
        f"auth={len(auth_all):,} app={len(app_all):,} net={len(net_all):,} sys={len(sys_all):,}",
        flush=True,
    )
    return auth_all, auth_failures, app_all, net_all, sys_all


def main() -> None:
    ap = argparse.ArgumentParser(description="Pipeline complète sur Parquet entier")
    ap.add_argument(
        "--parquet",
        type=Path,
        default=ROOT / "data/opensearch-export/logs-raw-merged.parquet",
        help="Chemin vers logs-raw-merged.parquet",
    )
    ap.add_argument(
        "--batch-rows",
        type=int,
        default=400_000,
        help="Taille de lot lecture PyArrow (défaut 400000)",
    )
    ap.add_argument(
        "--max-total-rows",
        type=int,
        default=None,
        help="Nombre maximal de lignes brutes à lire depuis le Parquet (arrêt anticipé).",
    )
    args = ap.parse_args()

    if not args.parquet.is_file():
        print(f"Fichier introuvable : {args.parquet}", file=sys.stderr)
        sys.exit(1)

    auth_all, auth_failures, app_all, net_all, sys_all = load_full_parquet_split(
        args.parquet,
        args.batch_rows,
        max_total_rows=args.max_total_rows,
    )

    # DataFrame « brut » minimal pour detection_time_seconds (timestamps + source_ip)
    batch_df_cols = ["timestamp", "source_ip"]
    parts = [auth_all, app_all, net_all, sys_all]
    batch_df = pd.concat(
        [p[batch_df_cols] for p in parts if not p.empty and set(batch_df_cols) <= set(p.columns)],
        ignore_index=True,
    )
    if "timestamp" in batch_df.columns:
        batch_df["timestamp"] = pd.to_datetime(batch_df["timestamp"], utc=True, errors="coerce")

    t_chain = time.perf_counter()
    attacks = run_detection_chain(
        auth_all,
        auth_failures,
        app_all,
        net_all,
        sys_all,
        use_dedup=True,
        connector=None,
        batch_df=batch_df,
    )
    print(f"[Pipeline] Chaîne terminée en {time.perf_counter() - t_chain:.1f}s — {len(attacks)} détection(s)")
    write_detection_files(attacks)


if __name__ == "__main__":
    main()
