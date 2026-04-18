"""
Pipeline principale de detection d'attaques (dataset local parquet).

Lit le dataset par chunks, accumule les logs par type,
lance les detecteurs heuristiques, deduplique, enrichit via Bedrock,
et sauvegarde le resultat dans detections.json.

Usage :
    python pipeline.py
    python pipeline.py --no-bedrock   # saute l'enrichissement LLM
    python pipeline.py --no-dedup     # saute la deduplication
"""

import time
import json
import argparse
import pyarrow.parquet as pq
import pandas as pd

from config import PARQUET_PATH, PARQUET_BATCH_SIZE, BEDROCK_ENABLED
from detectors import (
    detect_brute_force,
    detect_credential_stuffing,
    detect_port_scan,
    detect_network_recon,
    detect_account_takeover,
)
from detectors.dedup import deduplicate
from bedrock_analysis import enrich_detections

# Colonnes gardees par source (reduit la RAM des buffers)
AUTH_COLS = ["timestamp", "source_ip", "username", "status", "failure_reason",
             "auth_method", "destination_port"]
APP_COLS  = ["timestamp", "source_ip", "username", "status_code",
             "http_method", "uri", "user_agent"]
NET_COLS  = ["timestamp", "source_ip", "destination_ip", "destination_port",
             "action", "protocol"]


def load_logs(parquet_path: str):
    """
    Lit le parquet par chunks.
    Retourne (auth_all, auth_failures, app_401, net_all).
    auth_all   : tous les logs auth (pour account_takeover).
    auth_failures : uniquement status=failure (pour brute_force).
    """
    auth_all_chunks, auth_fail_chunks = [], []
    app_chunks, net_chunks = [], []

    pf = pq.ParquetFile(parquet_path)
    total_rows = pf.metadata.num_rows
    processed  = 0

    print(f"Reading {total_rows:,} rows in chunks of {PARQUET_BATCH_SIZE:,}...")

    for batch in pf.iter_batches(batch_size=PARQUET_BATCH_SIZE):
        df  = batch.to_pandas()
        processed += len(df)
        src = df["log_source"]

        auth = df[src == "authentication"][AUTH_COLS].copy()
        auth_all_chunks.append(auth)
        auth_fail_chunks.append(auth[auth["status"] == "failure"])

        app = df[src == "application"][APP_COLS].copy()
        app_chunks.append(app[app["status_code"] == 401])

        net_chunks.append(df[src == "network"][NET_COLS].copy())

        pct = processed / total_rows * 100
        print(f"  {processed:>12,} / {total_rows:,}  ({pct:.1f}%)", end="\r")

    print()

    auth_all      = pd.concat(auth_all_chunks,  ignore_index=True)
    auth_failures = pd.concat(auth_fail_chunks, ignore_index=True)
    app_df        = pd.concat(app_chunks,        ignore_index=True)
    net_df        = pd.concat(net_chunks,        ignore_index=True)

    print(
        f"Auth total={len(auth_all):,}  failures={len(auth_failures):,} | "
        f"HTTP 401={len(app_df):,} | Network={len(net_df):,}"
    )
    return auth_all, auth_failures, app_df, net_df


def run_detectors(
    auth_failures: pd.DataFrame,
    app_df: pd.DataFrame,
    net_df: pd.DataFrame,
    auth_all: pd.DataFrame | None = None,
    net_rejects: pd.DataFrame | None = None,
) -> list[dict]:
    """Lance tous les detecteurs et retourne la liste des detections brutes."""
    t0 = time.time()

    if net_rejects is None:
        net_rejects = net_df[net_df["action"] == "reject"].copy() \
            if not net_df.empty and "action" in net_df.columns else pd.DataFrame()

    steps = [
        ("Brute force",        lambda: detect_brute_force(auth_failures)),
        ("Credential stuffing", lambda: detect_credential_stuffing(app_df)),
        ("Port scan",          lambda: detect_port_scan(net_df)),
        ("Network recon",      lambda: detect_network_recon(net_rejects)),
        ("Account takeover",   lambda: detect_account_takeover(
            auth_all if auth_all is not None else auth_failures
        )),
    ]

    attacks = []
    for name, fn in steps:
        print(f"[Detection] {name}...")
        found = fn()
        print(f"  -> {len(found)} attack(s)")
        attacks.extend(found)

    elapsed = int(time.time() - t0)
    for a in attacks:
        a["detection_time_seconds"] = elapsed

    return attacks


def main(use_bedrock: bool = True, use_dedup: bool = True):
    t_start = time.time()

    auth_all, auth_failures, app_df, net_df = load_logs(PARQUET_PATH)
    net_rejects = net_df[net_df["action"] == "reject"].copy() \
        if not net_df.empty else pd.DataFrame()

    attacks = run_detectors(auth_failures, app_df, net_df,
                            auth_all=auth_all, net_rejects=net_rejects)

    if use_dedup:
        attacks = deduplicate(attacks)

    if use_bedrock and BEDROCK_ENABLED and attacks:
        # Reconstitue un DataFrame minimal pour l'echantillonnage Bedrock
        sample_df = pd.concat([auth_all, app_df, net_df], ignore_index=True)
        attacks = enrich_detections(attacks, sample_df)

    total_time = int(time.time() - t_start)
    print(f"\n{len(attacks)} detection(s) in {total_time}s")

    with open("detections.json", "w") as f:
        json.dump(attacks, f, indent=2, ensure_ascii=False)
    print("Saved to detections.json")

    return attacks


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-bedrock", action="store_true")
    parser.add_argument("--no-dedup",   action="store_true")
    args = parser.parse_args()
    main(use_bedrock=not args.no_bedrock, use_dedup=not args.no_dedup)
