"""
Pipeline principale de detection d'attaques (dataset local parquet).

Lit le dataset par chunks, accumule les logs par source,
lance les 5 detecteurs cibles, deduplique, enrichit via Bedrock,
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
    detect_credential_stuffing,
    detect_ssh_brute_force,
    detect_sql_injection,
    detect_directory_traversal,
    detect_ssrf,
)
from detectors.dedup import deduplicate
from bedrock_analysis import enrich_detections

AUTH_COLS = [
    "timestamp", "source_ip", "username", "status", "failure_reason",
    "auth_method", "destination_port", "geolocation_country",
]
APP_COLS = [
    "timestamp", "source_ip", "username", "status_code",
    "http_method", "uri", "user_agent", "response_size",
]
NET_COLS = [
    "timestamp", "source_ip", "destination_ip", "destination_port",
    "action", "protocol", "bytes_sent", "bytes_received",
]
SYS_COLS = [
    "timestamp", "source_ip", "hostname", "process", "pid",
    "message", "severity", "username",
]


def _safe_cols(df: pd.DataFrame, cols: list[str]) -> list[str]:
    """Retourne uniquement les colonnes qui existent dans le DataFrame."""
    return [c for c in cols if c in df.columns]


def load_logs(parquet_path: str):
    """
    Lit le parquet par chunks.
    Retourne (auth_all, auth_failures, app_all, net_all, sys_all).
    """
    auth_chunks, auth_fail_chunks = [], []
    app_chunks, net_chunks, sys_chunks = [], [], []

    pf = pq.ParquetFile(parquet_path)
    total_rows = pf.metadata.num_rows
    processed = 0

    print(f"Reading {total_rows:,} rows in chunks of {PARQUET_BATCH_SIZE:,}...")

    for batch in pf.iter_batches(batch_size=PARQUET_BATCH_SIZE):
        df = batch.to_pandas()
        processed += len(df)
        src = df["log_source"]

        auth = df[src == "authentication"][_safe_cols(df, AUTH_COLS)].copy()
        auth_chunks.append(auth)
        auth_fail_chunks.append(auth[auth["status"] == "failure"])

        app_chunks.append(df[src == "application"][_safe_cols(df, APP_COLS)].copy())
        net_chunks.append(df[src == "network"][_safe_cols(df, NET_COLS)].copy())
        sys_chunks.append(df[src == "system"][_safe_cols(df, SYS_COLS)].copy())

        pct = processed / total_rows * 100
        print(f"  {processed:>12,} / {total_rows:,}  ({pct:.1f}%)", end="\r")

    print()

    auth_all      = pd.concat(auth_chunks,      ignore_index=True)
    auth_failures = pd.concat(auth_fail_chunks, ignore_index=True)
    app_all       = pd.concat(app_chunks,       ignore_index=True)
    net_all       = pd.concat(net_chunks,       ignore_index=True)
    sys_all       = pd.concat(sys_chunks,       ignore_index=True)

    print(
        f"Auth total={len(auth_all):,}  failures={len(auth_failures):,} | "
        f"App={len(app_all):,} | Network={len(net_all):,} | System={len(sys_all):,}"
    )
    return auth_all, auth_failures, app_all, net_all, sys_all


def run_detectors(
    auth_failures: pd.DataFrame,
    app_all: pd.DataFrame,
    net_all: pd.DataFrame,
    sys_all: pd.DataFrame,
    auth_all: pd.DataFrame | None = None,
) -> list[dict]:
    """Lance les 5 detecteurs DS1 et retourne la liste brute des detections."""
    t0 = time.time()

    steps = [
        ("Credential stuffing", lambda: detect_credential_stuffing(
            app_all,
            auth_failures=auth_failures,
            net_all=net_all,
            auth_all=auth_all,
        )),
        ("SSH brute force", lambda: detect_ssh_brute_force(
            auth_failures,
            sys_df=sys_all,
            net_df=net_all,
            auth_all=auth_all,
        )),
        ("SQL injection",       lambda: detect_sql_injection(app_all)),
        ("Directory traversal", lambda: detect_directory_traversal(app_all)),
        ("SSRF",                lambda: detect_ssrf(app_all, net_df=net_all)),
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

    auth_all, auth_failures, app_all, net_all, sys_all = load_logs(PARQUET_PATH)

    attacks = run_detectors(
        auth_failures, app_all, net_all, sys_all, auth_all=auth_all
    )

    if use_dedup:
        attacks = deduplicate(attacks)

    if use_bedrock and BEDROCK_ENABLED and attacks:
        sample_df = pd.concat([auth_all, app_all, net_all], ignore_index=True)
        attacks = enrich_detections(attacks, sample_df)

    total_time = int(time.time() - t_start)
    print(f"\n{len(attacks)} detection(s) in {total_time}s")

    with open("detections.json", "w") as f:
        json.dump(attacks, f, indent=2, ensure_ascii=False)
    print("Saved to detections.json")

    # Export au format API (consommable par le backend/frontend)
    from detection_api import to_api_format
    api_items = [d.model_dump() for d in to_api_format(attacks)]
    with open("detections_api.json", "w") as f:
        json.dump(api_items, f, indent=2, ensure_ascii=False)
    print("Saved to detections_api.json (API format)")

    return attacks


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-bedrock", action="store_true")
    parser.add_argument("--no-dedup",   action="store_true")
    args = parser.parse_args()
    main(use_bedrock=not args.no_bedrock, use_dedup=not args.no_dedup)
