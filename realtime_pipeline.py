"""
Pipeline temps reel pour la finale.

Tourne en boucle, interroge OpenSearch toutes les OPENSEARCH_POLL_INTERVAL_S
secondes, detecte les attaques et soumet les resultats a l'API de scoring.

Usage :
    python realtime_pipeline.py
    python realtime_pipeline.py --dry-run   # detecte sans soumettre
    python realtime_pipeline.py --reset     # repart depuis le debut du flux
"""

import time
import argparse
import pandas as pd

from config import OPENSEARCH_POLL_INTERVAL_S
from opensearch_connector import (
    OpenSearchConnector,
    load_last_timestamp,
    save_last_timestamp,
    _now_iso,
)
from pipeline import run_detectors
from detectors.dedup import deduplicate
from bedrock_analysis import enrich_detections
from submit import submit_detection
from config import BEDROCK_ENABLED

AUTH_COLS = ["timestamp", "source_ip", "username", "status", "failure_reason",
             "auth_method", "destination_port"]
APP_COLS  = ["timestamp", "source_ip", "username", "status_code",
             "http_method", "uri", "user_agent"]
NET_COLS  = ["timestamp", "source_ip", "destination_ip", "destination_port",
             "action", "protocol"]


def _split_by_source(df: pd.DataFrame):
    """Separe le DataFrame par log_source et retourne les sous-ensembles utiles."""
    src = df.get("log_source", pd.Series(dtype=str))

    auth_df = df[src == "authentication"][
        [c for c in AUTH_COLS if c in df.columns]
    ].copy() if "authentication" in src.values else pd.DataFrame()

    app_df = df[src == "application"][
        [c for c in APP_COLS if c in df.columns]
    ].copy() if "application" in src.values else pd.DataFrame()
    if not app_df.empty and "status_code" in app_df.columns:
        app_df = app_df[app_df["status_code"] == 401]

    net_df = df[src == "network"][
        [c for c in NET_COLS if c in df.columns]
    ].copy() if "network" in src.values else pd.DataFrame()

    return auth_df, app_df, net_df


def process_batch(df: pd.DataFrame, dry_run: bool) -> int:
    """Detecte les attaques dans un batch et les soumet. Retourne le nb soumis."""
    if df.empty:
        return 0

    auth_df, app_df, net_df = _split_by_source(df)

    auth_failures = auth_df[auth_df.get("status", pd.Series()) == "failure"] \
        if not auth_df.empty and "status" in auth_df.columns else pd.DataFrame()

    net_rejects = net_df[net_df.get("action", pd.Series()) == "reject"] \
        if not net_df.empty and "action" in net_df.columns else pd.DataFrame()

    attacks = run_detectors(auth_failures, app_df, net_df,
                            auth_all=auth_df, net_rejects=net_rejects)
    attacks = deduplicate(attacks)

    if BEDROCK_ENABLED and attacks:
        attacks = enrich_detections(attacks, df)

    submitted = 0
    for attack in attacks:
        result = submit_detection(attack, dry_run=dry_run)
        if result or dry_run:
            submitted += 1

    return submitted


def run(dry_run: bool = False, reset: bool = False):
    connector = OpenSearchConnector()

    if reset:
        save_last_timestamp("2026-01-31T00:00:00Z")
        print("[Reset] Timestamp reinitialise au debut du flux.")

    print(f"[Realtime] Demarrage — polling toutes les {OPENSEARCH_POLL_INTERVAL_S}s")
    print(f"[Realtime] dry_run={dry_run}")

    while True:
        last_ts = load_last_timestamp()
        print(f"\n[{_now_iso()}] Interrogation depuis {last_ts}...")

        try:
            df = connector.fetch_since(last_ts)
        except Exception as e:
            print(f"[Erreur OpenSearch] {e} — retry dans {OPENSEARCH_POLL_INTERVAL_S}s")
            time.sleep(OPENSEARCH_POLL_INTERVAL_S)
            continue

        if not df.empty:
            submitted = process_batch(df, dry_run=dry_run)
            print(f"[Realtime] {submitted} detection(s) soumise(s)")

            new_ts = df["timestamp"].max().strftime("%Y-%m-%dT%H:%M:%SZ")
            if not dry_run:
                save_last_timestamp(new_ts)
        else:
            print("[Realtime] Aucun nouveau log.")

        time.sleep(OPENSEARCH_POLL_INTERVAL_S)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--reset",   action="store_true")
    args = parser.parse_args()
    run(dry_run=args.dry_run, reset=args.reset)
